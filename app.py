from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, current_app, abort, g
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
import base64
import hashlib
import hmac
import io
import json
import os
import secrets

import pyotp
import requests
import sqlalchemy as sa

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-me')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
# Pin the psycopg2 driver explicitly: SQLAlchemy 2.1+ defaults postgresql://
# to psycopg v3, which is not installed. psycopg2-binary is in requirements.
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql+psycopg2://', 1)
elif db_url.startswith('postgresql://'):
    db_url = db_url.replace('postgresql://', 'postgresql+psycopg2://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '1') == '1'
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']
# NOTE: do not set WTF_CSRF_CHECK_DEFAULT = False to silence the Referer
# check - in Flask-WTF that flag disables CSRF protection altogether. The
# Referer comparison is satisfied by the strict-origin-when-cross-origin
# Referrer-Policy set in security_headers() below.

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, storage_uri='memory://', app=app)
limiter.default_limits = ['600 per hour']

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please sign in to continue.'
login_manager.login_message_category = 'error'

KDF_ITERATIONS = 600_000
TRASH_RETENTION_DAYS = 30
HIBP_URL = 'https://api.pwnedpasswords.com/range/'

# Compared against when the username does not exist, so a missing account costs
# the same wall-clock time as a wrong password and cannot be detected by timing.
_DUMMY_HASH = generate_password_hash('timing-equaliser-' + 'x' * 24)


def utcnow():
    return datetime.utcnow()


def audit(action, detail=None, user=None):
    """Record a security-relevant event. Never raises: logging must not be able
    to break the request it is describing."""
    try:
        who = user
        if who is None and getattr(current_user, 'is_authenticated', False):
            who = current_user
        db.session.add(AuditEvent(
            user_id=getattr(who, 'id', None),
            username=getattr(who, 'username', None) or (request.form.get('username') or None),
            action=action,
            detail=(detail or '')[:300] or None,
            ip=(request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                or request.remote_addr or '')[:60] or None,
            created_at=utcnow(),
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()


def _server_key(salt):
    """Key for material that belongs to the server, not the user. Derived from
    SECRET_KEY so it is stable across deploys but never leaves the process."""
    return _derive_key(app.config['SECRET_KEY'], salt, 100_000)


def _encrypt_with_server(plaintext):
    salt = secrets.token_bytes(32)
    token = Fernet(_server_key(salt)).encrypt(plaintext.encode()).decode()
    return token, salt.hex()


def _decrypt_with_server(token, salt_hex):
    return Fernet(_server_key(bytes.fromhex(salt_hex))).decrypt(token.encode()).decode()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    session_version = db.Column(db.Integer, nullable=False, default=0)
    # Second factor for signing in to SafeX itself. The seed is sealed with a
    # key derived from the app SECRET_KEY, not the account password, so it is
    # unaffected by credential changes and never recoverable.
    twofa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    twofa_secret = db.Column(db.String(500))
    twofa_salt = db.Column(db.String(64))
    twofa_kdf_iterations = db.Column(db.Integer, nullable=False, default=200_000)
    recovery_codes = db.Column(db.Text)
    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")
    totps = db.relationship('Totp', backref='user', lazy=True, cascade="all, delete-orphan")
    events = db.relationship('AuditEvent', backref='user', lazy=True, cascade="all, delete-orphan")


class AuditEvent(db.Model):
    """Append-only record of security-relevant activity, so a compromise can be
    detected and attributed after the fact."""
    __tablename__ = 'audit_event'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    username = db.Column(db.String(100))
    action = db.Column(db.String(60), nullable=False)
    detail = db.Column(db.String(300))
    ip = db.Column(db.String(60))
    created_at = db.Column(db.DateTime, nullable=False)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(200))
    url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    encrypted_password = db.Column(db.String(500), nullable=False)
    salt = db.Column(db.String(64), nullable=False, default='')
    # PBKDF2 rounds this entry was sealed with. Defaults to the old 200k so rows
    # written before the upgrade still open; new entries use KDF_ITERATIONS.
    kdf_iterations = db.Column(db.Integer, nullable=False, default=200_000)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)


class Totp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100), nullable=False)
    account = db.Column(db.String(200))
    encrypted_secret = db.Column(db.String(500), nullable=False)
    salt = db.Column(db.String(64), nullable=False, default='')
    kdf_iterations = db.Column(db.Integer, nullable=False, default=200_000)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user is None:
        return None
    # session_version bump invalidates every existing session (sign out everywhere)
    if (session.get('sv') or 0) != (user.session_version or 0):
        return None
    return user


def _derive_key(passphrase, salt, iterations=KDF_ITERATIONS):
    raw = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _encrypt(passphrase, plaintext):
    salt = secrets.token_bytes(32)
    token = Fernet(_derive_key(passphrase, salt)).encrypt(plaintext.encode()).decode()
    return token, salt.hex(), KDF_ITERATIONS


def _decrypt(passphrase, token, salt_hex, iterations=KDF_ITERATIONS):
    key = _derive_key(passphrase, bytes.fromhex(salt_hex), iterations or KDF_ITERATIONS)
    return Fernet(key).decrypt(token.encode()).decode()


def _ensure_columns():
    """Additive schema upgrades for databases created before a feature existed."""
    wanted = {
        'password': {
            'username': sa.String(200),
            'url': sa.String(500),
            'notes': sa.Text(),
            'created_at': sa.DateTime(),
            'updated_at': sa.DateTime(),
            'deleted_at': sa.DateTime(),
            'kdf_iterations': sa.Integer(),
        },
        'totp': {
            'kdf_iterations': sa.Integer(),
        },        'user': {
            'session_version': sa.Integer(),
            'twofa_enabled': sa.Boolean(),
            'twofa_secret': sa.String(500),
            'twofa_salt': sa.String(64),
            'twofa_kdf_iterations': sa.Integer(),
            'recovery_codes': sa.Text(),
        },
    }
    with db.engine.connect() as conn:
        insp = sa.inspect(conn)
        present = set(insp.get_table_names())
        for table, cols in wanted.items():
            if table not in present:
                continue
            existing = {c['name'] for c in insp.get_columns(table)}
            for col, typ in cols.items():
                if col in existing:
                    continue
                ddl = typ.compile(dialect=conn.dialect)
                try:
                    conn.execute(sa.text('ALTER TABLE "%s" ADD COLUMN "%s" %s' % (table, col, ddl)))
                    app.logger.info('migrated %s.%s' % (table, col))
                except SQLAlchemyError:
                    app.logger.warning('could not add %s.%s' % (table, col))
        # backfill so pre-existing rows get a real value, not NULL
        for stmt in ('UPDATE "user" SET session_version = 0 WHERE session_version IS NULL',
                     'UPDATE password SET kdf_iterations = 200000 WHERE kdf_iterations IS NULL',
                     'UPDATE totp SET kdf_iterations = 200000 WHERE kdf_iterations IS NULL'):
            try:
                conn.execute(sa.text(stmt))
            except SQLAlchemyError:
                pass
        conn.commit()


def purge_expired_trash():
    cutoff = utcnow() - timedelta(days=TRASH_RETENTION_DAYS)
    try:
        n = Password.query.filter(Password.deleted_at.isnot(None),
                                  Password.deleted_at < cutoff).delete(synchronize_session=False)
        m = Totp.query.filter(Totp.deleted_at.isnot(None),
                              Totp.deleted_at < cutoff).delete(synchronize_session=False)
        db.session.commit()
        if n or m:
            app.logger.info('purged %d passwords and %d codes from trash' % (n, m))
    except SQLAlchemyError:
        db.session.rollback()


def _make_nonce():
    # One nonce per request: the value baked into the templates must be the
    # same one advertised in the Content-Security-Policy header, or the browser
    # will block our own scripts.
    n = getattr(g, '_csp_nonce', None)
    if n is None:
        n = secrets.token_urlsafe(16)
        g._csp_nonce = n
    return n


@app.context_processor
def inject_nonce():
    # templates stamp every <style> and <script> with this
    return {'nonce': _make_nonce()}


@app.after_request
def security_headers(resp):
    nonce = _make_nonce()
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    # strict-origin-when-cross-origin (not no-referrer) so same-origin form
    # submissions still carry a Referer, as Flask-WTF's CSRF check requires
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    # script-src is strict: only our own nonce-tagged blocks may run, so an
    # injected <script> or inline handler cannot execute. style-src keeps
    # 'unsafe-inline' only because templates still carry style="" attributes,
    # which nonces cannot cover; CSS injection cannot execute script.
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'nonce-%s'; form-action 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; object-src 'none'" % nonce
    )
    # Anything session-bearing must never be stored by a shared cache.
    if current_user.is_authenticated:
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Vary'] = 'Cookie'
    return resp


# --------------------------------------------------------------------------
# public
# --------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit('20 per hour')
def signup():
    if request.method == 'POST':
        username = (request.form['username'] or '').strip()
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not username or len(username) > 100:
            flash('Pick a username between 1 and 100 characters.', 'error')
            return redirect(url_for('signup'))
        if password != confirm:
            flash('Those passwords do not match.', 'error')
            return redirect(url_for('signup'))
        if (len(password) < 8 or not any(c.isdigit() for c in password)
                or not any(c.isalpha() for c in password)
                or not any(c in '!@#$%^&*()_+' for c in password)):
            flash('Password needs 8+ characters with a letter, a number and a special character.', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('That username is already taken.', 'error')
            return redirect(url_for('signup'))

        new_user = User(username=username, password=generate_password_hash(password), session_version=0)
        try:
            db.session.add(new_user)
            db.session.commit()
            audit('signup', user=new_user)
            flash('Account created. Sign in to open your vault.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError:
            db.session.rollback()
            flash('Could not create the account. Try again.', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    if request.method == 'POST':
        username = (request.form['username'] or '').strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        # Always run a verification, even when no such user exists, so response
        # time does not reveal which usernames are registered.
        stored = user.password if user else _DUMMY_HASH
        password_ok = check_password_hash(stored, password)
        if user and password_ok:
            if user.twofa_enabled:
                # Password is correct but the second factor is still required.
                session.clear()
                session['pending_2fa'] = user.id
                session['sv'] = user.session_version or 0
                session.permanent = False
                return redirect(url_for('twofa_challenge'))
            session.clear()
            session['sv'] = user.session_version or 0
            login_user(user, remember=True)
            audit('login.success', user=user)
            flash('Signed in.', 'success')
            return redirect(url_for('dashboard'))
        # identical message for unknown user and wrong password: do not leak
        # which usernames exist
        audit('login.failure', detail='username=%s' % (username[:60] or '?'))
        flash('Incorrect username or password.', 'error')
    return render_template('login.html')


@app.route('/twofa', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def twofa_challenge():
    user_id = session.get('pending_2fa')
    if not user_id:
        return redirect(url_for('login'))
    user = db.session.get(User, user_id)
    if user is None or not user.twofa_enabled:
        session.pop('pending_2fa', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = (request.form.get('code') or '').strip().replace(' ', '').replace('-', '')
        if _verify_twofa(user, code):
            session.pop('pending_2fa', None)
            session['sv'] = user.session_version or 0
            login_user(user, remember=True)
            audit('login.2fa_success', user=user)
            flash('Signed in.', 'success')
            return redirect(url_for('dashboard'))
        audit('login.2fa_failure', user=user)
        flash('That code was not accepted.', 'error')
    return render_template('twofa_challenge.html')


def _verify_twofa(user, code):
    """Accept a live TOTP code, or a single-use recovery code."""
    try:
        secret = _decrypt_with_server(user.twofa_secret, user.twofa_salt)
    except Exception:
        return False
    if code and pyotp.TOTP(secret).verify(code, valid_window=1):
        return True
    # recovery codes
    remaining = []
    matched = False
    for stored_hash in json.loads(user.recovery_codes or '[]'):
        if not matched and code and check_password_hash(stored_hash, code):
            matched = True
            continue  # consume it
        remaining.append(stored_hash)
    if matched:
        user.recovery_codes = json.dumps(remaining)
        db.session.commit()
    return matched


def _issue_recovery_codes(n=8):
    # No separators: the challenge strips spaces and hyphens before verifying,
    # so a hyphenated code could never match its stored hash.
    codes = [secrets.token_hex(10) for _ in range(n)]
    hashed = [generate_password_hash(c) for c in codes]
    return codes, json.dumps(hashed)


@app.route('/twofa/setup', methods=['GET', 'POST'])
@login_required
def twofa_setup():
    user = db.session.get(User, current_user.id)
    if request.method == 'POST':
        stage = request.form.get('stage')
        if stage == 'confirm':
            code = (request.form.get('code') or '').strip().replace(' ', '')
            pending = session.get('twofa_pending')
            if not pending:
                flash('Start again from the setup link.', 'error')
                return redirect(url_for('security'))
            if not pyotp.TOTP(pending).verify(code, valid_window=1):
                flash('That code did not match. Check your authenticator and retry.', 'error')
                return redirect(url_for('twofa_setup'))
            codes, hashed = _issue_recovery_codes()
            user.twofa_secret, user.twofa_salt = _encrypt_with_server(pending)
            user.twofa_enabled = True
            user.recovery_codes = hashed
            db.session.commit()
            session.pop('twofa_pending', None)
            audit('2fa.enabled', user=user)
            flash('Two-factor sign-in is on.', 'success')
            return render_template('twofa_recovery.html', codes=codes)
        # stage == 'start': re-authenticate before issuing a new seed
        if not check_password_hash(user.password, request.form.get('password') or ''):
            flash('Password incorrect.', 'error')
            return redirect(url_for('twofa_setup'))
        secret = pyotp.random_base32()
        session['twofa_pending'] = secret
        return render_template('twofa_setup.html', secret=secret,
                               uri=pyotp.TOTP(secret).provisioning_uri(
                                   name=user.username, issuer_name='SafeX'))
    # The "enter your password to begin" form lives on /security; coming here
    # with a GET just sends the user back to it rather than looping.
    return redirect(url_for('security'))


@app.route('/twofa/disable', methods=['POST'])
@login_required
def twofa_disable():
    user = db.session.get(User, current_user.id)
    if not check_password_hash(user.password, request.form.get('password') or ''):
        flash('Password incorrect.', 'error')
        return redirect(url_for('security'))
    if not _verify_twofa(user, (request.form.get('code') or '').strip()):
        flash('A valid code is required to turn this off.', 'error')
        return redirect(url_for('security'))
    user.twofa_enabled = False
    user.twofa_secret = None
    user.twofa_salt = None
    user.recovery_codes = None
    db.session.commit()
    audit('2fa.disabled', user=user)
    flash('Two-factor sign-in is off.', 'success')
    return redirect(url_for('security'))


@app.route('/twofa/recovery', methods=['POST'])
@login_required
def twofa_recovery():
    user = db.session.get(User, current_user.id)
    codes, hashed = _issue_recovery_codes()
    user.recovery_codes = hashed
    db.session.commit()
    audit('2fa.recovery_regenerated', user=user)
    return render_template('twofa_recovery.html', codes=codes)


@app.route('/logout')
@login_required
def logout():
    audit('logout', user=current_user)
    logout_user()
    session.clear()
    return redirect(url_for('home'))


@app.route('/security')
@login_required
def security():
    events = (AuditEvent.query.filter_by(user_id=current_user.id)
              .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(40).all())
    unused_recovery = 0
    if current_user.recovery_codes:
        try:
            unused_recovery = len(json.loads(current_user.recovery_codes))
        except ValueError:
            unused_recovery = 0
    return render_template('security.html', events=events, unused_recovery=unused_recovery)


@app.route('/signout-everywhere', methods=['POST'])
@login_required
def signout_everywhere():
    user = db.session.get(User, current_user.id)
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()
    audit('signout_everywhere', user=user)
    logout_user()
    session.clear()
    flash('Signed out on every device.', 'success')
    return redirect(url_for('home'))


# --------------------------------------------------------------------------
# vault
# --------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    q = (request.args.get('q') or '').strip()
    query = Password.query.filter_by(user_id=current_user.id, deleted_at=None)
    if q:
        like = '%%%s%%' % q
        query = query.filter(db.or_(Password.name.ilike(like),
                                    Password.username.ilike(like),
                                    Password.url.ilike(like)))
    passwords = query.order_by(Password.name).all()
    total = Password.query.filter_by(user_id=current_user.id, deleted_at=None).count()
    return render_template('dashboard.html', name=current_user.username,
                           passwords=passwords, total=total, q=q)


@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    label = (request.form['password_name'] or '').strip()
    if not label:
        flash('Give the entry a label so you can find it later.', 'error')
        return redirect(url_for('dashboard'))
    vault_key = request.form['passkey']
    if not vault_key:
        flash('A vault key is required.', 'error')
        return redirect(url_for('dashboard'))

    token, salt, iters = _encrypt(vault_key, request.form['password'])
    entry = Password(
        name=label,
        username=(request.form.get('entry_username') or '').strip() or None,
        url=(request.form.get('entry_url') or '').strip() or None,
        notes=(request.form.get('entry_notes') or '').strip() or None,
        encrypted_password=token,
        salt=salt,
        kdf_iterations=iters,
        user_id=current_user.id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    try:
        db.session.add(entry)
        db.session.commit()
        audit('entry.create', detail=label[:80])
        flash('Encrypted and saved.', 'success')
    except SQLAlchemyError:
        db.session.rollback()
        flash('Could not save that entry.', 'error')
    return redirect(url_for('dashboard'))


def _owned_or_404(model, entry_id):
    """Return the row only if it exists AND belongs to the caller.

    A row that exists but belongs to someone else produces exactly the same
    404 as a row that does not exist, so entry ids cannot be enumerated.
    """
    row = db.session.get(model, entry_id)
    if row is None or row.user_id != current_user.id:
        abort(404)
    return row


@app.route('/decrypt_password/<int:id>', methods=['GET', 'POST'])
@login_required
def decrypt_password_by_id(id):
    password = _owned_or_404(Password, id)
    if password.deleted_at is not None:
        flash('That entry is in the trash. Restore it first.', 'error')
        return redirect(url_for('trash'))

    if request.method == 'POST':
        try:
            plain = _decrypt(request.form['passkey'], password.encrypted_password,
                             password.salt, password.kdf_iterations)
            audit('entry.decrypt', detail=password.name[:80])
            return render_template('decrypt_result.html', password=password, decrypted=plain)
        except Exception:
            audit('entry.decrypt_failed', detail=password.name[:80])
            flash('That vault key did not open this entry.', 'error')
            return redirect(url_for('dashboard'))
    return render_template('decrypt_password.html', password=password)


@app.route('/update_password/<int:id>', methods=['GET', 'POST'])
@login_required
def update_password(id):
    password = _owned_or_404(Password, id)
    if request.method == 'POST':
        label = (request.form['password_name'] or '').strip()
        if not label:
            flash('A label is required.', 'error')
            return redirect(url_for('update_password', id=id))
        try:
            token, salt, iters = _encrypt(request.form['passkey'], request.form['password'])
            password.name = label
            password.username = (request.form.get('entry_username') or '').strip() or None
            password.url = (request.form.get('entry_url') or '').strip() or None
            password.notes = (request.form.get('entry_notes') or '').strip() or None
            password.encrypted_password = token
            password.salt = salt
            password.kdf_iterations = iters
            password.updated_at = utcnow()
            db.session.commit()
            audit('entry.update', detail=label[:80])
            flash('Entry updated.', 'success')
            return redirect(url_for('dashboard'))
        except SQLAlchemyError:
            db.session.rollback()
            flash('Could not update that entry.', 'error')
            return redirect(url_for('update_password', id=id))
    return render_template('update_password.html', password=password)


@app.route('/delete_password/<int:id>', methods=['POST'])
@login_required
def delete_password_by_id(id):
    password = _owned_or_404(Password, id)
    password.deleted_at = utcnow()
    db.session.commit()
    audit('entry.delete', detail=password.name[:80])
    flash('Moved to trash. Recoverable for %d days.' % TRASH_RETENTION_DAYS, 'success')
    return redirect(url_for('dashboard'))


# --------------------------------------------------------------------------
# trash
# --------------------------------------------------------------------------

@app.route('/trash')
@login_required
def trash():
    passwords = Password.query.filter_by(user_id=current_user.id).filter(
        Password.deleted_at.isnot(None)).order_by(Password.deleted_at.desc()).all()
    totps = Totp.query.filter_by(user_id=current_user.id).filter(
        Totp.deleted_at.isnot(None)).order_by(Totp.deleted_at.desc()).all()
    return render_template('trash.html', passwords=passwords, totps=totps)


@app.route('/trash/<int:id>/restore', methods=['POST'])
@login_required
def restore_password(id):
    password = _owned_or_404(Password, id)
    password.deleted_at = None
    db.session.commit()
    audit('entry.restore', detail=password.name[:80])
    flash('Restored.', 'success')
    return redirect(url_for('trash'))


@app.route('/trash/<int:id>/purge', methods=['POST'])
@login_required
def purge_password(id):
    password = _owned_or_404(Password, id)
    detail = password.name[:80]
    db.session.delete(password)
    db.session.commit()
    audit('entry.purge', detail=detail)
    flash('Permanently deleted.', 'success')
    return redirect(url_for('trash'))


# --------------------------------------------------------------------------
# breach check (HIBP k-anonymity: only 5 hash chars ever leave the server)
# --------------------------------------------------------------------------

def breach_count(password):
    digest = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        resp = requests.get(HIBP_URL + prefix, timeout=8,
                            headers={'Add-Padding': 'true', 'User-Agent': 'SafeX'})
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    for line in resp.text.splitlines():
        if ':' not in line:
            continue
        candidate, count = line.split(':', 1)
        if hmac.compare_digest(candidate.strip().upper(), suffix):
            return int(count.strip())
    return 0


@app.route('/breach-check', methods=['POST'])
@login_required
@limiter.limit('20 per minute')
def breach_check():
    password = request.form.get('candidate') or ''
    if not password:
        flash('Nothing to check.', 'error')
        return redirect(url_for('dashboard'))
    count = breach_count(password)
    if count is None:
        flash('Could not reach the breach database. Try again shortly.', 'error')
    elif count == 0:
        flash('No breaches found for that password. Good choice.', 'success')
    else:
        flash('Found in %d known breach%s. Do not use it anywhere.'
              % (count, '' if count == 1 else 'es'), 'error')
    # Deliberately not request.referrer: the Referer header is attacker
    # controlled, so redirecting to it is an open redirect. The form lives on
    # the dashboard, so that is the correct and safe target.
    return redirect(url_for('dashboard'))


# --------------------------------------------------------------------------
# TOTP
# --------------------------------------------------------------------------

def _totp_uri(label, account, secret):
    return pyotp.TOTP(secret).provisioning_uri(name=account or label, issuer_name='SafeX')


@app.route('/totp', methods=['GET', 'POST'])
@login_required
def totp():
    if request.method == 'POST':
        label = (request.form['label'] or '').strip()
        account = (request.form.get('account') or '').strip()
        if not label:
            flash('Give the code a label.', 'error')
            return redirect(url_for('totp'))
        secret = pyotp.random_base32()
        token, salt, iters = _encrypt(request.form['passkey'], secret)
        db.session.add(Totp(label=label, account=account or None,
                            encrypted_secret=token, salt=salt, kdf_iterations=iters,
                            user_id=current_user.id, created_at=utcnow()))
        db.session.commit()
        flash('Added. Scan the setup key in your authenticator app.', 'success')
        return redirect(url_for('totp'))

    rows = Totp.query.filter_by(user_id=current_user.id, deleted_at=None).order_by(Totp.label).all()
    return render_template('totp.html', totps=rows)


@app.route('/totp/<int:id>', methods=['GET', 'POST'])
@login_required
def totp_reveal(id):
    row = _owned_or_404(Totp, id)
    if row.deleted_at is not None:
        flash('That code is in the trash. Restore it first.', 'error')
        return redirect(url_for('trash'))
    if request.method == 'GET':
        return render_template('totp_unlock.html', row=row)
    try:
        secret = _decrypt(request.form['passkey'], row.encrypted_secret, row.salt,
                          row.kdf_iterations)
    except Exception:
        flash('That vault key did not open this code.', 'error')
        return redirect(url_for('totp_reveal', id=row.id))
    audit('totp.reveal', detail=row.label[:80])
    t = pyotp.TOTP(secret)
    now = int(utcnow().timestamp())
    return render_template('totp_code.html', row=row, current=t.now(),
                           next_=t.at(now + 30), expires_in=30 - (now % 30),
                           uri=_totp_uri(row.label, row.account, secret))


@app.route('/totp/<int:id>/delete', methods=['POST'])
@login_required
def totp_delete(id):
    row = _owned_or_404(Totp, id)
    row.deleted_at = utcnow()
    db.session.commit()
    audit('totp.delete', detail=row.label[:80])
    flash('Moved to trash.', 'success')
    return redirect(url_for('trash'))


@app.route('/trash/totp/<int:id>/restore', methods=['POST'])
@login_required
def totp_restore(id):
    row = _owned_or_404(Totp, id)
    row.deleted_at = None
    db.session.commit()
    flash('Restored.', 'success')
    return redirect(url_for('trash'))


@app.route('/trash/totp/<int:id>/purge', methods=['POST'])
@login_required
def totp_purge(id):
    row = _owned_or_404(Totp, id)
    db.session.delete(row)
    db.session.commit()
    flash('Permanently deleted.', 'success')
    return redirect(url_for('trash'))


# --------------------------------------------------------------------------
# export / import (ciphertext only - plaintext never exists server-side)
# --------------------------------------------------------------------------

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        if request.form.get('op') == 'import':
            return _do_import()
        return _do_export()
    return render_template('transfer.html')


def _do_export():
    if not check_password_hash(current_user.password, request.form.get('password') or ''):
        flash('Re-enter your account password to export.', 'error')
        return redirect(url_for('transfer'))
    payload = {
        'format': 'safex-export',
        'version': 1,
        'exported_at': utcnow().isoformat() + 'Z',
        'entries': [
            {
                'name': p.name, 'username': p.username, 'url': p.url, 'notes': p.notes,
                'ciphertext': p.encrypted_password, 'salt': p.salt,
                'kdf_iterations': p.kdf_iterations,
                'created_at': p.created_at.isoformat() if p.created_at else None,
            }
            for p in Password.query.filter_by(user_id=current_user.id).all()
        ],
        'totp': [
            {
                'label': t.label, 'account': t.account,
                'ciphertext': t.encrypted_secret, 'salt': t.salt,
                'kdf_iterations': t.kdf_iterations,
            }
            for t in Totp.query.filter_by(user_id=current_user.id).all()
        ],
    }
    body = json.dumps(payload, indent=2)
    audit('vault.export', detail='%d entries, %d codes' % (len(payload['entries']), len(payload['totp'])))
    stamp = utcnow().strftime('%Y%m%d-%H%M')
    return send_file(io.BytesIO(body.encode()), mimetype='application/json',
                     as_attachment=True, download_name='safex-export-%s.json' % stamp)


def _do_import():
    upload = request.files.get('file')
    if upload is None or not upload.filename:
        flash('Choose a SafeX export file first.', 'error')
        return redirect(url_for('transfer'))
    try:
        data = json.loads(upload.read().decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        flash('That file is not valid SafeX export JSON.', 'error')
        return redirect(url_for('transfer'))
    if not isinstance(data, dict) or data.get('format') != 'safex-export':
        flash('That is not a SafeX export file.', 'error')
        return redirect(url_for('transfer'))

    n = 0
    for row in data.get('entries') or []:
        try:
            name = (row.get('name') or '').strip()
            cipher, salt = row.get('ciphertext'), row.get('salt')
            if not name or not cipher or not salt:
                continue
            db.session.add(Password(
                name=name[:100], username=row.get('username'), url=row.get('url'),
                notes=row.get('notes'), encrypted_password=cipher, salt=salt,
                kdf_iterations=int(row.get('kdf_iterations') or 200_000),
                user_id=current_user.id, created_at=utcnow(), updated_at=utcnow()))
            n += 1
        except Exception:
            continue
    for row in data.get('totp') or []:
        try:
            label = (row.get('label') or '').strip()
            cipher, salt = row.get('ciphertext'), row.get('salt')
            if not label or not cipher or not salt:
                continue
            db.session.add(Totp(label=label[:100], account=row.get('account'),
                                encrypted_secret=cipher, salt=salt,
                                kdf_iterations=int(row.get('kdf_iterations') or 200_000),
                                user_id=current_user.id, created_at=utcnow()))
            n += 1
        except Exception:
            continue
    try:
        db.session.commit()
        audit('vault.import', detail='%d items' % n)
        flash('Imported %d item%s.' % (n, '' if n == 1 else 's'), 'success')
    except SQLAlchemyError:
        db.session.rollback()
        flash('Import failed. Nothing was changed.', 'error')
    return redirect(url_for('dashboard'))


# --------------------------------------------------------------------------
# boot
# --------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    try:
        _ensure_columns()
    except Exception:
        app.logger.exception('schema migration step failed')
    purge_expired_trash()

if __name__ == '__main__':
    app.run(debug=False)
