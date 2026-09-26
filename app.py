from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
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
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, storage_uri='memory://', app=app)
limiter.default_limits = ['600 per hour']

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please sign in to continue.'
login_manager.login_message_category = 'error'

KDF_ITERATIONS = 200_000
TRASH_RETENTION_DAYS = 30
HIBP_URL = 'https://api.pwnedpasswords.com/range/'


def utcnow():
    return datetime.utcnow()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    session_version = db.Column(db.Integer, nullable=False, default=0)
    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")
    totps = db.relationship('Totp', backref='user', lazy=True, cascade="all, delete-orphan")


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(200))
    url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    encrypted_password = db.Column(db.String(500), nullable=False)
    salt = db.Column(db.String(64), nullable=False, default='')
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


def _derive_key(passphrase, salt):
    raw = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, KDF_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _encrypt(passphrase, plaintext):
    salt = secrets.token_bytes(32)
    token = Fernet(_derive_key(passphrase, salt)).encrypt(plaintext.encode()).decode()
    return token, salt.hex()


def _decrypt(passphrase, token, salt_hex):
    return Fernet(_derive_key(passphrase, bytes.fromhex(salt_hex))).decrypt(token.encode()).decode()


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
        },
        'user': {
            'session_version': sa.Integer(),
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
        try:
            conn.execute(sa.text('UPDATE "user" SET session_version = 0 WHERE session_version IS NULL'))
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


@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
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
@limiter.limit('5 per hour')
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
        if user and check_password_hash(user.password, password):
            session.clear()
            session['sv'] = user.session_version or 0
            login_user(user, remember=True)
            flash('Signed in.', 'success')
            return redirect(url_for('dashboard'))
        # identical message for unknown user and wrong password: do not leak
        # which usernames exist
        flash('Incorrect username or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))


@app.route('/security')
@login_required
def security():
    return render_template('security.html')


@app.route('/signout-everywhere', methods=['POST'])
@login_required
def signout_everywhere():
    user = db.session.get(User, current_user.id)
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()
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

    token, salt = _encrypt(vault_key, request.form['password'])
    entry = Password(
        name=label,
        username=(request.form.get('entry_username') or '').strip() or None,
        url=(request.form.get('entry_url') or '').strip() or None,
        notes=(request.form.get('entry_notes') or '').strip() or None,
        encrypted_password=token,
        salt=salt,
        user_id=current_user.id,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    try:
        db.session.add(entry)
        db.session.commit()
        flash('Encrypted and saved.', 'success')
    except SQLAlchemyError:
        db.session.rollback()
        flash('Could not save that entry.', 'error')
    return redirect(url_for('dashboard'))


def _owned_or_404(model, entry_id):
    row = model.query.get_or_404(entry_id)
    if row.user_id != current_user.id:
        flash('That item is not in your vault.', 'error')
        return None
    return row


@app.route('/decrypt_password/<int:id>', methods=['GET', 'POST'])
@login_required
def decrypt_password_by_id(id):
    password = _owned_or_404(Password, id)
    if password is None:
        return redirect(url_for('dashboard'))
    if password.deleted_at is not None:
        flash('That entry is in the trash. Restore it first.', 'error')
        return redirect(url_for('trash'))

    if request.method == 'POST':
        try:
            plain = _decrypt(request.form['passkey'], password.encrypted_password, password.salt)
            return render_template('decrypt_result.html', password=password, decrypted=plain)
        except Exception:
            flash('That vault key did not open this entry.', 'error')
            return redirect(url_for('dashboard'))
    return render_template('decrypt_password.html', password=password)


@app.route('/update_password/<int:id>', methods=['GET', 'POST'])
@login_required
def update_password(id):
    password = _owned_or_404(Password, id)
    if password is None:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        label = (request.form['password_name'] or '').strip()
        if not label:
            flash('A label is required.', 'error')
            return redirect(url_for('update_password', id=id))
        try:
            token, salt = _encrypt(request.form['passkey'], request.form['password'])
            password.name = label
            password.username = (request.form.get('entry_username') or '').strip() or None
            password.url = (request.form.get('entry_url') or '').strip() or None
            password.notes = (request.form.get('entry_notes') or '').strip() or None
            password.encrypted_password = token
            password.salt = salt
            password.updated_at = utcnow()
            db.session.commit()
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
    if password is None:
        return redirect(url_for('dashboard'))
    password.deleted_at = utcnow()
    db.session.commit()
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
    if password is None:
        return redirect(url_for('trash'))
    password.deleted_at = None
    db.session.commit()
    flash('Restored.', 'success')
    return redirect(url_for('trash'))


@app.route('/trash/<int:id>/purge', methods=['POST'])
@login_required
def purge_password(id):
    password = _owned_or_404(Password, id)
    if password is None:
        return redirect(url_for('trash'))
    db.session.delete(password)
    db.session.commit()
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
    return redirect(request.referrer or url_for('dashboard'))


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
        token, salt = _encrypt(request.form['passkey'], secret)
        db.session.add(Totp(label=label, account=account or None,
                            encrypted_secret=token, salt=salt,
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
    if row is None:
        return redirect(url_for('totp'))
    if row.deleted_at is not None:
        flash('That code is in the trash. Restore it first.', 'error')
        return redirect(url_for('trash'))
    if request.method == 'GET':
        return render_template('totp_unlock.html', row=row)
    try:
        secret = _decrypt(request.form['passkey'], row.encrypted_secret, row.salt)
    except Exception:
        flash('That vault key did not open this code.', 'error')
        return redirect(url_for('totp_reveal', id=row.id))
    t = pyotp.TOTP(secret)
    now = int(utcnow().timestamp())
    return render_template('totp_code.html', row=row, current=t.now(),
                           next_=t.at(now + 30), expires_in=30 - (now % 30),
                           uri=_totp_uri(row.label, row.account, secret))


@app.route('/totp/<int:id>/delete', methods=['POST'])
@login_required
def totp_delete(id):
    row = _owned_or_404(Totp, id)
    if row is None:
        return redirect(url_for('totp'))
    row.deleted_at = utcnow()
    db.session.commit()
    flash('Moved to trash.', 'success')
    return redirect(url_for('trash'))


@app.route('/trash/totp/<int:id>/restore', methods=['POST'])
@login_required
def totp_restore(id):
    row = _owned_or_404(Totp, id)
    if row is None:
        return redirect(url_for('trash'))
    row.deleted_at = None
    db.session.commit()
    flash('Restored.', 'success')
    return redirect(url_for('trash'))


@app.route('/trash/totp/<int:id>/purge', methods=['POST'])
@login_required
def totp_purge(id):
    row = _owned_or_404(Totp, id)
    if row is None:
        return redirect(url_for('trash'))
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
                'created_at': p.created_at.isoformat() if p.created_at else None,
            }
            for p in Password.query.filter_by(user_id=current_user.id).all()
        ],
        'totp': [
            {
                'label': t.label, 'account': t.account,
                'ciphertext': t.encrypted_secret, 'salt': t.salt,
            }
            for t in Totp.query.filter_by(user_id=current_user.id).all()
        ],
    }
    body = json.dumps(payload, indent=2)
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
                                user_id=current_user.id, created_at=utcnow()))
            n += 1
        except Exception:
            continue
    try:
        db.session.commit()
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
