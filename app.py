import os
import random
import time
import requests
from dotenv import load_dotenv
from bit import Key  # ✅ replaces bitcoinlib
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

load_dotenv()

# ----------------- App Setup -----------------
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY")

# ----------------- Database Setup -----------------
DATABASE_URL = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----------------- Email Config -----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME", "yourcompanyemail@gmail.com")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD", "your_app_password")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER", "yourcompanyemail@gmail.com")
mail = Mail(app)

# ----------------- File Upload Config -----------------
UPLOAD_FOLDER = os.path.join('static', 'uploads')
PICTURE_FOLDER = os.path.join("pictures")
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['PICTURE_FOLDER'] =  PICTURE_FOLDER
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PICTURE_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------- Database Models -----------------
# ----------------- Database Models -----------------
class User(db.Model):
    __tablename__ = "users"  # 👈 avoid reserved word
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    profile_image = db.Column(db.String(200), nullable=True)


class PasswordReset(db.Model):
    __tablename__ = "password_resets"  # 👈 add explicit name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.Float, default=time.time)


class Case(db.Model):
    __tablename__ = "cases"  # 👈 add explicit name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    issue_type = db.Column(db.String(255))
    amount_lost = db.Column(db.Float)
    transaction_id = db.Column(db.String(255))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )


# ----------------- Schema Helper -----------------
def ensure_schema():
    inspector = db.inspect(db.engine)
    tables = inspector.get_table_names()

    if "users" not in tables:   # 👈 check new name
        db.create_all()
        return

    cols = [c["name"] for c in inspector.get_columns("users")]
    if "username" not in cols:
        with db.engine.begin() as conn:
            conn.execute(text('ALTER TABLE "users" ADD COLUMN username VARCHAR(80);'))

        existing = User.query.all()
        taken = set(u.username.lower() for u in existing if u.username)

        def unique_username(base):
            candidate = base
            i = 1
            while candidate.lower() in taken:
                i += 1
                candidate = f"{base}{i}"
            taken.add(candidate.lower())
            return candidate

        for u in existing:
            if not u.username or u.username.strip() == "":
                base = (u.email.split("@")[0] if u.email else "user").strip()
                base = "".join(
                    ch for ch in base if ch.isalnum() or ch in ("_", ".", "-")
                )[:80] or "user"
                u.username = unique_username(base)
        db.session.commit()

# ----------------- Bank & Crypto -----------------
def send_bank_transfer(amount, account_number, bank_code):
    headers = {"Authorization": f"Bearer {os.getenv('PAYSTACK_SECRET_KEY', 'YOUR_PAYSTACK_SECRET_KEY')}"}
    data = {
        "source": "balance",
        "amount": int(amount * 100),
        "recipient": account_number,
        "reason": "Withdrawal",
        "currency": "NGN",
        "bank_code": bank_code
    }
    try:
        response = requests.post("https://api.paystack.co/transfer", headers=headers, json=data, timeout=30)
        return response.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}

def send_btc(destination_address, amount):
    """
    Send BTC using the bit library.
    """
    try:
        private_key = os.getenv("BTC_WIF_KEY")
        if not private_key:
            return {"status": "error", "message": "BTC_WIF_KEY not set in environment"}

        key = Key(private_key)
        tx_hash = key.send([(destination_address, amount, 'btc')])

        return {"status": "success", "tx": tx_hash}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ----------------- OAuth Setup -----------------
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET"),
    redirect_to="oauth_callback",
    scope=["profile", "email"]
)
facebook_bp = make_facebook_blueprint(
    client_id=os.getenv("FACEBOOK_APP_ID", "YOUR_FACEBOOK_APP_ID"),
    client_secret=os.getenv("FACEBOOK_APP_SECRET", "YOUR_FACEBOOK_APP_SECRET"),
    redirect_to="oauth_callback",
    scope=["email"]
)
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(facebook_bp, url_prefix="/login")

# ----------------- Public Routes -----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/case")
def case():
    return render_template("case.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

# ----------------- Authentication -----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password")

        if not username or not email or not password:
            flash("⚠️ Please fill all fields!", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already taken!", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("⚠️ Email already registered!", "warning")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("✅ Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user"] = user.username
            flash("✅ Login successful! Welcome.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("❌ Invalid username or password!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/profile")
def profile():
    username = session.get("user")
    if not username:
        flash("⚠️ You need to log in first!", "warning")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("❌ User not found!", "danger")
        return redirect(url_for("login"))
    return render_template("profile.html", user=user)

@app.route('/upload_profile_image', methods=['POST'])
def upload_profile_image():
    username = session.get("user")
    if not username:
        flash("⚠️ You need to log in first!", "warning")
        return redirect(url_for("login"))

    user = User.query.filter_by(username=username).first()
    if 'profile_image' not in request.files:
        flash("❌ No file part", "danger")
        return redirect(url_for('profile'))
    file = request.files['profile_image']
    if file.filename == '':
        flash("❌ No selected file", "danger")
        return redirect(url_for('profile'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user.profile_image = filename
        db.session.commit()
        flash("✅ Profile image updated!", "success")
        return redirect(url_for('profile'))
    else:
        flash("❌ Invalid file type", "danger")
        return redirect(url_for('profile'))

@app.route("/setting")
def setting():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    return render_template("setting.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("login"))

# ----------------- Password Reset -----------------
@app.route("/forgotten", methods=["GET", "POST"])
def forgotten():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        user = User.query.filter_by(username=username).first()
        if user:
            code = str(random.randint(100000, 999999))
            reset_entry = PasswordReset(username=username, code=code)
            db.session.add(reset_entry)
            db.session.commit()
            session["reset_username"] = username
            send_email(user.email, code, "password_reset")
            flash("📩 Check your email for the reset code.", "info")
        else:
            flash("📩 If this username exists, a reset code has been sent.", "info")
        return redirect(url_for("reset_password"))
    return render_template("forgotten.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    username = session.get("reset_username")
    if not username:
        return redirect(url_for("forgotten"))

    if request.method == "POST":
        code = request.form.get("code")
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        reset_entry = PasswordReset.query.filter_by(username=username, code=code).first()
        if reset_entry:
            if time.time() - reset_entry.created_at > 300:
                db.session.delete(reset_entry)
                db.session.commit()
                flash("❌ Code expired. Please request a new one.", "danger")
                return redirect(url_for("forgotten"))

            if new_password == confirm_password:
                user = User.query.filter_by(username=username).first()
                if not user:
                    flash("❌ User not found.", "danger")
                    return redirect(url_for("forgotten"))
                user.password = generate_password_hash(new_password)
                db.session.commit()
                db.session.delete(reset_entry)
                db.session.commit()
                flash("✅ Password reset successful! Please login.", "success")
                return redirect(url_for("login"))
            else:
                flash("❌ Passwords do not match.", "danger")
        else:
            flash("❌ Invalid reset code.", "danger")
    return render_template("reset_password.html")

# ----------------- OAuth Callback -----------------
@app.route("/oauth_callback")
def oauth_callback():
    user = None
    if google.authorized:
        resp = google.get("/oauth2/v1/userinfo")
        user_info = resp.json()
        email = (user_info.get("email") or "").lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            base = email.split("@")[0] or "user"
            candidate = base
            i = 1
            while User.query.filter_by(username=candidate).first():
                i += 1
                candidate = f"{base}{i}"
            user = User(username=candidate, email=email, password=generate_password_hash(os.urandom(16).hex()))
            db.session.add(user)
            db.session.commit()

    elif facebook.authorized:
        resp = facebook.get("/me?fields=name,email")
        user_info = resp.json()
        email = (user_info.get("email") or "").lower()
        name = (user_info.get("name") or "facebook_user").replace(" ", "").lower()[:80] or "facebook_user"
        user = User.query.filter_by(email=email).first() if email else None
        if not user:
            candidate = name
            i = 1
            while User.query.filter_by(username=candidate).first():
                i += 1
                candidate = f"{name}{i}"
            user = User(username=candidate, email=email or f"{candidate}@example.com",
                        password=generate_password_hash(os.urandom(16).hex()))
            db.session.add(user)
            db.session.commit()

    if user:
        session["user"] = user.username
        flash(f"✅ Logged in as {user.username}", "success")
        return redirect(url_for("dashboard"))

    flash("❌ OAuth login failed. Try again.", "danger")
    return redirect(url_for("login"))

# ----------------- Dashboard -----------------
@app.route("/dashboard")
def dashboard():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=username)

# ----------------- Submit Case -----------------
@app.route("/submit", methods=["GET", "POST"])
def submit():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        issue_type = request.form.get("issue_type")
        amount_lost = request.form.get("amount_lost")
        transaction_id = request.form.get("transaction_id")
        notes = request.form.get("notes")

        try:
            msg = Message(
                subject="New Case Submission",
                sender="noreply@cryptoguard.com",
                recipients=["company@example.com"]
            )
            msg.body = f"""
New Case Submitted by {username}

Type: {issue_type}
Amount Lost: ${amount_lost}
Wallet / Tx ID: {transaction_id}
Notes: {notes}
"""
            mail.send(msg)
            flash("✅ Case submitted successfully. Our team will review it shortly.", "success")
        except Exception as e:
            flash("⚠️ Case saved, but failed to send email notification.", "danger")

        return redirect(url_for("dashboard"))

    return render_template("submit.html")

# ----------------- Withdrawals -----------------
@app.route("/withdrawal", methods=["GET", "POST"])
def withdrawal():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        amount = float(request.form.get("amount", 0))
        method = request.form.get("method")
        destination = request.form.get("destination")
        bank_code = request.form.get("bank_code", "")

        if amount <= 0:
            flash("Invalid withdrawal amount.", "danger")
            return redirect(url_for("withdrawal"))

        if method == "bank":
            result = send_bank_transfer(amount, destination, bank_code)
        elif method == "crypto":
            result = send_btc(destination, amount)
        else:
            flash("Invalid withdrawal method.", "danger")
            return redirect(url_for("withdrawal"))

        if result.get("status") == "success":
            flash(f"Withdrawal of {amount} via {method} successful! TX: {result.get('tx', '')}", "success")
        else:
            flash(f"Withdrawal failed: {result.get('message', 'Unknown error')}", "danger")

        return redirect(url_for("dashboard"))

    return render_template("withdrawal.html", user=username)

# ----------------- Wallet -----------------
@app.route("/wallet")
def wallet():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    wallets = [
        {"coin": "BTC", "name": "Bitcoin", "balance": 0.523},
        {"coin": "ETH", "name": "Ethereum", "balance": 12.450},
        {"coin": "USDT", "name": "Tether", "balance": 2500.0}
    ]
    portfolio = [{"coin": w["coin"], "balance": w["balance"]} for w in wallets]
    market_trends = [
        {"coin": "BTC", "price": 27300, "change": "+2.5%"},
        {"coin": "ETH", "price": 1800, "change": "-1.2%"},
        {"coin": "USDT", "price": 1.0, "change": "0%"},
    ]

    return render_template(
        "wallet.html",
        wallets=wallets,
        portfolio=portfolio,
        market_trends=market_trends,
        user=username
    )

@app.route("/wallet/receive", methods=["POST"])
def receive_funds():
    username = session.get("user")
    if not username:
        return {"status": "error", "message": "Login required"}, 401

    coin = request.json.get("coin")
    amount = float(request.json.get("amount", 0))

    return {"status": "success", "message": f"{amount} {coin} added to your wallet"}

@app.route("/wallet/send", methods=["POST"])
def send_funds():
    username = session.get("user")
    if not username:
        return {"status": "error", "message": "Login required"}, 401

    coin = request.json.get("coin")
    amount = float(request.json.get("amount", 0))
    destination = request.json.get("destination")

    return {"status": "success", "message": f"Sent {amount} {coin} to {destination}"}

# ----------------- Activity -----------------
@app.route("/activity")
def activity():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    activities = [
        {"type": "Case Submitted", "details": "Reported BTC scam", "timestamp": "2024-02-10 14:32"},
        {"type": "Withdrawal", "details": "0.02 BTC withdrawn", "timestamp": "2024-02-09 18:10"},
        {"type": "Profile Update", "details": "Changed password", "timestamp": "2024-02-08 09:47"}
    ]
    return render_template("activity.html", activities=activities, user=username)

# ----------------- Track Case -----------------
@app.route("/track")
def track():
    username = session.get("user")
    if not username:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for("login"))

    cases = Case.query.filter_by(username=username).all()
    return render_template("track.html", cases=cases, user=username)

# ----------------- Email Helper -----------------
def send_email(to, code, purpose="password_reset"):
    try:
        subject = "Phantom Recovery - Verification Code"
        if purpose == "password_reset":
            body = f"Your verification code is: {code}\nIt will expire in 5 minutes."
        else:
            body = f"Your code: {code}"

        msg = Message(subject, recipients=[to])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print("Failed to send email:", e)

# ----------------- Run App -----------------
if __name__ == "__main__":
    with app.app_context():
        try:
            result = db.session.execute(text("SELECT 1")).scalar()
            print(f"[✔] Database connected, test query returned: {result}")
        except Exception as e:
            print(f"[✖] Database connection failed: {e}")
        if os.getenv("RESET_DB") == "1":
            db.drop_all()
            db.create_all()
        else:
            # always ensure schema, and create missing tables
            db.create_all()
            ensure_schema()
    app.run(host="0.0.0.0", port=10000, debug=False)

