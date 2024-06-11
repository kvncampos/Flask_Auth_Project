from flask import (
    Flask,
    render_template,
    request,
    session,
    url_for,
    redirect,
    flash,
    send_from_directory,
)
from flask_bootstrap import Bootstrap5
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from sqlalchemy.exc import SQLAlchemyError
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user,
)
from dotenv import load_dotenv
from os import environ
from forms.forms import RegistrationForm, LoginForm

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# take environment variables from .env.
load_dotenv()

# FLASK APP SETUP
app = Flask(__name__)
app.config["SECRET_KEY"] = environ.get("SECRET_KEY")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["STATIC_FOLDER"] = "static"

# Bootstrap-Flask requires this line
bootstrap = Bootstrap5(app)
# Flask-WTF requires this line
csrf = CSRFProtect(app)
# Flask Login Config
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)
migrate = Migrate()
bcrypt = Bcrypt()
migrate.init_app(app, db)
bcrypt.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    def __repr__(self):
        return "<User %r>" % self.name


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("User already exists. Please log in.", "warning")
            return redirect(url_for("login"))

        session["email"] = form.email.data
        hash_and_salted_password = generate_password_hash(
            password=form.password.data, method="pbkdf2:sha256", salt_length=8
        )
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash_and_salted_password,
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            print({"status": "user created in db."})
        except SQLAlchemyError as error:
            db.session.rollback()
            print(f"Error: {error}", 400)
        finally:
            print({"status": "db closed"})
            db.session.close()

        return redirect(url_for("secrets"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    # Initialize counter in session if not already present
    if "login_attempts" not in session:
        session["login_attempts"] = 0

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        try:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                session["email"] = user.email
                session["login_attempts"] = 0  # Reset counter on successful login
                login_user(user)  # Log the user in
                flash("Login successful!", "success")
                return redirect(url_for("secrets"))
            else:
                session["login_attempts"] += 1  # Increment counter on failed login
                flash("Login failed. Check your email and password.", "danger")

                # Check if login attempts exceed 3
                if session["login_attempts"] >= 3:
                    flash(
                        "Too many failed login attempts. Redirecting to homepage.",
                        "danger",
                    )
                    session["login_attempts"] = 0  # Just For Testing Purposes
                    return redirect(url_for("home"))

                return render_template("login.html", form=form)

        except SQLAlchemyError as error:
            db.session.rollback()
            print(f"Error: {error}", 400)

        finally:
            db.session.close()
            print({"status": "db closed"})

    return render_template("login.html", form=form)


@app.route("/secrets")
@login_required
def secrets():
    email = session.get("email")
    if email:
        account = User.query.filter_by(email=email).first_or_404()
        return render_template("secrets.html", user=account.name)
    else:
        return redirect(url_for("login"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/download")
@login_required
def download():
    # Ensure the STATIC_FOLDER is correctly configured
    static_folder = app.config.get("STATIC_FOLDER", "static")

    return send_from_directory(
        directory=static_folder, path="files/cheat_sheet.pdf", as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
