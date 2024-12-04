from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, make_response
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from wtforms import Form, StringField, PasswordField, SubmitField, validators
from wtforms.validators import DataRequired, Length, Email
from flask_login import LoginManager,UserMixin, login_required, login_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

app.config.from_object('config.Config')

# Initialize extensions
bcrypt = Bcrypt(app)
mongo = PyMongo(app)
jwt = JWTManager(app)


# User loader for JWT-based authentication
class User(UserMixin):
    def __init__(self, user_id, role, username):
        self.id = user_id
        self.role = role
        self.username = username

    @staticmethod
    def get(user_id):
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            return User(str(user["_id"]), user.get("role"), user.get("username"))
        return None

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(str(user["_id"]), user.get("role"), user.get("username"))
    return None


# Forms
class RegistrationForm(Form):
    username = StringField("Username", [validators.Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField("Password", [validators.DataRequired(), validators.Length(min=6)])
    submit = SubmitField('Register')


class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField("Password", [validators.DataRequired()])
    submit = SubmitField('Login')


# JWT Role-based decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user["role"] not in roles:
                flash("You do not have permission to access this resource.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
# Routes
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/profile")
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    return render_template("profile.html", username=current_user["username"])


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm(request.form)
    if request.method == "POST" and form.validate():
        username = form.username.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")

        role = "User"
        permissions = ["view_dashboard"]

        if mongo.db.users.find_one({"email": email}):
            flash("Username already exists. Please choose a different one.", "danger")
        else:
            mongo.db.users.insert_one({
                "username": username,
                "email": email,
                "password": password,
                "role": role,
                "permissions": permissions
            })

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        user = mongo.db.users.find_one({"email": form.email.data})
        if user and bcrypt.check_password_hash(user["password"], form.password.data):
            #access_token = create_access_token(identity=user["username"])
            access_token = create_access_token(
                identity=str(user["_id"]),
                additional_claims={"role": user["role"], "username": user["username"]}
            )
            print("access_token in login-- "+ access_token)

            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie('access_token_cookie', access_token)  # Set secure cookie
            return resp
            #return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@jwt_required()
def logout():
    # JWT doesn't have a logout endpoint, but you can revoke the token on the client side.
    return jsonify({"msg": "Successfully logged out"}), 200


@app.route("/dashboard")
@jwt_required(locations=["cookies"])
def dashboard():
    claims = get_jwt()
    user_role = claims.get("role")
    username = claims.get("username")
    current_user = get_jwt_identity()
    return render_template("dashboard.html", username=username, role=user_role)

@app.route("/user_panel")
@jwt_required(locations=["cookies"])
def user_panel():
    current_user = get_jwt_identity()
    print("current_user in user panel "+current_user)
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})
    username = user["username"]
    role = user["role"]
    print("role"+role)
    print("username" + username)
    if user["role"] != "User":
        flash("Unauthorized access!", "danger")

    return render_template("user.html",user=user)


@app.route("/add_message/<user_id>", methods=["POST"])
@jwt_required(locations=["headers", "cookies"])
def add_message(user_id):
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})
    print("add_message")
    # log_activity(user_id=current_user.id, username=session.get("username"), alert="User Added Message")
    if request.method == "POST":
        message = request.form.get("message")
        print("message "+message)
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$push": {"messages": message}})
        flash("Message added successfully!", "success")
        return redirect(url_for("user_panel"))
    return render_template("user.html", user=user)


@app.route("/edit_user/<user_id>", methods=["POST"])
@jwt_required(locations=["headers","cookies"])
def edit_user(user_id):
    print("user_id"+user_id)
    # print(request.cookies.get('access_token_cookie'))
    current_user = get_jwt_identity()
    # print(current_user)
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})
    # print("user "+user["username"])
    if request.method == "POST":
        if user["role"] == "User":
            email = request.form.get("email")
            username = request.form.get("username")
            mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"email": email,"username": username}})
            flash("User Details updated successfully!", "success")
            return redirect(url_for("user_panel"))
        elif user["role"] == "Admin":
            new_role = request.form.get("role")
            mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})
            flash("User Role updated successfully!", "success")
            return redirect(url_for("admin_panel"))
    return render_template("user.html", user=user)

@app.route("/admin/manage_roles", methods=["GET", "POST"])
@jwt_required()
def manage_roles():
    current_user = get_jwt_identity()
    if current_user["role"] != "Admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    users = mongo.db.users.find()  # Fetch all users
    if request.method == "POST":
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})
        flash("Role updated successfully!", "success")

    return render_template("manage_roles.html", users=users)


@app.route("/admin_panel")
@jwt_required(locations=["cookies"])
def admin_panel():
    current_user = get_jwt_identity()
    if current_user["role"] != "Admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    users = list(mongo.db.users.find())
    return render_template("admin.html", users=users)



@app.route("/user_posts")
@jwt_required()
def user_posts():
    current_user = get_jwt_identity()
    if current_user["role"] != "Moderator":
        flash("Access restricted to Moderators only.", "danger")
        return redirect(url_for("dashboard"))

    users = mongo.db.users.find({}, {"username": 1, "messages": 1})
    user_posts = [{"username": user.get("username"), "messages": user.get("messages", [])} for user in users]

    return render_template("user_posts.html", user_posts=user_posts)


if __name__ == "__main__":
    app.run(debug=True)
