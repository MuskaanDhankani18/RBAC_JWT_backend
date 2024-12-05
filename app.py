from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, make_response
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from bson.objectid import ObjectId
from datetime import datetime, timedelta

from sqlalchemy.sql.functions import current_user
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

def log_activity(user_id, username, alert):
    activity = {
        "user_id": user_id,
        "username": username,
        "alert": alert,
        "timestamp": datetime.now()
    }
    mongo.db.logs_activity.insert_one(activity)


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
            user_id = mongo.db.users.insert_one({
                "username": username,
                "email": email,
                "password": password,
                "role": role,
                "permissions": permissions
            })
            log_activity(user_id=str(user_id), username=username, alert="New user registered")
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
            log_activity(user_id=str(user["_id"]), username=user["username"], alert="User logged in")
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie('access_token_cookie', access_token)  # Set secure cookie
            return resp
            #return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@jwt_required(locations=["cookies"])
def logout():
    response = make_response(redirect(url_for("home")))
    response.delete_cookie("access_token_cookie")  # Delete the JWT cookie
    flash("Successfully logged out!", "success")
    return response


@app.route("/dashboard")
@jwt_required(locations=["cookies"])
def dashboard():
    claims = get_jwt()
    user_role = claims.get("role")
    username = claims.get("username")
    current_user = get_jwt_identity()

    log_activity(user_id=current_user, username=username, alert="User accessed the dashboard")

    return render_template("dashboard.html", username=username, role=user_role)


@app.route("/user_panel")
@jwt_required(locations=["cookies"])
def user_panel():
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})
    username = user["username"]
    role = user["role"]

    if user["role"] != "User":
        flash("Unauthorized access!", "danger")

    return render_template("user.html",user=user)


@app.route("/add_message/<user_id>", methods=["POST"])
@jwt_required(locations=["headers", "cookies"])
def add_message(user_id):
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})

    if request.method == "POST":
        message = request.form.get("message")
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$push": {"messages": message}})
        log_activity(user_id=str(current_user), username=user["username"], alert="Message added by user")
        flash("Message added successfully!", "success")
        return redirect(url_for("user_panel"))

    return render_template("user.html", user=user)


@app.route("/edit_user/<user_id>", methods=["POST"])
@jwt_required(locations=["headers","cookies"])
def edit_user(user_id):
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})

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


@app.route("/delete_user/<user_id>", methods=["POST"])
@jwt_required(locations=["headers", "cookies"])
def delete_user(user_id):
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(current_user)})

    if user.get("role") != "Admin":
        flash("Unauthorized access! Only Admins can delete users.", "danger")
        return redirect(url_for("dashboard"))

    user_to_delete = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if user_to_delete:
        log_activity(user_id=str(current_user), username=user["username"], alert=f"Admin deleted user {user_to_delete['username']}")
    result = mongo.db.users.delete_one({"_id": ObjectId(user_id)})

    if result.deleted_count > 0:
        flash("User deleted successfully!", "success")
        return redirect(url_for("admin_panel"))

    else:
        flash("User not found. Deletion failed.", "danger")
        return redirect(url_for("admin_panel"))



# @app.route("/admin/manage_roles", methods=["GET", "POST"])
# @jwt_required()
# def manage_roles():
#     current_user = get_jwt_identity()
#     if current_user["role"] != "Admin":
#         flash("Unauthorized access!", "danger")
#         return redirect(url_for("dashboard"))
#
#     users = mongo.db.users.find()  # Fetch all users
#     if request.method == "POST":
#         user_id = request.form.get("user_id")
#         new_role = request.form.get("role")
#         mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})
#         flash("Role updated successfully!", "success")
#
#     return render_template("manage_roles.html", users=users)


@app.route("/admin_panel")
@jwt_required(locations=["cookies"])
def admin_panel():
    claims = get_jwt()
    if claims.get("role") != "Admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    users = list(mongo.db.users.find())
    return render_template("admin.html", users=users)


@app.route("/admin/search", methods=["GET"])
@jwt_required(locations=["cookies"])
def admin_search():
    claims = get_jwt()
    if claims.get("role") != "Admin":
        flash("Access restricted to Admins only.", "danger")
        return redirect(url_for("dashboard"))

    # Get query parameters
    search_query = request.args.get("query", "")
    role_filter = request.args.get("role", "")

    # Build query dynamically
    query = {}
    if search_query:
        query["$or"] = [
            {"username": {"$regex": search_query, "$options": "i"}},
            {"email": {"$regex": search_query, "$options": "i"}}
        ]
    if role_filter:
        query["role"] = role_filter

    # Fetch results
    users = list(mongo.db.users.find(query))

    return render_template("admin.html", users=users, search_query=search_query, role_filter=role_filter)


@app.route("/moderator")
@jwt_required(locations=["headers","cookies"])
# @permission_required()
def moderator_panel():
    # user = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    claims = get_jwt()
    if claims.get("role") != "Moderator":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("dashboard"))

    activities = mongo.db.logs_activity.find().sort("timestamp", -1).limit(100)

    return render_template("moderator.html", activities=activities)


@app.route("/user_posts")
@jwt_required(locations=["cookies"])
def user_posts():
    current_user = get_jwt_identity()
    claims = get_jwt()
    if claims["role"] != "Moderator":
        flash("Access restricted to Moderators only.", "danger")
        return redirect(url_for("dashboard"))

    users = mongo.db.users.find({}, {"username": 1, "messages": 1})
    user_posts = [{"username": user.get("username"), "messages": user.get("messages", [])} for user in users]

    return render_template("user_posts.html", user_posts=user_posts)


if __name__ == "__main__":
    app.run(debug=True)
