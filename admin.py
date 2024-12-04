from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["authSystem_db"]
users_collection = db["users"]

# Initialize Bcrypt for password hashing
bcrypt = Bcrypt()

# Insert admin user
admin_user = {
    "username": "admin",
    "email": "admin@gmail.com",
    "password": bcrypt.generate_password_hash("admin123").decode("utf-8"),
    "role": "Admin"
}

activity = {
    "user_id": ObjectId("a32a804ce636972e43041e28"),
    "username": "ramKumar",
    "alert": "User Logged In",
    "timestamp": datetime.now()
}

db.logs_activity.insert_one(activity)

if not users_collection.find_one({"email": "admin@gmail.com"}):
    users_collection.insert_one(admin_user)
    print("Admin user created successfully.")
else:
    print("Admin user already exists.")
