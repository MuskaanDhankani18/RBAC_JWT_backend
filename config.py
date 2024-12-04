import os

class Config:
    SECRET_KEY = os.urandom(24)
    MONGO_URI = "mongodb://localhost:27017/authSystem_db"  # Adjust as per your MongoDB setup
