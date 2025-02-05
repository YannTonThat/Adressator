import os
from dotenv import load_dotenv

if os.path.exists("confidential.env"):
    load_dotenv("confidential.env")  # ✅ Charge les variables uniquement en local

class Config:

    STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
    SECRET_KEY = os.getenv("SECRET_KEY")
    APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
    APP_MAIL_USERNAME = os.getenv("APP_MAIL_USERNAME")
    APP_MAIL_PASSWORD = os.getenv("APP_MAIL_PASSWORD")
    APP_MAIL_DEFAULT_SENDER = os.getenv("APP_MAIL_DEFAULT_SENDER")
    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT")
    FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
    
    
