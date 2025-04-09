import os
import pymongo
from dotenv import load_dotenv
import secrets

load_dotenv(dotenv_path=".env")

TITLE: str = "SCMXpertLite"
DESCRIPTION: str = """SCMXpertLite created in FastAPI"""
PROJECT_VERSION: str = "1.0.0"

MONGODB_USER = os.getenv("mongodb_user")
MONGODB_PASSWORD = os.getenv("mongodb_password")
MONGO_URI = os.getenv("mongouri")

mongo_client = pymongo.MongoClient(MONGO_URI)

database = mongo_client[os.getenv("DB_NAME")]  

Shipments = database['shipments']
User_details = database['user_details']
Device_Data_Stream= database['Device_Data_Stream']

ACCESS_TOKEN_EXPIRE_MINUTES = 30
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"