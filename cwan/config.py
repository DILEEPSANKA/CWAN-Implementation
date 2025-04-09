import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "you-will-never-guess"
    # Add more configuration variables as needed
    LOGGING_LEVEL = os.environ.get("LOGGING_LEVEL") or "DEBUG"
    LOG_FILE = os.environ.get("LOG_FILE") or "app.log"
    MONGO_URI = os.environ.get("MONGO_URI") or "mongodb://localhost:27017"
    MONGO_DBNAME = os.environ.get("MONGO_DBNAME") or "flex-render"
    # Extensions initialization
    # EXTENSIONS_FOLDER = os.path.join(os.getcwd(), "extensions")
    EXTENSIONS = os.environ.get("EXTENSIONS", "").split(" ")
    EXTENSION_FOLDER = os.environ.get("EXTENSION_FOLDER", "")
