import os
from dotenv import load_dotenv

load_dotenv()

class Config(object):
    ENV = os.getenv("FRONTEND_ENV", "development")
    DEBUG = True if ENV == "development" else False
    TESTING = True if ENV == "development" else False
    
    SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")
    