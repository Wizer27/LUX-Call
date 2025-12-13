import os
from dotenv import load_dotenv

load_dotenv()

def connect():
    return f"postgresql+psycopg://{os.getenv("DB_USER")}:{os.getenv("DB_PASSWORD")}@localhost:5432/lux_call_user_data" 
