from dotenv import load_dotenv
import os
load_dotenv()

class Config:
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SECRET_KEY = os.environ.get('SECRET_KEY', 'una-clave-secreta-temporal')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Zona horaria por defecto para las conexiones a la DB (ej. '+05:00')
    DB_TIMEZONE = os.environ.get('DB_TIMEZONE', '+05:00')

