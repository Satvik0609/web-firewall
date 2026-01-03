from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Ensure directory exists
os.makedirs("data/processed", exist_ok=True)

# Default to SQLite, but ready for Postgres
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/processed/traffic_logs.db")

# check_same_thread is needed for SQLite only
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
