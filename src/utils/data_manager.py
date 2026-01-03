import pandas as pd
import time
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database import Base, SessionLocal, engine as default_engine
from src.models import TrafficLogDB

class DataManager:
    def __init__(self, db_path=None):
        # If db_path is provided, we might need to re-bind the engine
        # But for simplicity, we'll rely on the global engine unless specific override logic is needed
        # For testing, we might need to swap the engine.
        self.Session = SessionLocal
        self._initialize_db()

    def _initialize_db(self):
        # Create tables
        # If we need to support dynamic db_path for tests:
        pass # Tables are created via Base.metadata.create_all(bind=engine) called externally or here
        Base.metadata.create_all(bind=default_engine)

    def log_traffic(self, log_data, result):
        """
        Log traffic data and model result to DB.
        """
        session = self.Session()
        try:
            entry = TrafficLogDB(
                timestamp = time.time(),
                source_ip = log_data.get('source_ip'),
                packet_size = log_data.get('packet_size'),
                latency = log_data.get('latency'),
                url_length = log_data.get('url_length'),
                num_params = log_data.get('num_params'),
                method = log_data.get('method'),
                protocol = log_data.get('protocol'),
                request_rate_1min = log_data.get('request_rate_1min', 0),
                is_anomaly = result['is_anomaly'],
                anomaly_score = result['anomaly_score'],
                recommendation = result.get('recommendation', 'None'),
                explanation = result.get('explanation', 'None'),
                user_feedback = None
            )
            session.add(entry)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error logging to DB: {e}")
        finally:
            session.close()

    def add_feedback(self, timestamp, feedback_label):
        """
        Update feedback for a specific log entry.
        """
        session = self.Session()
        try:
            # Find record with close timestamp
            # We use a small epsilon
            record = session.query(TrafficLogDB).filter(
                TrafficLogDB.timestamp > timestamp - 0.001,
                TrafficLogDB.timestamp < timestamp + 0.001
            ).first()
            
            if record:
                record.user_feedback = feedback_label
                session.commit()
                return True
            return False
        finally:
            session.close()

    def load_data(self, limit=1000):
        """Load recent data for retraining or dashboard."""
        session = self.Session()
        try:
            # Query recent logs
            q = session.query(TrafficLogDB).order_by(TrafficLogDB.timestamp.desc()).limit(limit)
            
            # Use pandas to read from query statement
            # session.connection() might be needed
            df = pd.read_sql(q.statement, session.bind)
            
            return df.sort_values('timestamp')
        except Exception as e:
            print(f"Error loading data: {e}")
            return pd.DataFrame()
        finally:
            session.close()

    def get_training_data(self):
        """Get all data for retraining."""
        session = self.Session()
        try:
            q = session.query(TrafficLogDB)
            df = pd.read_sql(q.statement, session.bind)
            return df
        finally:
            session.close()
