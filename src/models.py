from sqlalchemy import Column, Integer, String, Float, Boolean, Text
from src.database import Base

class TrafficLogDB(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, index=True)
    source_ip = Column(String, index=True)
    packet_size = Column(Integer)
    latency = Column(Float)
    url_length = Column(Integer)
    num_params = Column(Integer)
    method = Column(String)
    protocol = Column(String)
    request_rate_1min = Column(Float)
    is_anomaly = Column(Boolean)
    anomaly_score = Column(Float)
    user_feedback = Column(String, nullable=True)
    recommendation = Column(String)
    explanation = Column(Text)
