import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import os

class TrafficPreprocessor:
    def __init__(self):
        # Added request_rate_1min
        self.numeric_features = ['packet_size', 'latency', 'url_length', 'num_params', 'request_rate_1min']
        self.categorical_features = ['method', 'protocol']
        
        self.pipeline = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), self.numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore'), self.categorical_features)
            ])
            
    def fit(self, data):
        """Fit the preprocessor on training data."""
        df = pd.DataFrame(data)
        self.pipeline.fit(df)
        return self

    def transform(self, data):
        """Transform data into feature vectors."""
        df = pd.DataFrame(data)
        return self.pipeline.transform(df)

    def save(self, filepath):
        joblib.dump(self.pipeline, filepath)

    def load(self, filepath):
        self.pipeline = joblib.load(filepath)
