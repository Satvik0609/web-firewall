from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
import joblib
import numpy as np
import os
import datetime

class AutoencoderDetector:
    def __init__(self, hidden_layer_sizes=(10, 5, 10), max_iter=500):
        self.model = MLPRegressor(hidden_layer_sizes=hidden_layer_sizes, 
                                  activation='relu', 
                                  solver='adam', 
                                  max_iter=max_iter, 
                                  random_state=42)
        self.threshold = 0.0
        self.is_fitted = False

    def fit(self, X):
        # Autoencoder maps Input -> Input
        self.model.fit(X, X)
        
        # Determine threshold (95th percentile of reconstruction error on training data)
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)
        self.is_fitted = True

    def predict(self, X):
        if not self.is_fitted:
            raise ValueError("Model not fitted yet.")
        
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        
        # 1 for normal (error <= threshold), -1 for anomaly (error > threshold)
        return np.where(mse <= self.threshold, 1, -1)

    def score_samples(self, X):
        # Return negative MSE as score (compatible with IsolationForest where lower is more anomalous)
        # IF: lower (more negative) is worse.
        # MSE: higher is worse.
        # So we return -MSE.
        if not self.is_fitted:
            raise ValueError("Model not fitted yet.")
        
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        return -mse

class AnomalyDetector:
    def __init__(self, model_type='isolation_forest', contamination=0.05):
        self.model_type = model_type
        if model_type == 'isolation_forest':
            self.model = IsolationForest(contamination=contamination, random_state=42)
        elif model_type == 'autoencoder':
            # Note: hidden layers should be tuned based on feature size. 
            # We'll assume typical feature size ~10-20, so (8, 4, 8) is decent.
            self.model = AutoencoderDetector(hidden_layer_sizes=(8, 4, 8))
        else:
            raise ValueError(f"Unknown model type: {model_type}")
            
        self.is_fitted = False

    def train(self, X):
        """Train the model."""
        if self.model_type == 'isolation_forest':
            self.model.fit(X)
        else:
            self.model.fit(X)
        self.is_fitted = True

    def predict(self, X):
        """
        Predict anomalies.
        Returns: 
            -1 for anomaly
            1 for normal
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted yet.")
        return self.model.predict(X)

    def score_samples(self, X):
        """Return anomaly scores."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet.")
        return self.model.score_samples(X)

    def save(self, filepath):
        # We save the wrapper object itself to preserve model_type and threshold
        joblib.dump(self, filepath)
        
        # Save a versioned backup
        dirname = os.path.dirname(filepath)
        filename = os.path.basename(filepath)
        name, ext = os.path.splitext(filename)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(dirname, f"{name}_{timestamp}{ext}")
        
        try:
            joblib.dump(self, backup_path)
        except Exception as e:
            print(f"Warning: Could not save backup model: {e}")

    def load(self, filepath):
        # Load the entire object
        loaded = joblib.load(filepath)
        
        # If the loaded object is an AnomalyDetector (new version), replace self
        if isinstance(loaded, AnomalyDetector):
            self.model = loaded.model
            self.model_type = loaded.model_type
            self.is_fitted = loaded.is_fitted
        # Backward compatibility for old IsolationForest dumps
        elif isinstance(loaded, IsolationForest):
            self.model = loaded
            self.model_type = 'isolation_forest'
            self.is_fitted = True
        else:
            # Fallback or error
            raise ValueError("Unknown model format")
