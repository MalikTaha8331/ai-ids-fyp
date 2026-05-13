import joblib
import numpy as np
import os
from features import FEATURE_NAMES, PROTOCOL_TYPES, SERVICE_TYPES, FLAG_TYPES

# Load model once when server starts
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'best_model.pkl')
model = joblib.load(MODEL_PATH)

def encode_features(data):
    """Encode categorical features to numbers"""
    data['protocol_type'] = PROTOCOL_TYPES.get(data['protocol_type'], 0)
    data['service']       = SERVICE_TYPES.get(data['service'], 42)
    data['flag']          = FLAG_TYPES.get(data['flag'], 9)
    return data

def predict_traffic(data):
    """Take raw feature dict and return prediction"""
    # Encode categorical values
    data = encode_features(data)

    # Build feature vector in correct order
    features = np.array([[data.get(f, 0) for f in FEATURE_NAMES]])

    # Get prediction and confidence
    prediction  = model.predict(features)[0]
    probability = model.predict_proba(features)[0]
    confidence  = round(float(max(probability)) * 100, 2)

    return {
        'prediction': int(prediction),
        'label':      'ATTACK' if prediction == 1 else 'NORMAL',
        'confidence': confidence
    }