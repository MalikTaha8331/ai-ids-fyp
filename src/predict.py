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

def get_threat_category(prediction, confidence):
    """Classify threat based on prediction and confidence score"""
    try:
        prediction = int(prediction)
        confidence = float(confidence)

        if prediction == 0:
            return {
                'category':    'NORMAL',
                'level':       0,
                'color':       'green',
                'auto_block':  False,
                'show_block':  False,
                'description': 'Traffic appears normal'
            }
        elif confidence < 55:
            return {
                'category':    'SUSPICIOUS',
                'level':       1,
                'color':       'gray',
                'auto_block':  False,
                'show_block':  True,
                'description': 'Low confidence threat — monitor closely'
            }
        elif confidence <= 75:
            return {
                'category':    'MODERATE THREAT',
                'level':       2,
                'color':       'yellow',
                'auto_block':  False,
                'show_block':  True,
                'description': 'Moderate threat — admin action recommended'
            }
        else:
            return {
                'category':    'SEVERE THREAT',
                'level':       3,
                'color':       'red',
                'auto_block':  True,
                'show_block':  False,
                'description': 'Severe threat — auto-blocked immediately!'
            }
    except Exception as e:
        return {
            'category':    'UNKNOWN',
            'level':       0,
            'color':       'gray',
            'auto_block':  False,
            'show_block':  False,
            'description': f'Classification error: {str(e)}'
        }

def predict_traffic(data):
    """Take raw feature dict and return prediction + threat category"""
    try:
        # Make a copy to avoid modifying original
        data_copy = dict(data)

        # Encode categorical values
        data_copy = encode_features(data_copy)

        # Build feature vector in correct order
        features = np.array([[data_copy.get(f, 0) for f in FEATURE_NAMES]])

        # Get prediction and confidence
        prediction  = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        confidence  = round(float(max(probability)) * 100, 2)

        # Get threat category
        threat = get_threat_category(int(prediction), confidence)

        return {
            'prediction':  int(prediction),
            'label':       'ATTACK' if prediction == 1 else 'NORMAL',
            'confidence':  confidence,
            'category':    threat['category'],
            'level':       threat['level'],
            'color':       threat['color'],
            'auto_block':  threat['auto_block'],
            'show_block':  threat['show_block'],
            'description': threat['description']
        }
    except Exception as e:
        return {
            'prediction':  0,
            'label':       'ERROR',
            'confidence':  0,
            'category':    'UNKNOWN',
            'level':       0,
            'color':       'gray',
            'auto_block':  False,
            'show_block':  False,
            'description': str(e)
        }