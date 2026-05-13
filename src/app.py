from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from predict import predict_traffic
import random
import time
import os

app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static'
)
CORS(app)

# Store recent alerts in memory
alerts = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        result = predict_traffic(data)

        # Store alert if attack detected
        if result['prediction'] == 1:
            alerts.append({
                'time':       time.strftime('%H:%M:%S'),
                'label':      result['label'],
                'confidence': result['confidence'],
                'src_bytes':  data.get('src_bytes', 0),
                'protocol':   data.get('protocol_type', 'unknown')
            })
            # Keep only last 50 alerts
            if len(alerts) > 50:
                alerts.pop(0)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

@app.route('/stats', methods=['GET'])
def get_stats():
    total    = len(alerts)
    attacks  = sum(1 for a in alerts if a['label'] == 'ATTACK')
    return jsonify({
        'total_alerts':   total,
        'total_attacks':  attacks,
        'total_normal':   total - attacks
    })

if __name__ == '__main__':
    print("🚀 AI-IDS Server starting...")
    print("📊 Dashboard: http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)