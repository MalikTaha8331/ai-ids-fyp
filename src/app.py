from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from predict import predict_traffic
import time
import os

app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static'
)
CORS(app)

# In-memory storage
alerts     = []
blocked_ips = {}  # ip -> {time, reason, confidence}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data   = request.get_json()
        result = predict_traffic(data)

        # Get source IP (simulated if not provided)
        src_ip = data.get('src_ip', f"192.168.1.{len(alerts) % 255 + 1}")

        # Build alert record
        alert = {
            'time':        time.strftime('%H:%M:%S'),
            'label':       result['label'],
            'category':    result['category'],
            'confidence':  result['confidence'],
            'color':       result['color'],
            'auto_block':  result['auto_block'],
            'show_block':  result['show_block'],
            'description': result['description'],
            'src_bytes':   data.get('src_bytes', 0),
            'protocol':    data.get('protocol_type', 'tcp'),
            'src_ip':      src_ip,
            'blocked':     False
        }

        # Auto block severe threats
        if result['auto_block']:
            blocked_ips[src_ip] = {
                'time':       time.strftime('%H:%M:%S'),
                'reason':     result['category'],
                'confidence': result['confidence']
            }
            alert['blocked'] = True
            print(f"🚫 AUTO-BLOCKED: {src_ip} — {result['category']} ({result['confidence']}%)")

        alerts.append(alert)
        if len(alerts) > 100:
            alerts.pop(0)

        result['src_ip']  = src_ip
        result['blocked'] = alert['blocked']
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts[-50:])

@app.route('/stats', methods=['GET'])
def get_stats():
    total        = len(alerts)
    attacks      = sum(1 for a in alerts if a['label'] == 'ATTACK')
    severe       = sum(1 for a in alerts if a['category'] == 'SEVERE THREAT')
    moderate     = sum(1 for a in alerts if a['category'] == 'MODERATE THREAT')
    suspicious   = sum(1 for a in alerts if a['category'] == 'SUSPICIOUS')
    auto_blocked = sum(1 for a in alerts if a['blocked'])
    return jsonify({
        'total':        total,
        'attacks':      attacks,
        'normal':       total - attacks,
        'severe':       severe,
        'moderate':     moderate,
        'suspicious':   suspicious,
        'auto_blocked': auto_blocked,
        'blocked_ips':  len(blocked_ips)
    })

@app.route('/block', methods=['POST'])
def block_ip():
    data = request.get_json()
    ip   = data.get('ip')
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400
    blocked_ips[ip] = {
        'time':       time.strftime('%H:%M:%S'),
        'reason':     'Manual block by admin',
        'confidence': data.get('confidence', 0)
    }
    print(f"🚫 MANUAL BLOCK: {ip}")
    return jsonify({'success': True, 'message': f'IP {ip} blocked successfully'})

@app.route('/unblock', methods=['POST'])
def unblock_ip():
    data = request.get_json()
    ip   = data.get('ip')
    if ip in blocked_ips:
        del blocked_ips[ip]
        print(f"✅ UNBLOCKED: {ip}")
        return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    return jsonify({'error': 'IP not found'}), 404

@app.route('/blocked', methods=['GET'])
def get_blocked():
    return jsonify(blocked_ips)

# Store live traffic
live_traffic = []
MAX_TRAFFIC  = 100000  # store up to 100k packets

@app.route('/live')
def live_page():
    return render_template('live.html')

@app.route('/traffic', methods=['POST'])
def add_traffic():
    try:
        data = request.get_json()
        live_traffic.append(data)
        # Only trim if memory gets very large
        if len(live_traffic) > MAX_TRAFFIC:
            live_traffic.pop(0)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/traffic', methods=['GET'])
def get_traffic():
    protocol = request.args.get('protocol', '')
    service  = request.args.get('service', '')
    category = request.args.get('category', '')

    filtered = live_traffic

    if protocol:
        filtered = [t for t in filtered if t.get('protocol', '').lower() == protocol.lower()]
    if service:
        filtered = [t for t in filtered if t.get('service', '').lower() == service.lower()]
    if category:
        filtered = [t for t in filtered if t.get('category', '').lower() == category.lower()]

    return jsonify(filtered)

if __name__ == '__main__':
    print("⚔️  CyberSentinel Starting...")
    print("📊 Dashboard: http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)