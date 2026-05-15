from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
import time
from collections import defaultdict
import threading

# Flask API endpoint
API_URL = 'http://127.0.0.1:5000/predict'

# Track connection statistics
connection_stats = defaultdict(lambda: {
    'count': 0, 'srv_count': 0,
    'serror_rate': 0, 'rerror_rate': 0,
    'same_srv_rate': 0, 'diff_srv_rate': 0,
    'dst_host_count': 0, 'dst_host_srv_count': 0,
    'dst_host_same_srv_rate': 0, 'dst_host_serror_rate': 0,
    'dst_host_srv_serror_rate': 0,
    'start_time': time.time()
})

def get_service(port):
    """Map port number to service name"""
    port_map = {
        80: 'http', 443: 'http_443', 21: 'ftp', 22: 'ssh',
        23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop_3',
        143: 'imap4', 3306: 'sql_net', 8080: 'http_8001',
        20: 'ftp_data', 37: 'time', 79: 'finger', 119: 'nntp'
    }
    return port_map.get(port, 'private')

def get_flag(tcp_flags):
    """Map TCP flags to NSL-KDD flag names"""
    if tcp_flags is None:
        return 'SF'
    flags = int(tcp_flags)
    if flags == 0x02:  return 'S0'   # SYN only
    if flags == 0x12:  return 'SF'   # SYN-ACK
    if flags == 0x14:  return 'RSTO' # RST-ACK
    if flags == 0x04:  return 'RSTR' # RST
    if flags == 0x11:  return 'REJ'  # FIN-ACK
    if flags == 0x01:  return 'SH'   # FIN
    return 'SF'

def extract_features(packet):
    """Extract 41 NSL-KDD features from a live packet"""
    try:
        if not packet.haslayer(IP):
            return None

        ip  = packet[IP]
        src = ip.src
        dst = ip.dst

        # Protocol
        if packet.haslayer(TCP):
            proto    = 'tcp'
            tcp      = packet[TCP]
            dst_port = tcp.dport
            src_port = tcp.sport
            flag     = get_flag(tcp.flags)
            service  = get_service(dst_port)
        elif packet.haslayer(UDP):
            proto    = 'udp'
            udp      = packet[UDP]
            dst_port = udp.dport
            src_port = udp.sport
            flag     = 'SF'
            service  = get_service(dst_port)
        elif packet.haslayer(ICMP):
            proto    = 'icmp'
            dst_port = 0
            src_port = 0
            flag     = 'SF'
            service  = 'ecr_i'
        else:
            return None

        # Bytes
        src_bytes = len(packet)
        dst_bytes = 0

        # Connection key
        conn_key = f"{src}:{src_port}-{dst}:{dst_port}"
        stats    = connection_stats[conn_key]
        stats['count'] += 1
        stats['dst_host_count'] += 1

        # Duration
        duration = round(time.time() - stats['start_time'], 2)

        # Build feature dict
        features = {
            'duration':                    duration,
            'protocol_type':               proto,
            'service':                     service,
            'flag':                        flag,
            'src_bytes':                   src_bytes,
            'dst_bytes':                   dst_bytes,
            'land':                        1 if src == dst else 0,
            'wrong_fragment':              0,
            'urgent':                      0,
            'hot':                         0,
            'num_failed_logins':           0,
            'logged_in':                   0,
            'num_compromised':             0,
            'root_shell':                  0,
            'su_attempted':                0,
            'num_root':                    0,
            'num_file_creations':          0,
            'num_shells':                  0,
            'num_access_files':            0,
            'num_outbound_cmds':           0,
            'is_host_login':               0,
            'is_guest_login':              0,
            'count':                       min(stats['count'], 511),
            'srv_count':                   min(stats['count'], 511),
            'serror_rate':                 1.0 if flag == 'S0' else 0.0,
            'srv_serror_rate':             1.0 if flag == 'S0' else 0.0,
            'rerror_rate':                 1.0 if flag in ['REJ','RSTR'] else 0.0,
            'srv_rerror_rate':             1.0 if flag in ['REJ','RSTR'] else 0.0,
            'same_srv_rate':               1.0,
            'diff_srv_rate':               0.0,
            'srv_diff_host_rate':          0.0,
            'dst_host_count':              min(stats['dst_host_count'], 255),
            'dst_host_srv_count':          min(stats['count'], 255),
            'dst_host_same_srv_rate':      1.0,
            'dst_host_diff_srv_rate':      0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate':        1.0 if flag == 'S0' else 0.0,
            'dst_host_srv_serror_rate':    1.0 if flag == 'S0' else 0.0,
            'dst_host_rerror_rate':        0.0,
            'dst_host_srv_rerror_rate':    0.0,
            'src_ip':                      src
        }
        return features

    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None

def process_packet(packet):
    """Process each captured packet"""
    features = extract_features(packet)
    if features is None:
        return

    try:
        # Send to predict endpoint
        response = requests.post(API_URL, json=features, timeout=2)
        result   = response.json()
        category = result.get('category', 'UNKNOWN')
        conf     = result.get('confidence', 0)
        src_ip   = features['src_ip']

        # Build traffic record
        traffic_record = {
            'time':      time.strftime('%H:%M:%S'),
            'src_ip':    src_ip,
            'protocol':  features['protocol_type'].upper(),
            'service':   features['service'],
            'src_bytes': features['src_bytes'],
            'flag':      features['flag'],
            'category':  category,
            'confidence': conf,
            'color':     result.get('color', 'gray'),
            'blocked':   result.get('blocked', False)
        }

        # Send to traffic endpoint
        requests.post(
            'http://127.0.0.1:5000/traffic',
            json=traffic_record,
            timeout=2
        )

        icons = {
            'NORMAL':          '✅',
            'SUSPICIOUS':      '⚪',
            'MODERATE THREAT': '🟡',
            'SEVERE THREAT':   '🔴'
        }
        icon = icons.get(category, '🔍')

        if category != 'NORMAL':
            blocked = '🚫 AUTO-BLOCKED!' if result.get('blocked') else ''
            print(f"{icon} {category:15s} | {src_ip:15s} | "
                  f"Conf: {conf:.1f}% | "
                  f"{features['protocol_type'].upper():4s} | "
                  f"{features['service']:10s} {blocked}")

    except Exception as e:
        pass

def start_sniffing(interface=None):
    """Start live packet capture"""
    print("🚀 AI-IDS Live Sniffer Starting...")
    print("📊 Dashboard: http://127.0.0.1:5000")
    print("🔍 Capturing live network traffic...")
    print("Press Ctrl+C to stop\n")

    try:
        # Sniff all traffic — filter out our own API calls
        sniff(
            iface=interface,
            prn=process_packet,
            filter="ip and not port 5000",
            store=0
        )
    except KeyboardInterrupt:
        print("\n⏹ Sniffer stopped!")
    except Exception as e:
        print(f"Sniffer error: {e}")
        print("Try running as Administrator!")

if __name__ == '__main__':
    start_sniffing()