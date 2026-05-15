import pandas as pd
import numpy as np
import requests
import time
import random

# Load real test data
print("⏳ Loading real NSL-KDD test data...")

test_df = pd.read_csv('../data/processed/X_test.csv')
y_test  = pd.read_csv('../data/processed/y_test.csv').values.ravel()

# Original categorical columns mapping (reverse of encoding)
PROTOCOL_MAP = {0: 'tcp', 1: 'udp', 2: 'icmp'}
SERVICE_MAP  = {
    0: 'aol', 1: 'auth', 2: 'bgp', 3: 'courier', 4: 'csnet_ns',
    5: 'ctf', 6: 'daytime', 7: 'discard', 8: 'domain', 9: 'domain_u',
    10: 'echo', 11: 'eco_i', 12: 'ecr_i', 13: 'efs', 14: 'exec',
    15: 'finger', 16: 'ftp', 17: 'ftp_data', 18: 'gopher',
    19: 'harvest', 20: 'hostnames', 21: 'http', 22: 'http_2784',
    23: 'http_443', 24: 'http_8001', 25: 'imap4', 26: 'IRC',
    27: 'iso_tsap', 28: 'klogin', 29: 'kshell', 30: 'ldap',
    31: 'link', 32: 'login', 33: 'mtp', 34: 'name',
    35: 'netbios_dgm', 36: 'netbios_ns', 37: 'netbios_ssn',
    38: 'netstat', 39: 'nnsp', 40: 'nntp', 41: 'ntp_u',
    42: 'other', 43: 'pm_dump', 44: 'pop_2', 45: 'pop_3',
    46: 'printer', 47: 'private', 48: 'red_i', 49: 'remote_job',
    50: 'rje', 51: 'shell', 52: 'smtp', 53: 'sql_net', 54: 'ssh',
    55: 'sunrpc', 56: 'supdup', 57: 'systat', 58: 'telnet',
    59: 'tftp_u', 60: 'tim_i', 61: 'time', 62: 'urh_i', 63: 'urp_i',
    64: 'uucp', 65: 'uucp_path', 66: 'vmnet', 67: 'whois',
    68: 'X11', 69: 'Z39_50'
}
FLAG_MAP = {
    0: 'OTH', 1: 'REJ', 2: 'RSTO', 3: 'RSTOS0',
    4: 'RSTR', 5: 'S0', 6: 'S1', 7: 'S2',
    8: 'S3', 9: 'SF', 10: 'SH'
}

FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

def row_to_dict(row):
    """Convert a dataframe row back to original feature dict"""
    d = {}
    for col in FEATURE_NAMES:
        val = row[col]
        if col == 'protocol_type':
            # Convert encoded number back to string
            val = PROTOCOL_MAP.get(int(round(float(val))), 'tcp')
        elif col == 'service':
            val = SERVICE_MAP.get(int(round(float(val))), 'other')
        elif col == 'flag':
            val = FLAG_MAP.get(int(round(float(val))), 'SF')
        else:
            val = float(val)
        d[col] = val
    return d

print(f"✅ Loaded {len(test_df)} real test records!")
print("🚀 Starting pipeline simulation...")
print("📊 Dashboard: http://127.0.0.1:5000")
print("Press Ctrl+C to stop\n")

# Send records to Flask API one by one
correct = 0
total   = 0

try:
    for i, row in test_df.iterrows():
        data   = row_to_dict(row)
        actual = y_test[total]

        try:
            response = requests.post(
                'http://127.0.0.1:5000/predict',
                json=data,
                timeout=5
            )
            result = response.json()

            # Check for errors
            if 'error' in result:
                print(f"API Error on record {i}: {result['error']}")
                total += 1
                continue

            predicted = result.get('prediction', -1)

            # Track accuracy
            if predicted == actual:
                correct += 1
            total += 1

            category = result.get('category', 'UNKNOWN')
            conf     = result.get('confidence', 0)
            blocked  = '🚫 AUTO-BLOCKED' if result.get('blocked') else ''

            icons = {
                'NORMAL':          '✅',
                'SUSPICIOUS':      '⚪',
                'MODERATE THREAT': '🟡',
                'SEVERE THREAT':   '🔴'
            }
            icon   = icons.get(category, '🔍')
            match  = "✓" if predicted == actual else "✗"

            print(f"[{total:04d}] {icon} {category:15s} "
                  f"| Conf: {conf:5.1f}% "
                  f"| Actual: {'Normal' if actual==0 else 'Attack':7s} "
                  f"| {match} "
                  f"| Acc: {correct/total*100:.1f}% {blocked}")

        except Exception as e:
            print(f"Error sending record {i}: {e}")
            total += 1

        time.sleep(random.uniform(0.3, 0.8))

except KeyboardInterrupt:
    print(f"\n⏹ Simulation stopped!")
    print(f"📊 Final Accuracy: {correct/total*100:.2f}%")
    print(f"✅ Correct: {correct}/{total}")