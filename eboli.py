from flask import Flask, request, jsonify
import numpy as np
import joblib
from waitress import serve
import logging

app = Flask(__name__)


try:
    model = joblib.load('eboli.pkl')
    scaler = joblib.load('scaler.pkl')
    print("Model and scaler loaded successfully!")
except Exception as e:
    print(f"Error loading model or scaler: {e}")
    exit(1)

#  logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='eboli.log'
)

# Feature / must match training data
FEATURE_NAMES = [
    'packet_size', 'packet_rate', 'protocol_type', 
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

# Attack type 
ATTACK_LABELS = {
    0: "Normal",
    1: "DDoS",
    2: "Spoofing",
    3: "Port Scan",
    4: "Brute Force",
    5: "Malware"
}

def extract_features(request_data):
    """Extract features from the incoming request data"""
    features = {}
    
    # Extract basic connection 
    features['packet_size'] = request_data.get('packet_size', 0)
    features['packet_rate'] = request_data.get('packet_rate', 0)
    features['protocol_type'] = request_data.get('protocol_type', 0)  # 0: TCP, 1: UDP, 2: ICMP
    features['duration'] = request_data.get('duration', 0)
    features['src_bytes'] = request_data.get('src_bytes', 0)
    features['dst_bytes'] = request_data.get('dst_bytes', 0)
    
    # Extract content 
    features['wrong_fragment'] = request_data.get('wrong_fragment', 0)
    features['urgent'] = request_data.get('urgent', 0)
    features['hot'] = request_data.get('hot', 0)
    features['num_failed_logins'] = request_data.get('num_failed_logins', 0)
    features['logged_in'] = request_data.get('logged_in', 0)
    
    # Extract security related 
    features['num_compromised'] = request_data.get('num_compromised', 0)
    features['root_shell'] = request_data.get('root_shell', 0)
    features['su_attempted'] = request_data.get('su_attempted', 0)
    features['num_root'] = request_data.get('num_root', 0)
    features['num_file_creations'] = request_data.get('num_file_creations', 0)
    features['num_shells'] = request_data.get('num_shells', 0)
    features['num_access_files'] = request_data.get('num_access_files', 0)
    features['num_outbound_cmds'] = request_data.get('num_outbound_cmds', 0)
    features['is_host_login'] = request_data.get('is_host_login', 0)
    features['is_guest_login'] = request_data.get('is_guest_login', 0)
    
    # Extract traffic 
    features['count'] = request_data.get('count', 0)
    features['srv_count'] = request_data.get('srv_count', 0)
    features['serror_rate'] = request_data.get('serror_rate', 0)
    features['srv_serror_rate'] = request_data.get('srv_serror_rate', 0)
    features['rerror_rate'] = request_data.get('rerror_rate', 0)
    features['srv_rerror_rate'] = request_data.get('srv_rerror_rate', 0)
    features['same_srv_rate'] = request_data.get('same_srv_rate', 0)
    features['diff_srv_rate'] = request_data.get('diff_srv_rate', 0)
    features['srv_diff_host_rate'] = request_data.get('srv_diff_host_rate', 0)
    
    # Extract destination host 
    features['dst_host_count'] = request_data.get('dst_host_count', 0)
    features['dst_host_srv_count'] = request_data.get('dst_host_srv_count', 0)
    features['dst_host_same_srv_rate'] = request_data.get('dst_host_same_srv_rate', 0)
    features['dst_host_diff_srv_rate'] = request_data.get('dst_host_diff_srv_rate', 0)
    features['dst_host_same_src_port_rate'] = request_data.get('dst_host_same_src_port_rate', 0)
    features['dst_host_srv_diff_host_rate'] = request_data.get('dst_host_srv_diff_host_rate', 0)
    features['dst_host_serror_rate'] = request_data.get('dst_host_serror_rate', 0)
    features['dst_host_srv_serror_rate'] = request_data.get('dst_host_srv_serror_rate', 0)
    features['dst_host_rerror_rate'] = request_data.get('dst_host_rerror_rate', 0)
    features['dst_host_srv_rerror_rate'] = request_data.get('dst_host_srv_rerror_rate', 0)
    

    feature_array = np.array([features[feature] for feature in FEATURE_NAMES]).reshape(1, -1)
    
    return feature_array

@app.route('/check', methods=['POST'])
def check_request():
    """Endpoint to check if a request is malicious"""
    try:

        request_data = request.get_json()
        features = extract_features(request_data)

        scaled_features = scaler.transform(features)

        prediction = model.predict(scaled_features)[0]
        proba = model.predict_proba(scaled_features)[0]
        

        attack_type = ATTACK_LABELS.get(prediction, "Unknown")
        
        client_ip = request.remote_addr
        logging.info(f"Request from {client_ip} - Prediction: {attack_type} - Probabilities: {proba}")
        
        response = {
            'status': 'success',
            'prediction': int(prediction),
            'attack_type': attack_type,
            'probabilities': {ATTACK_LABELS[i]: float(prob) for i, prob in enumerate(proba)},
            'is_malicious': bool(prediction != 0)  # 0 is normal
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    print("Starting Eboli AI Security Proxy...")
    serve(app, host='0.0.0.0', port=5000)
