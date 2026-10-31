import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
if not DATA_DIR.exists() or not (DATA_DIR / "KDDTrain+.txt").exists():
    DATA_DIR = Path(r"D:\data_miner\archive")
OUTPUT_DIR = BASE_DIR / "output"
MODELS_DIR = OUTPUT_DIR / "models"
PLOTS_DIR = OUTPUT_DIR / "plots"
REPORTS_DIR = OUTPUT_DIR / "reports"

# Ensure output directories exist
for p in [MODELS_DIR, PLOTS_DIR, REPORTS_DIR]:
    p.mkdir(parents=True, exist_ok=True)

# Dataset file paths
TRAIN_DATA_PATH = DATA_DIR / "KDDTrain+.txt"
TEST_DATA_PATH = DATA_DIR / "KDDTest+.txt"
TEST21_DATA_PATH = DATA_DIR / "KDDTest-21.txt"

# Column schema for NSL-KDD
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# Feature Types
CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
BINARY_FEATURES = ['land', 'logged_in', 'root_shell', 'su_attempted', 'is_host_login', 'is_guest_login']
CONTINUOUS_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'num_compromised', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'count', 'srv_count',
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]
SKEWED_FEATURES = ['duration', 'src_bytes', 'dst_bytes']

# Attack Category Mapping (5-Class)
# Standard NSL-KDD taxonomies: Normal, DoS, Probe, R2L, U2R
ATTACK_CATEGORIES = {
    'normal': 'Normal',
    
    # DoS (Denial of Service)
    'neptune': 'DoS',
    'smurf': 'DoS',
    'pod': 'DoS',
    'teardrop': 'DoS',
    'land': 'DoS',
    'back': 'DoS',
    'apache2': 'DoS',       # Novel in test
    'udpstorm': 'DoS',      # Novel in test
    'processtable': 'DoS',  # Novel in test
    'mailbomb': 'DoS',      # Novel in test
    
    # Probe (Surveillance and reconnaissance)
    'portsweep': 'Probe',
    'ipsweep': 'Probe',
    'nmap': 'Probe',
    'satan': 'Probe',
    'saint': 'Probe',       # Novel in test
    'mscan': 'Probe',       # Novel in test
    
    # R2L (Remote to Local / Unauthorized remote access)
    'guess_passwd': 'R2L',
    'ftp_write': 'R2L',
    'imap': 'R2L',
    'phf': 'R2L',
    'multihop': 'R2L',
    'warezmaster': 'R2L',
    'warezclient': 'R2L',
    'spy': 'R2L',
    'xlock': 'R2L',         # Novel in test
    'xsnoop': 'R2L',        # Novel in test
    'snmpguess': 'R2L',     # Novel in test
    'snmpgetattack': 'R2L', # Novel in test
    'httptunnel': 'R2L',    # Novel in test
    'sendmail': 'R2L',      # Novel in test
    'named': 'R2L',         # Novel in test
    'worm': 'R2L',          # Novel in test
    
    # U2R (User to Root / Privilege Escalation)
    'buffer_overflow': 'U2R',
    'loadmodule': 'U2R',
    'perl': 'U2R',
    'rootkit': 'U2R',
    'ps': 'U2R',            # Novel in test
    'xterm': 'U2R',         # Novel in test
    'sqlattack': 'U2R'      # Novel in test
}

# Attacks appearing ONLY in the test set (Novel / Zero-Day attacks)
NOVEL_ATTACKS = {
    'apache2', 'mailbomb', 'processtable', 'udpstorm',  # DoS novel
    'mscan', 'saint',                                    # Probe novel
    'httptunnel', 'named', 'sendmail', 'snmpgetattack', 
    'snmpguess', 'worm', 'xlock', 'xsnoop',              # R2L novel
    'ps', 'sqlattack', 'xterm'                           # U2R novel
}

# MITRE ATT&CK Mapping for Wazuh alerts
MITRE_ATTACK_MAPPING = {
    'Normal': {'id': 'N/A', 'name': 'Normal Traffic', 'tactic': 'None'},
    'DoS': {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    'Probe': {'id': 'T1046', 'name': 'Network Service Discovery', 'tactic': 'Discovery'},
    'R2L': {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
    'U2R': {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'}
}

# Wazuh Alert Rules Severity Levels
WAZUH_SEVERITY = {
    'Normal': 3,
    'Low_Anomaly': 5,
    'Probe': 7,
    'DoS': 10,
    'R2L': 12,
    'U2R': 14,
    'Novel_Anomaly': 13  # High alert for unknown / zero-day anomaly
}
