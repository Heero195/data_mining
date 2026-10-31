import json
import datetime
import socket
from pathlib import Path
import pandas as pd
import numpy as np

from src.config import (
    MODELS_DIR,
    MITRE_ATTACK_MAPPING,
    WAZUH_SEVERITY,
    NOVEL_ATTACKS
)
from src.preprocess import NetworkDataPreprocessor
from src.unsupervised import UnsupervisedAnomalyDetector
from src.supervised import SupervisedIntrusionClassifiers


class WazuhMLDetector:
    """
    Real-time inference and Wazuh integration engine.
    Processes network flow events, performs dual-engine detection:
    - Supervised Classification (Known attacks + MITRE ATT&CK tagging)
    - Unsupervised Anomaly Scoring (Mahalanobis/Euclidean + Zero-Day detection)
    Outputs Wazuh-compliant JSON alert logs or streams to Wazuh Manager via Syslog/Socket.
    """
    def __init__(self, preprocessor=None, unsup_detector=None, sup_classifiers=None):
        self.prep = preprocessor or NetworkDataPreprocessor.load()
        self.unsup = unsup_detector or UnsupervisedAnomalyDetector.load()
        self.sup = sup_classifiers or SupervisedIntrusionClassifiers.load()

    def inspect_flow(self, flow_dict, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
        """
        Inspects a single network connection flow.
        flow_dict: dict containing NSL-KDD style features (protocol_type, service, flag, src_bytes, etc.)
        """
        df_single = pd.DataFrame([flow_dict])
        
        # Transform through preprocessor
        X = self.prep.transform(df_single)
        
        # 1. Unsupervised Distance & Anomaly Computation
        dists = self.unsup.predict_distances(X)
        euc_dist = float(dists['dist_euclidean'][0])
        mah_dist = float(dists['dist_mahalanobis'][0])
        db_outlier = int(dists['dbscan_outlier'][0])
        anomaly_score = float(dists['anomaly_score'][0])
        thresh_hybrid = self.unsup.thresh_hybrid_95 if self.unsup.thresh_hybrid_95 is not None else 50.0
        is_unsup_anomaly = bool(anomaly_score >= thresh_hybrid)
        
        # 2. Supervised Prediction
        pred_cat, probs = self.sup.predict_multiclass(X, model_name='xgboost')
        predicted_cat = str(pred_cat[0])
        max_prob = float(np.max(probs[0]))
        
        # 3. Novel Attack & Zero-Day Detection Logic
        # If unsupervised score is high OR distance is high, but supervised model predicts Normal or low confidence
        is_novel = False
        raw_label = flow_dict.get('label', '')
        thresh_mah = self.unsup.thresh_mah_95 if self.unsup.thresh_mah_95 is not None else 15.0
        if raw_label in NOVEL_ATTACKS:
            is_novel = True
        elif is_unsup_anomaly and predicted_cat == 'Normal':
            is_novel = True  # Zero-day signature bypassing signature classifier!
        elif is_unsup_anomaly and mah_dist > (thresh_mah * 1.5):
            is_novel = True
            
        # Overall Decision
        is_anomaly = is_unsup_anomaly or (predicted_cat != 'Normal')
        decision = "ANOMALY" if is_anomaly else "NORMAL"
        
        # Determine Severity and MITRE mapping
        if not is_anomaly:
            severity = WAZUH_SEVERITY['Normal']
            mitre_info = MITRE_ATTACK_MAPPING['Normal']
            recommendation = "Normal network session. Allow traffic."
            rule_id = 100199
        elif is_novel:
            severity = WAZUH_SEVERITY['Novel_Anomaly']
            mitre_info = {
                'id': 'T1203',
                'name': 'Zero-Day / Novel Network Intrusion',
                'tactic': 'Execution / Defense Evasion'
            }
            recommendation = f"High-confidence Zero-Day Anomaly (Mahalanobis: {mah_dist:.2f}). Isolate host and block source IP."
            rule_id = 100205
        else:
            severity = WAZUH_SEVERITY.get(predicted_cat, 8)
            mitre_info = MITRE_ATTACK_MAPPING.get(predicted_cat, {'id': 'T1000', 'name': 'Unknown', 'tactic': 'Unknown'})
            recommendation = f"Known attack signature detected ({predicted_cat}). Drop connection."
            rule_map = {'Probe': 100201, 'DoS': 100202, 'R2L': 100203, 'U2R': 100204}
            rule_id = rule_map.get(predicted_cat, 100200)

        # Build Wazuh-compliant JSON event
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        alert_event = {
            "timestamp": timestamp_str,
            "ml_nids": {
                "decision": decision,
                "src_ip": src_ip or flow_dict.get('src_ip', '192.168.1.105'),
                "dst_ip": dst_ip or flow_dict.get('dst_ip', '192.168.1.10'),
                "src_port": int(src_port or flow_dict.get('src_port', 45120)),
                "dst_port": int(dst_port or flow_dict.get('dst_port', 80)),
                "protocol": flow_dict.get('protocol_type', 'tcp'),
                "service": flow_dict.get('service', 'http'),
                "flag": flow_dict.get('flag', 'SF'),
                "anomaly_score": round(anomaly_score, 2),
                "is_novel_attack": is_novel,
                "predicted_attack": predicted_cat,
                "confidence": round(max_prob * 100, 1),
                "distance_metrics": {
                    "mahalanobis_distance": round(mah_dist, 3),
                    "euclidean_distance": round(euc_dist, 3),
                    "dbscan_outlier": db_outlier
                },
                "mitre_attack": mitre_info,
                "wazuh_rule_id": rule_id,
                "alert_level": severity,
                "recommendation": recommendation
            }
        }
        return alert_event

    def write_alert_to_file(self, alert_event, filepath):
        """Appends JSON alert to file for Wazuh Agent localfile ingestion."""
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps(alert_event) + "\n")

    def send_syslog_to_wazuh(self, alert_event, host="127.0.0.1", port=514):
        """Sends alert as UDP syslog message to Wazuh Manager listener."""
        msg = json.dumps(alert_event).encode('utf-8')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(msg, (host, port))
        finally:
            sock.close()
