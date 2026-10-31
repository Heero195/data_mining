import time
import argparse
from pathlib import Path
import pandas as pd

from src.config import TEST_DATA_PATH, OUTPUT_DIR
from src.preprocess import NetworkDataPreprocessor
from src.wazuh_integration.wazuh_detector import WazuhMLDetector


def run_traffic_replay(output_file=None, wazuh_host=None, wazuh_port=514, count=15, delay=0.5):
    """
    Replays sample network traffic connections (Normal, Known Attack, Novel Attack)
    through the ML Detector and streams alerts to Wazuh.
    """
    if output_file is None:
        output_file = OUTPUT_DIR / "wazuh_alerts.json"
        
    print(f"\n==================================================================")
    print(f"       WAZUH HOMELAB ML-NIDS TRAFFIC REPLAY & ALERT ENGINE        ")
    print(f"==================================================================")
    print(f"Alert output file: {output_file}")
    if wazuh_host:
        print(f"Streaming syslog directly to Wazuh Manager: {wazuh_host}:{wazuh_port}")
    print(f"Replaying {count} simulated connections...\n")
    
    detector = WazuhMLDetector()
    prep = detector.prep
    df_test = prep.load_dataset(TEST_DATA_PATH)
    
    # Select a diverse mixture of connections:
    # 1. Normal traffic
    samples_normal = df_test[df_test['is_attack'] == 0].sample(n=min(5, count), random_state=42)
    # 2. Known attacks (e.g. neptune, satan, guess_passwd)
    samples_known = df_test[(df_test['is_attack'] == 1) & (df_test['is_novel'] == 0)].sample(n=min(5, count), random_state=42)
    # 3. Novel attacks (unseen attack types e.g. mscan, processtable, snmpguess)
    samples_novel = df_test[df_test['is_novel'] == 1].sample(n=min(5, count), random_state=42)
    
    replay_df = pd.concat([samples_normal, samples_known, samples_novel]).sample(frac=1.0, random_state=123).reset_index(drop=True)
    
    # Homelab IP pool
    ip_attackers = ["192.168.1.188", "192.168.1.192", "10.0.0.45", "172.16.20.15"]
    ip_victims = ["192.168.1.10", "192.168.1.20", "192.168.1.50"]
    
    total_processed = 0
    anomalies_detected = 0
    novel_detected = 0
    
    for idx, row in replay_df.iterrows():
        flow_dict = row.to_dict()
        src_ip = ip_attackers[idx % len(ip_attackers)] if row['is_attack'] == 1 else "192.168.1.105"
        dst_ip = ip_victims[idx % len(ip_victims)]
        src_port = 40000 + (idx * 37) % 20000
        dst_port = 80 if row['service'] == 'http' else (53 if row['service'] == 'domain_u' else 22)
        
        # Inspect flow with ML engine
        alert = detector.inspect_flow(flow_dict, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port)
        ev = alert['ml_nids']
        
        # Write alert to JSON file for Wazuh Agent
        detector.write_alert_to_file(alert, output_file)
        
        # Optionally send to Wazuh Syslog
        if wazuh_host:
            try:
                detector.send_syslog_to_wazuh(alert, host=wazuh_host, port=wazuh_port)
            except Exception as e:
                print(f"[Warning] Failed to send syslog to Wazuh: {e}")
                
        total_processed += 1
        is_novel = ev['is_novel_attack']
        is_anom = ev['decision'] == 'ANOMALY'
        
        if is_anom:
            anomalies_detected += 1
        if is_novel:
            novel_detected += 1
            
        # Display formatted log
        status_tag = f"[LEVEL {ev['alert_level']:02d}]"
        if is_novel:
            label_tag = "[CRITICAL ZERO-DAY]"
        elif is_anom:
            label_tag = f"[KNOWN ATTACK: {ev['predicted_attack']}]"
        else:
            label_tag = "[NORMAL TRAFFIC]"
            
        print(f"[{total_processed:02d}] {status_tag} {label_tag} | Flow: {ev['src_ip']}:{ev['src_port']} -> {ev['dst_ip']}:{ev['dst_port']} ({ev['protocol'].upper()}/{ev['service']})")
        print(f"     Score: {ev['anomaly_score']:.1f}/100 | Mahalanobis: {ev['distance_metrics']['mahalanobis_distance']:.2f} | Euclidean: {ev['distance_metrics']['euclidean_distance']:.2f} | Ground Truth: {row['label']}")
        if is_anom:
            print(f"     MITRE: {ev['mitre_attack']['id']} - {ev['mitre_attack']['name']} | Action: {ev['recommendation']}")
        print("-" * 75)
        
        if delay > 0:
            time.sleep(delay)
            
    print(f"\nReplay Complete:")
    print(f"  Total connections processed: {total_processed}")
    print(f"  Anomalies identified:        {anomalies_detected} / {total_processed}")
    print(f"  Novel attacks isolated:      {novel_detected}")
    print(f"  Wazuh alert logs written to: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay network connections to Wazuh Homelab ML-NIDS.")
    parser.add_argument("--count", type=int, default=15, help="Number of connection samples to replay")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between connections in seconds")
    parser.add_argument("--wazuh-host", type=str, default=None, help="Wazuh Manager IP address for syslog")
    parser.add_argument("--wazuh-port", type=int, default=514, help="Wazuh Manager Syslog UDP port")
    parser.add_argument("--output-file", type=str, default=None, help="Custom output path for alerts.json")
    
    args = parser.parse_args()
    run_traffic_replay(
        output_file=args.output_file,
        wazuh_host=args.wazuh_host,
        wazuh_port=args.wazuh_port,
        count=args.count,
        delay=args.delay
    )
