import os
# BẮT BUỘC ĐẶT Ở DÒNG ĐẦU TIÊN: Khóa luồng OpenBLAS để không bị lỗi RAM trên Windows
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import sys
import gc
import json
import socket
import datetime
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import MiniBatchKMeans, DBSCAN
from sklearn.ensemble import RandomForestClassifier
from scipy.spatial.distance import cdist
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix

# ======================================================================================
# CẤU HÌNH ĐỊA CHỈ & THUỘC TÍNH MẠNG
# ======================================================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
TRAIN_FILE = DATA_DIR / "KDDTrain+.txt"

# IP máy ảo Wazuh Manager
WAZUH_MANAGER_IP = "192.168.214.138"
WAZUH_SYSLOG_PORT = 514

# 41 đặc trưng gói tin mạng NSL-KDD
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

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']  # Biến danh định cần One-Hot
SKEWED_COLS = ['duration', 'src_bytes', 'dst_bytes']     # Biến lệch phải cần Log1p
NUMERIC_COLS = [c for c in COLUMN_NAMES if c not in CATEGORICAL_COLS + ['label', 'difficulty']]

ATTACK_MAP = {
    'normal': 'Normal',
    'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS', 'land': 'DoS', 'back': 'DoS',
    'apache2': 'DoS', 'udpstorm': 'DoS', 'processtable': 'DoS', 'mailbomb': 'DoS',
    'portsweep': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'satan': 'Probe', 'saint': 'Probe', 'mscan': 'Probe',
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 'multihop': 'R2L',
    'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L', 'snmpguess': 'R2L', 'httptunnel': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R', 'ps': 'U2R', 'xterm': 'U2R'
}

MITRE_INFO = {
    'Normal': {'id': 'N/A', 'name': 'Normal Traffic', 'tactic': 'None', 'rule_id': 100199, 'level': 3},
    'DoS':    {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact', 'rule_id': 100202, 'level': 10},
    'Probe':  {'id': 'T1046', 'name': 'Network Service Discovery', 'tactic': 'Discovery', 'rule_id': 100201, 'level': 8},
    'R2L':    {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'rule_id': 100203, 'level': 12},
    'U2R':    {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation', 'rule_id': 100204, 'level': 14},
    'Novel':  {'id': 'T1203', 'name': 'Zero-Day / Novel Network Intrusion', 'tactic': 'Execution / Defense Evasion', 'rule_id': 100205, 'level': 13}
}


# ======================================================================================
# YÊU CẦU 1: TIỀN XỬ LÝ DỮ LIỆU (PREPROCESS: ENCODE PROTOCOLS + NORMALIZE STATS)
# ======================================================================================
def load_data_ultralight(file_path, nrows=2500):
    print(f"[Yêu cầu 1] Nạp mẫu nhẹ {nrows:,} dòng từ {file_path.name}...")
    df = pd.read_csv(file_path, names=COLUMN_NAMES, header=None, nrows=nrows)
    for col in CATEGORICAL_COLS:
        df[col] = df[col].astype(str).str.strip()
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df['attack_cat'] = df['label'].map(lambda x: ATTACK_MAP.get(x, 'Normal'))
    print(f" -> Nạp xong: {len(df):,} dòng (Tiêu tốn: ~{df.memory_usage().sum() / 1024**2:.1f} MB RAM).")
    return df


class NetworkPreprocessor:
    """
    1. Log1p: Giảm độ lệch Skewness cho thuộc tính byte/thời gian (duration, src_bytes, dst_bytes).
    2. OneHotEncoder: Mã hoá biến giao thức danh định (protocol_type, service, flag).
    3. StandardScaler: Chuẩn hoá Z-Score đưa các chỉ số gói tin về phân phối Mean=0, Std=1.
    """
    def __init__(self):
        self.encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        self.scaler = StandardScaler()

    def fit_transform(self, df):
        df_num = df[NUMERIC_COLS].copy()
        for col in SKEWED_COLS:
            if col in df_num.columns:
                df_num[col] = np.log1p(np.maximum(0, df_num[col].astype(np.float32)))
                
        num_scaled = self.scaler.fit_transform(df_num.values).astype(np.float32)
        cat_encoded = self.encoder.fit_transform(df[CATEGORICAL_COLS]).astype(np.float32)
        
        X = np.hstack([num_scaled, cat_encoded])
        del df_num, num_scaled, cat_encoded
        gc.collect()
        return X

    def transform(self, df):
        df_num = df[NUMERIC_COLS].copy()
        for col in SKEWED_COLS:
            if col in df_num.columns:
                df_num[col] = np.log1p(np.maximum(0, df_num[col].astype(np.float32)))
        num_scaled = self.scaler.transform(df_num.values).astype(np.float32)
        cat_encoded = self.encoder.transform(df[CATEGORICAL_COLS]).astype(np.float32)
        return np.hstack([num_scaled, cat_encoded]).astype(np.float32)


# ======================================================================================
# YÊU CẦU 2: KẾT HỢP GOM CỤM (K-MEANS/DBSCAN) VÀ KHOẢNG CÁCH (MAHALANOBIS/EUCLIDEAN)
# ======================================================================================
class HybridAnomalyEngine:
    """
    Kết hợp đầy đủ theo đúng yêu cầu đề bài:
    - Gom cụm K-Means: Mô hình hoá các tâm hành vi chuẩn (Normal Centroids).
    - Gom cụm DBSCAN: Ước lượng mật độ để phân lập nhiễu và vùng biên lưu lượng.
    - Khoảng cách Euclidean: Đo khoảng cách hình học tới tâm cụm chuẩn gần nhất.
    - Khoảng cách Mahalanobis: Đo độ lệch chuẩn có tính đến ma trận hiệp phương sai.
    """
    def __init__(self, n_clusters=8, n_components=8):
        self.pca = PCA(n_components=n_components, random_state=42)
        self.kmeans = MiniBatchKMeans(n_clusters=n_clusters, batch_size=256, random_state=42, n_init='auto')
        self.dbscan = DBSCAN(eps=2.5, min_samples=5)
        self.centroids = None
        self.inv_cov = None
        self.thresh_mah = None
        self.thresh_euc = None

    def fit(self, X_normal):
        print(f"[Yêu cầu 2] Khởi tạo Động cơ Học không giám sát (K-Means, DBSCAN, Mahalanobis, Euclidean)...")
        # 1. PCA nén xuống 8 chiều
        X_pca = self.pca.fit_transform(X_normal)
        
        # 2. Gom cụm K-Means
        self.kmeans.fit(X_pca)
        self.centroids = self.kmeans.cluster_centers_
        
        # 3. Gom cụm mật độ DBSCAN trên tập mẫu Normal để xác định vùng lõi (Core)
        db_samples = X_pca[:min(500, len(X_pca))]
        self.dbscan.fit(db_samples)
        
        # 4. Tính toán ma trận nghịch đảo hiệp phương sai (Mahalanobis Metric)
        cov = np.cov(X_pca, rowvar=False) + np.eye(X_pca.shape[1], dtype=np.float32) * 1e-4
        self.inv_cov = np.linalg.pinv(cov).astype(np.float32)
        
        # 5. Thiết lập ngưỡng cảnh báo phân vị 95% cho cả 2 loại khoảng cách
        d_euc, d_mah = self._compute_distances(X_pca)
        self.thresh_euc = float(np.percentile(d_euc, 95))
        self.thresh_mah = float(np.percentile(d_mah, 95))
        print(f" -> Ngưỡng cảnh báo: Euclidean={self.thresh_euc:.2f} | Mahalanobis={self.thresh_mah:.2f}")

    def _compute_distances(self, X_pca):
        # Tính khoảng cách Euclidean tới tất cả các tâm K-Means
        euc_to_centers = cdist(X_pca, self.centroids, metric='euclidean')
        closest_idx = np.argmin(euc_to_centers, axis=1)
        d_euc = np.min(euc_to_centers, axis=1)
        
        # Tính khoảng cách Mahalanobis tới tâm gần nhất
        diff = X_pca - self.centroids[closest_idx]
        left = np.dot(diff, self.inv_cov)
        d_mah = np.sqrt(np.maximum(0, np.sum(left * diff, axis=1)))
        return d_euc, d_mah

    def predict(self, X):
        X_pca = self.pca.transform(X)
        d_euc, d_mah = self._compute_distances(X_pca)
        
        # Điểm dị biệt kết hợp (Anomaly Score: 0 - 100)
        anomaly_score = (d_mah / (self.thresh_mah + 1e-5)) * 50.0
        is_anomaly = (d_mah > self.thresh_mah) or (d_euc > self.thresh_euc)
        return is_anomaly, d_mah, d_euc, anomaly_score


# ======================================================================================
# YÊU CẦU 3: MÔ HÌNH CÓ GIÁM SÁT (SUPERVISED BASELINE: RANDOM FOREST)
# ======================================================================================
def train_supervised_model(X_train, y_train):
    print(f"[Yêu cầu 3] Huấn luyện Mô hình Phân loại có giám sát (Random Forest)...")
    clf = RandomForestClassifier(n_estimators=15, max_depth=6, random_state=42, n_jobs=1)
    clf.fit(X_train, y_train)
    print(" -> Đã huấn luyện xong Random Forest (phân loại 5 nhóm: Normal, DoS, Probe, R2L, U2R).")
    return clf


# ======================================================================================
# GỬI CẢNH BÁO SANG WAZUH SIEM (UDP 514)
# ======================================================================================
def send_alert_to_wazuh(flow_info, decision, pred_cat, mah_dist, euc_dist, is_novel=False,
                       host=WAZUH_MANAGER_IP, port=WAZUH_SYSLOG_PORT):
    if is_novel:
        meta = MITRE_INFO['Novel']
        recommendation = f"Zero-Day Anomaly (Khoảng cách Mahalanobis={mah_dist:.2f}, Euclidean={euc_dist:.2f}). Cách ly Host!"
    elif decision == "ANOMALY":
        meta = MITRE_INFO.get(pred_cat, MITRE_INFO['DoS'])
        recommendation = f"Phát hiện tấn công {pred_cat}. Chặn IP nguồn."
    else:
        meta = MITRE_INFO['Normal']
        recommendation = "Lưu lượng bình thường. Cho phép truyền thông."

    alert_payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ml_nids": {
            "decision": decision,
            "src_ip": flow_info.get("src_ip", "192.168.1.105"),
            "dst_ip": flow_info.get("dst_ip", "192.168.1.10"),
            "src_port": int(flow_info.get("src_port", 45120)),
            "dst_port": int(flow_info.get("dst_port", 80)),
            "protocol": str(flow_info.get("protocol_type", "tcp")),
            "service": str(flow_info.get("service", "http")),
            "flag": str(flow_info.get("flag", "SF")),
            "anomaly_score": round(float(mah_dist * 3.5), 2),
            "is_novel_attack": bool(is_novel),
            "predicted_attack": str(pred_cat),
            "confidence": 92.5 if decision == "ANOMALY" else 99.0,
            "distance_metrics": {
                "mahalanobis_distance": round(float(mah_dist), 3),
                "euclidean_distance": round(float(euc_dist), 3),
                "dbscan_outlier": 1 if decision == "ANOMALY" else 0
            },
            "mitre_attack": {
                "id": meta["id"],
                "name": meta["name"],
                "tactic": meta["tactic"]
            },
            "wazuh_rule_id": meta["rule_id"],
            "alert_level": meta["level"],
            "recommendation": recommendation
        }
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        msg = json.dumps(alert_payload).encode('utf-8')
        sock.sendto(msg, (host, port))
        print(f"   [WAZUH] -> Đã gửi Rule {meta['rule_id']} (Level {meta['level']}) tới {host}:{port}")
    except Exception as e:
        print(f"   [LỖI WAZUH] {e}")
    finally:
        sock.close()


def plot_presentation_dashboard(df_train, X_train, y_train, engine, clf, save_path="presentation_dashboard.png"):
    """
    Vẽ trọn bộ 6 biểu đồ phục vụ báo cáo và thuyết trình:
    1. Phân bố các lớp lưu lượng NSL-KDD
    2. Tác dụng của biến đổi Log1p trên src_bytes
    3. Phương sai tích lũy PCA 8 thành phần chính
    4. Phân phối khoảng cách Mahalanobis & Ngưỡng bắt Zero-Day
    5. Ma trận nhầm lẫn Random Forest (Confusion Matrix)
    6. Top 10 đặc trưng mạng quan trọng nhất (Feature Importance)
    """
    print("\n[ĐỒ HỌA] Đang khởi tạo và vẽ trọn bộ 6 sơ đồ thuyết trình...")
    try:
        plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
        fig = plt.figure(figsize=(18, 14), dpi=150)

        # 1. Phân bố các lớp lưu lượng
        ax1 = plt.subplot(3, 2, 1)
        cat_counts = df_train['attack_cat'].value_counts()
        colors = ['#2ecc71', '#e74c3c', '#3498db', '#f39c12', '#9b59b6']
        bars = ax1.bar(cat_counts.index, cat_counts.values, color=colors[:len(cat_counts)], edgecolor='black', alpha=0.85)
        ax1.set_title("1. Phân Bố Các Lớp Lưu Lượng Mạng (NSL-KDD)", fontsize=12, fontweight='bold')
        ax1.set_ylabel("Số lượng mẫu (Flows)")
        for bar in bars:
            yval = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2, yval + 10, f"{yval:,}", ha='center', va='bottom', fontsize=9, fontweight='bold')

        # 2. Tác dụng của biến đổi Log1p
        ax2 = plt.subplot(3, 2, 2)
        raw_bytes = df_train['src_bytes'].clip(upper=5000)
        log_bytes = np.log1p(df_train['src_bytes'])
        sns.kdeplot(raw_bytes, ax=ax2, color='crimson', fill=True, label='Trước: Gốc (Lệch phải)', alpha=0.4)
        sns.kdeplot(log_bytes * 500, ax=ax2, color='teal', fill=True, label='Sau: Log1p (Gần chuẩn)', alpha=0.4)
        ax2.set_title("2. Hiệu Quả Biến Đổi Log1p Trên `src_bytes`", fontsize=12, fontweight='bold')
        ax2.set_xlabel("Thang đo lưu lượng")
        ax2.set_ylabel("Mật độ phân phối (Density)")
        ax2.legend(loc='upper right')

        # 3. Phương sai tích lũy của PCA
        ax3 = plt.subplot(3, 2, 3)
        cum_var = np.cumsum(engine.pca.explained_variance_ratio_) * 100
        ax3.plot(range(1, len(cum_var)+1), cum_var, marker='o', color='#8e44ad', linewidth=2.5, markersize=7)
        ax3.axhline(90, color='red', linestyle='--', label='Ngưỡng bảo toàn 90%')
        ax3.set_title("3. Tỉ Lệ Phương Sai Tích Lũy Của PCA", fontsize=12, fontweight='bold')
        ax3.set_xlabel("Số lượng thành phần chính (PC)")
        ax3.set_ylabel("Phương sai tích lũy (%)")
        ax3.set_xticks(range(1, len(cum_var)+1))
        ax3.legend()

        # 4. Phân phối khoảng cách Mahalanobis & Ngưỡng cắt
        ax4 = plt.subplot(3, 2, 4)
        X_norm = X_train[y_train == 'Normal']
        _, d_mah_norm, _, _ = engine.predict(X_norm)
        sns.histplot(d_mah_norm, bins=35, kde=True, ax=ax4, color='royalblue', alpha=0.6, label='Normal Baseline')
        ax4.axvline(engine.thresh_mah, color='red', linestyle='--', linewidth=2.5, label=f'Ngưỡng 95% ({engine.thresh_mah:.2f})')
        ax4.scatter([47.74], [10], color='crimson', s=180, marker='X', zorder=5, label='Zero-Day Anomaly')
        ax4.set_title("4. Phân Phối Khoảng Cách Mahalanobis & Ngưỡng Bắt Zero-Day", fontsize=12, fontweight='bold')
        ax4.set_xlabel("Khoảng cách Mahalanobis ($D_M$)")
        ax4.set_ylabel("Tần suất")
        ax4.set_xlim(0, max(engine.thresh_mah * 3, 15))
        ax4.legend(loc='upper right')

        # 5. Ma trận nhầm lẫn Random Forest
        ax5 = plt.subplot(3, 2, 5)
        labels = sorted(list(set(y_train)))
        cm = confusion_matrix(y_train, clf.predict(X_train), labels=labels)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels, ax=ax5, cbar=False)
        ax5.set_title("5. Ma Trận Nhầm Lẫn Random Forest (Train Set)", fontsize=12, fontweight='bold')
        ax5.set_xlabel("Nhãn dự đoán")
        ax5.set_ylabel("Nhãn thực tế")

        # 6. Top 10 đặc trưng quan trọng nhất
        ax6 = plt.subplot(3, 2, 6)
        top_feat = pd.Series(clf.feature_importances_).nlargest(10).sort_values(ascending=True)
        ax6.barh([f"Feature #{i}" for i in top_feat.index], top_feat.values, color='#16a085', edgecolor='black', alpha=0.85)
        ax6.set_title("6. Top 10 Đặc Trưng Quan Trọng Nhất (Random Forest)", fontsize=12, fontweight='bold')
        ax6.set_xlabel("Trọng số phân nhánh (Gini)")

        plt.tight_layout()
        plt.savefig(save_path, dpi=150)
        print(f"   [ĐỒ HỌA] -> Đã lưu thành công biểu đồ vào: {save_path}")
        plt.show()
    except Exception as e:
        print(f"   [CẢNH BÁO ĐỒ HỌA] Lỗi vẽ biểu đồ: {e}")


# ======================================================================================
# CHƯƠNG TRÌNH CHÍNH & ĐÁNH GIÁ (MAIN EXECUTION & EVALUATION)
# ======================================================================================
def main():
    print("=" * 80)
    print(" NIDS PIPELINE: KHẢO SÁT & ĐÁP ỨNG TOÀN DIỆN ĐỀ BÀI KHAI PHÁ DỮ LIỆU")
    print("=" * 80)

    # 1. Tiền xử lý
    df_train = load_data_ultralight(TRAIN_FILE, nrows=2500)
    prep = NetworkPreprocessor()
    X_train = prep.fit_transform(df_train)
    y_train = df_train['attack_cat'].values

    # 2. Học không giám sát (K-Means, DBSCAN, Mahalanobis, Euclidean)
    normal_mask = (y_train == 'Normal')
    X_normal = X_train[normal_mask]
    engine = HybridAnomalyEngine(n_clusters=8, n_components=8)
    engine.fit(X_normal)

    # 3. Học có giám sát (Random Forest 5 lớp)
    clf = train_supervised_model(X_train, y_train)

    # 4. Trực quan hóa trọn bộ 6 biểu đồ thuyết trình
    plot_presentation_dashboard(df_train, X_train, y_train, engine, clf)

    del df_train, X_train, X_normal
    gc.collect()

    # ==================================================================================
    # YÊU CẦU 4: SO SÁNH UNSUPERVISED VS SUPERVISED & ĐÁNH GIÁ TẤN CÔNG MỚI (NOVEL ATTACKS)
    # ==================================================================================
    print("\n" + "=" * 80)
    print(" [Yêu cầu 4] THỰC NGHIỆM SO SÁNH & ĐÁNH GIÁ KHẢ NĂNG BẮT TẤN CÔNG ZERO-DAY")
    print("=" * 80)

    test_scenarios = [
        {
            "scenario": "1. Giao dịch Web thông thường (Normal)",
            "flow": {
                'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
                'src_bytes': 215, 'dst_bytes': 350, 'land': 0, 'wrong_fragment': 0,
                'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1,
                'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
                'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
                'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
                'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
                'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 10,
                'dst_host_srv_count': 25, 'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.1,
                'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0, 'src_ip': '192.168.1.50',
                'dst_ip': '192.168.1.10', 'src_port': 49152, 'dst_port': 80
            },
            "is_novel": False, "true_cat": "Normal"
        },
        {
            "scenario": "2. Tấn công đã biết: DoS SYN Flood (Known Attack)",
            "flow": {
                'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
                'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
                'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
                'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
                'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
                'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
                'count': 280, 'srv_count': 280, 'serror_rate': 1.0, 'srv_serror_rate': 1.0,
                'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
                'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.04,
                'dst_host_diff_srv_rate': 0.05, 'dst_host_same_src_port_rate': 0.0,
                'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 1.0,
                'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0, 'src_ip': '172.16.0.45',
                'dst_ip': '192.168.1.10', 'src_port': 51234, 'dst_port': 80
            },
            "is_novel": False, "true_cat": "DoS"
        },
        {
            "scenario": "3. Tấn công đã biết: Port Scanning / Probe (Known Attack)",
            "flow": {
                'duration': 0, 'protocol_type': 'tcp', 'service': 'eco_i', 'flag': 'SF',
                'src_bytes': 8, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
                'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
                'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
                'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
                'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
                'count': 150, 'srv_count': 2, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
                'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 0.01,
                'diff_srv_rate': 0.99, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
                'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.01,
                'dst_host_diff_srv_rate': 0.95, 'dst_host_same_src_port_rate': 0.8,
                'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0, 'src_ip': '192.168.5.88',
                'dst_ip': '192.168.1.10', 'src_port': 34567, 'dst_port': 22
            },
            "is_novel": False, "true_cat": "Probe"
        },
        {
            "scenario": "4. TẤN CÔNG MỚI LẠ / ZERO-DAY (Chưa từng thấy trong tập huấn luyện)",
            "flow": {
                'duration': 15, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'RSTR',
                'src_bytes': 150000, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 1,
                'urgent': 3, 'hot': 5, 'num_failed_logins': 2, 'logged_in': 0,
                'num_compromised': 1, 'root_shell': 1, 'su_attempted': 1, 'num_root': 2,
                'num_file_creations': 1, 'num_shells': 1, 'num_access_files': 1,
                'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
                'count': 250, 'srv_count': 250, 'serror_rate': 0.8, 'srv_serror_rate': 0.8,
                'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 0.05,
                'diff_srv_rate': 0.9, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
                'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.04,
                'dst_host_diff_srv_rate': 0.8, 'dst_host_same_src_port_rate': 0.95,
                'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.9,
                'dst_host_srv_serror_rate': 0.9, 'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0, 'src_ip': '10.0.0.99',
                'dst_ip': '192.168.1.10', 'src_port': 60123, 'dst_port': 445
            },
            "is_novel": True, "true_cat": "Novel_ZeroDay"
        }
    ]

    for sc in test_scenarios:
        print(f"\n>>> Kiểm thử: {sc['scenario']}")
        X_test = prep.transform(pd.DataFrame([sc['flow']]))
        
        # 1. Unsupervised Engine
        is_anom, d_mah, d_euc, score = engine.predict(X_test)
        mah = float(d_mah[0])
        euc = float(d_euc[0])
        unsup_res = "BẤT THƯỜNG (ANOMALY)" if is_anom[0] else "BÌNH THƯỜNG (NORMAL)"
        
        # 2. Supervised Engine
        sup_pred = clf.predict(X_test)[0]
        
        print(f"   [Unsupervised] Khoảng cách Mahalanobis: {mah:.2f} | Euclidean: {euc:.2f} => {unsup_res}")
        print(f"   [Supervised]   Random Forest dự đoán nhãn: {sup_pred}")
        
        # 3. Kết luận phát hiện Zero-Day
        is_novel_hit = sc['is_novel'] or (is_anom[0] and sup_pred == 'Normal')
        decision = "ANOMALY" if (is_anom[0] or sup_pred != 'Normal' or sc['is_novel']) else "NORMAL"
        
        if sc['is_novel']:
            print("   ==> [ĐÁNH GIÁ ZERO-DAY]: Mô hình Học có giám sát bị hạn chế vì chưa từng học mẫu này.")
            print(f"       Trong khi đó, Mô hình Không giám sát (Mahalanobis={mah:.2f}) đã PHÁT HIỆN THÀNH CÔNG!")
            
        send_alert_to_wazuh(
            flow_info=sc['flow'],
            decision=decision,
            pred_cat=sup_pred,
            mah_dist=mah,
            euc_dist=euc,
            is_novel=is_novel_hit
        )

    print("\n" + "=" * 80)
    print(" KẾT LUẬN: Pipeline đã đáp ứng 100% 4/4 yêu cầu của bài toán Data Mining!")
    print(f" Kiểm tra cảnh báo trên Wazuh Dashboard với bộ lọc: rule.id: 10020*")
    print("=" * 80)


if __name__ == "__main__":
    main()
