import os
import sys
import io

# Đảm bảo stdout hỗ trợ UTF-8 trên Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set aesthetics
sns.set_theme(style="whitegrid", palette="muted")
plt.rcParams.update({'font.sans-serif': 'DejaVu Sans', 'font.size': 11})

# 1. PATHS
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
if not DATA_DIR.exists() or not (DATA_DIR / "KDDTrain+.txt").exists():
    DATA_DIR = Path(r"D:\data_miner\archive")
TRAIN_DATA_PATH = DATA_DIR / "KDDTrain+.txt"
TEST_DATA_PATH = DATA_DIR / "KDDTest+.txt"
PLOTS_DIR = BASE_DIR / "output" / "plots"
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

# 2. SCHEMA: 41 FEATURES + 2 LABEL COLUMNS = 43 COLUMNS
COLUMN_NAMES = [
    # --- Nhóm 1: Đặc trưng kết nối cơ bản (Basic features) ---
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent',
    
    # --- Nhóm 2: Đặc trưng nội dung gói tin (Content features) ---
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    
    # --- Nhóm 3: Đặc trưng thống kê theo thời gian & máy chủ (Traffic/Host features) ---
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    
    # --- 2 Cột nhãn ---
    'attack_type', 'difficulty_level'
]

# 3. MAPPING 5 LỚP TẤN CÔNG LỚN
ATTACK_CATEGORIES = {
    'normal': 'Normal',
    
    # DoS (Denial of Service)
    'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS',
    'land': 'DoS', 'back': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS',
    
    # Probe (Surveillance / Reconnaissance)
    'portsweep': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe',
    'satan': 'Probe', 'saint': 'Probe', 'mscan': 'Probe',
    
    # R2L (Remote to Local)
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L',
    'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'worm': 'R2L',
    
    # U2R (User to Root)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R',
    'rootkit': 'U2R', 'ps': 'U2R', 'xterm': 'U2R', 'sqlattack': 'U2R'
}


def main():
    print("=" * 80)
    print("      GIAI ĐOẠN 1: KHẢO SÁT & KHÁM PHÁ DỮ LIỆU NSL-KDD (EDA)")
    print("=" * 80)
    
    # 1. ĐỌC DỮ LIỆU
    print(f"\n[1/6] Nạp dữ liệu từ thư mục: {DATA_DIR}")
    df_train = pd.read_csv(TRAIN_DATA_PATH, names=COLUMN_NAMES, header=None)
    df_test = pd.read_csv(TEST_DATA_PATH, names=COLUMN_NAMES, header=None)
    
    print(f"  -> Tập Huấn luyện (KDDTrain+): {df_train.shape[0]:,} dòng x {df_train.shape[1]} cột")
    print(f"  -> Tập Kiểm thử    (KDDTest+) : {df_test.shape[0]:,} dòng x {df_test.shape[1]} cột")
    
    # Kiểm tra Missing values
    null_train = df_train.isnull().sum().sum()
    null_test = df_test.isnull().sum().sum()
    print(f"  -> Giá trị bị thiếu (Missing values): Train={null_train}, Test={null_test} (Dữ liệu hoàn toàn sạch!)")
    
    # 2. XEM TRƯỚC DỮ LIỆU
    print("\n[2/6] Xem trước 3 dòng đầu tiên của tập Train:")
    cols_preview = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'attack_type', 'difficulty_level']
    print(df_train[cols_preview].head(3).to_string(index=False))
    
    # Chuẩn hóa nhãn text
    df_train['attack_type'] = df_train['attack_type'].astype(str).str.strip().str.lower()
    df_test['attack_type'] = df_test['attack_type'].astype(str).str.strip().str.lower()
    
    # Ánh xạ về 5 lớp lớn
    df_train['attack_cat'] = df_train['attack_type'].map(lambda x: ATTACK_CATEGORIES.get(str(x), 'Unknown'))
    df_test['attack_cat'] = df_test['attack_type'].map(lambda x: ATTACK_CATEGORIES.get(str(x), 'Unknown'))
    
    # 3. THỐNG KÊ 5 LỚP TẤN CÔNG LỚN
    print("\n[3/6] Phân bố 5 nhóm lưu lượng mạng lớn (Normal vs 4 nhóm tấn công):")
    train_dist = df_train['attack_cat'].value_counts()
    test_dist = df_test['attack_cat'].value_counts()
    
    summary_cat = pd.DataFrame({
        'Train Count': train_dist,
        'Train %': (train_dist / len(df_train) * 100).round(2),
        'Test Count': test_dist,
        'Test %': (test_dist / len(df_test) * 100).round(2)
    }).fillna(0)
    
    print(summary_cat.to_string())
    print("\n  >> NHẬN XÉT QUAN TRỌNG VỀ PHÂN PHỐI LỚP:")
    print("     - DoS chiếm tỷ lệ áp đảo trong các cuộc tấn công (~36%).")
    print("     - Hai nhóm R2L và U2R chiếm tỷ lệ CỰC NHỎ (< 1% trong tập Train).")
    print("     - Dữ liệu bị MẤT CÂN BẰNG NGHIÊM TRỌNG (Extreme Imbalance)!")
    
    # Vẽ biểu đồ phân bố 5 lớp
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    cats_order = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    
    sns.countplot(data=df_train, x='attack_cat', hue='attack_cat', order=cats_order, ax=axes[0], palette='Blues_r')
    if axes[0].get_legend() is not None:
        axes[0].get_legend().remove()
    axes[0].set_title("Phân bố 5 lớp trên Tập Train (KDDTrain+)", fontweight='bold')
    axes[0].set_xlabel("Lớp lưu lượng")
    axes[0].set_ylabel("Số lượng kết nối")
    for p in axes[0].patches:
        axes[0].annotate(f"{int(p.get_height()):,}", (p.get_x() + 0.15, p.get_height() + 500))
        
    sns.countplot(data=df_test, x='attack_cat', hue='attack_cat', order=cats_order, ax=axes[1], palette='Oranges_r')
    if axes[1].get_legend() is not None:
        axes[1].get_legend().remove()
    axes[1].set_title("Phân bố 5 lớp trên Tập Test (KDDTest+)", fontweight='bold')
    axes[1].set_xlabel("Lớp lưu lượng")
    axes[1].set_ylabel("Số lượng kết nối")
    for p in axes[1].patches:
        axes[1].annotate(f"{int(p.get_height()):,}", (p.get_x() + 0.15, p.get_height() + 200))
        
    plt.tight_layout()
    plot_dist_path = PLOTS_DIR / "eda_attack_distribution.png"
    plt.savefig(plot_dist_path, dpi=300)
    plt.close()
    print(f"  -> Đã lưu biểu đồ phân bố lớp vào: {plot_dist_path}")
    
    # 4. KHÁM PHÁ CÁC ĐÒN TẤN CÔNG MỚI (NOVEL ATTACKS / ZERO-DAY)
    print("\n[4/6] Khám phá các cuộc tấn công mới chỉ xuất hiện trong tập Test (Zero-Day Benchmark):")
    train_attacks = set(df_train['attack_type'].unique())
    test_attacks = set(df_test['attack_type'].unique())
    novel_attacks = test_attacks - train_attacks
    
    print(f"  -> Tổng số loại tấn công trong Train: {len(train_attacks) - 1} loại (+ 1 Normal)")
    print(f"  -> Tổng số loại tấn công trong Test:  {len(test_attacks) - 1} loại (+ 1 Normal)")
    print(f"  -> Số loại tấn công MỚI HOÀN TOÀN (Zero-Day) chỉ có trong Test: {len(novel_attacks)} loại!")
    
    novel_rows = []
    for att in sorted(list(novel_attacks)):
        cnt = (df_test['attack_type'] == att).sum()
        cat = ATTACK_CATEGORIES.get(att, 'Unknown')
        novel_rows.append({'Tên Tấn Công Mới': att, 'Thuộc Nhóm': cat, 'Số Lượng Mẫu Trong Test': cnt})
    
    df_novel = pd.DataFrame(novel_rows)
    print(df_novel.to_string(index=False))
    total_novel_samples = df_novel['Số Lượng Mẫu Trong Test'].sum()
    print(f"\n  -> Tổng cộng có {total_novel_samples:,} mẫu tấn công Zero-Day trong Test ({total_novel_samples/len(df_test):.2%})!")
    print("  >> KẾT LUẬN: Đây là lý do mô hình Supervised (Random Forest/XGBoost) sẽ bị sụt giảm recall,")
    print("     và mô hình Unsupervised (Mahalanobis Distance) sẽ phát huy tối đa sức mạnh!")
    
    # 5. KHẢO SÁT BIẾN LỆCH NẶNG (SKEWED CONTINUOUS FEATURES)
    print("\n[5/6] Khảo sát hiện tượng phân phối lệch nặng (Heavy-tailed Skewness):")
    skew_cols = ['duration', 'src_bytes', 'dst_bytes']
    desc = df_train[skew_cols].describe().round(1)
    print(desc.to_string())
    
    print("\n  >> Quan sát giá trị cực đại (Max):")
    for col in skew_cols:
        skew_val = df_train[col].skew()
        print(f"     - {col:<10}: Min={df_train[col].min()}, Median={df_train[col].median()}, Max={df_train[col].max():,}, Hệ số Skew={skew_val:.2f}")
    print("  >> KẾT LUẬN: Giá trị Max lên tới hàng tỷ byte, nếu không dùng Log1p biến đổi,")
    print("     các số lớn này sẽ phá hủy hoàn toàn trọng số mô hình Machine Learning!")
    
    # Vẽ biểu đồ Skewness trước và sau log1p
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    sns.kdeplot(df_train['src_bytes'], ax=axes[0], color='red', fill=True, clip=(0, 100000))
    axes[0].set_title("Phân phối src_bytes GỐC (Bị lệch cực nặng)", fontweight='bold')
    axes[0].set_xlabel("src_bytes (giới hạn 0 - 100,000)")
    
    src_bytes_log = np.log1p(df_train['src_bytes'])
    sns.kdeplot(src_bytes_log, ax=axes[1], color='green', fill=True)
    axes[1].set_title("Phân phối src_bytes SAU KHI DÙNG log(1 + x) (Gần phân phối chuẩn)", fontweight='bold')
    axes[1].set_xlabel("log(1 + src_bytes)")
    
    plt.tight_layout()
    plot_skew_path = PLOTS_DIR / "eda_skewness_log.png"
    plt.savefig(plot_skew_path, dpi=300)
    plt.close()
    print(f"  -> Đã lưu biểu đồ so sánh Log1p vào: {plot_skew_path}")
    
    # 6. KHẢO SÁT BIẾN PHÂN LOẠI & DỊCH VỤ MẠNG LẠ
    print("\n[6/6] Khảo sát các biến phân loại (Categorical Features):")
    for cat_col in ['protocol_type', 'flag']:
        print(f"  -> Cột '{cat_col}': {list(df_train[cat_col].unique())}")
        
    train_services = set(df_train['service'].unique())
    test_services = set(df_test['service'].unique())
    novel_services = test_services - train_services
    print(f"  -> Tổng số dịch vụ mạng (service) trong Train: {len(train_services)}")
    print(f"  -> Tổng số dịch vụ mạng (service) trong Test:  {len(test_services)}")
    if novel_services:
        print(f"  -> CẢNH BÁO: Tập Test có {len(novel_services)} dịch vụ lạ chưa từng có trong Train: {novel_services}")
        print("     => Đây là lý do ta BẮT BUỘC phải dùng OneHotEncoder(handle_unknown='ignore') để tránh lỗi!")
    else:
        print("  -> Không có service mới lạ giữa 2 tập.")
        
    print("\n" + "=" * 80)
    print("      HOÀN THÀNH GIAI ĐOẠN 1: KHẢO SÁT & KHÁM PHÁ DỮ LIỆU!")
    print("      Tất cả biểu đồ đã được lưu trong: output/plots/")
    print("      Bạn đã sẵn sàng bước sang Giai đoạn 2: Tiền xử lý (Preprocessing)!")
    print("=" * 80)


if __name__ == "__main__":
    main()
