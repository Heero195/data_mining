# 👥 KẾ HOẠCH PHÂN CHIA CÔNG VIỆC DỰ ÁN ML-NIDS (3 THÀNH VIÊN)
### Đề tài: Network Intrusion & Cyber Attack Detection (ML-NIDS)
### Kiến trúc: Hybrid Unsupervised Anomaly Detection + Supervised Classification + Wazuh SIEM SOC

---

## 📌 BỨC TRANH TỔNG THỂ DỰ ÁN
Dự án được xây dựng theo chuỗi pipeline khép kín gồm 4 tầng:
```
[Tập dữ liệu NSL-KDD] 
        ↓
[Tiền xử lý & Trích xuất đặc trưng]
        ↓
  ┌───────────────────────────────────┐
  │  Unsupervised Engine (Zero-Day)   │  →  Tính Anomaly Score (0 - 100)
  │  Supervised Engine (5 Attack Grp) │  →  Phân loại nhóm tấn công
  └───────────────────────────────────┘
        ↓
[Wazuh Integration Engine]  →  Gán mã MITRE ATT&CK & Sinh Log JSON
        ↓
[Wazuh SIEM Dashboard]      →  Kích hoạt Rule & Bắn Alert thời gian thực
```

---

## 👤 THÀNH VIÊN 1: Kỹ sư Dữ liệu & Học máy Không giám sát (Data & Unsupervised Engine)
> **Trách nhiệm chính**: Quản trị dữ liệu, tiền xử lý, khử nhiễu và phát triển động cơ phát hiện dị biệt / tấn công mới (Zero-Day Detection).

### 1. Nhiệm vụ kỹ thuật (Source Code & Pipeline)
* **Khảo sát dữ liệu & EDA** ([`eda_exploration.py`](file:///d:/data_miner/dtd/eda_exploration.py), [`01_eda_and_exploration.ipynb`](file:///d:/data_miner/dtd/01_eda_and_exploration.ipynb)):
  * Phân tích phân phối của 41 đặc trưng và 2 cột nhãn trong `KDDTrain+.txt` và `KDDTest+.txt`.
  * Phân tích hiện tượng mất cân bằng dữ liệu giữa các lớp tấn công (`DoS`, `Probe`, `R2L`, `U2R`).
* **Tiền xử lý dữ liệu chuẩn hóa** ([`src/preprocess.py`](file:///d:/data_miner/dtd/src/preprocess.py)):
  * Mã hóa One-Hot (`OneHotEncoder`) cho các biến phân loại: `protocol_type`, `service`, `flag`.
  * Biến đổi phân phối lệch nặng (Heavy-tailed Skewness) bằng $y = \log(1 + x)$ (`np.log1p`) cho `src_bytes`, `dst_bytes`, `duration`.
  * Chuẩn hóa thang đo bằng `StandardScaler`.
  * **Nguyên tắc cốt lõi**: Khóa chống rò rỉ dữ liệu (`Data Leakage`) bằng cách chỉ `fit` trên tập Train và `transform` trên tập Test.
* **Xây dựng động cơ Anomaly Unsupervised** ([`src/unsupervised.py`](file:///d:/data_miner/dtd/src/unsupervised.py)):
  * Giảm chiều PCA (giữ 95% phương sai thông tin) giúp tối ưu ma trận và triệt tiêu đa cộng tuyến.
  * Phân cụm $k=12$ Normal traffic bằng K-Means để xây dựng hồ sơ hành vi mạng an toàn chuẩn (Baseline).
  * Đo khoảng cách hình học **Euclidean** tới các tâm cụm gần nhất.
  * Đo khoảng cách hiệp phương sai **Mahalanobis** (sử dụng ước lượng ổn định `LedoitWolf`).
  * Trích xuất mật độ không gian qua lõi cụm **DBSCAN**.
  * Căn chỉnh ngưỡng cảnh báo động theo phân vị 95% (Threshold 95th Percentile) để khống chế False Alarm Rate ~5%.

### 2. Sản phẩm bàn giao (Deliverables)
* Module tiền xử lý `preprocess.py` và lưu trữ pipeline `joblib`.
* Module `unsupervised.py` hoàn chỉnh, trích xuất được `anomaly_score` và cờ dị biệt `is_anomaly`.

### 3. Phân công Viết Báo cáo & Thuyết trình
* **Nội dung viết Báo cáo (Word / LaTeX)**:
  * Khảo sát tập dữ liệu NSL-KDD, phân tích 41 đặc trưng mạng.
  * Phương pháp tiền xử lý dữ liệu và kỹ thuật chống rò rỉ dữ liệu.
  * Cơ sở toán học của PCA, K-Means, DBSCAN và khoảng cách Mahalanobis trong phát hiện dị biệt.
* **Khi thuyết trình / Vấn đáp**:
  * Trình bày luồng dữ liệu vào, lý do tại sao phải dùng Log-transform.
  * Giải thích trực quan tại sao khoảng cách Mahalanobis lại bắt được hành vi bất thường mới (Zero-Day) tốt hơn các phương pháp chữ ký truyền thống.

---

## 👤 THÀNH VIÊN 2: Kỹ sư Học máy Có giám sát & Đánh giá Đối sánh (Supervised & Benchmark)
> **Trách nhiệm chính**: Huấn luyện các mô hình phân loại tấn công đã biết, thiết kế hệ thống benchmark đối sánh và chứng minh tính hiệu quả của hệ thống.

### 1. Nhiệm vụ kỹ thuật (Source Code & Pipeline)
* **Huấn luyện mô hình Supervised** ([`src/supervised.py`](file:///d:/data_miner/dtd/src/supervised.py)):
  * Xây dựng và tinh chỉnh siêu tham số cho **Random Forest** và **XGBoost Classifier**.
  * Giải quyết 2 bài toán:
    * **Binary Classification**: Phân loại nhị phân (Bình thường vs Tấn công).
    * **Multi-class Classification (5 Lớp)**: Phân loại chi tiết vào 5 nhóm hành vi (`Normal`, `DoS`, `Probe`, `R2L`, `U2R`).
  * Trích xuất độ quan trọng của đặc trưng (**Feature Importance**) để tìm ra các trường gói tin quyết định hành vi tấn công.
* **Hệ thống đánh giá & Đối sánh chuyên sâu** ([`src/evaluate.py`](file:///d:/data_miner/dtd/src/evaluate.py)):
  * Đánh giá bộ chỉ số tiêu chuẩn: Accuracy, Precision, Recall, F1-Score, ROC-AUC, FPR (False Positive Rate).
  * **Điểm nhấn học thuật cốt lõi**: Đánh giá trên **17 chữ ký tấn công mới (Novel/Zero-Day Attacks)** có trong `KDDTest+` mà không hề có trong `KDDTrain+` (`mscan`, `processtable`, `sqlattack`, `sendmail`...).
  * So sánh định lượng: Chứng minh Supervised bị sụt giảm hiệu năng mạnh khi gặp tấn công mới, trong khi Unsupervised Hybrid Engine giữ vững phong độ phát hiện.
* **Trực quan hóa kết quả** ([`src/visualize.py`](file:///d:/data_miner/dtd/src/visualize.py)):
  * Xuất biểu đồ đường cong ROC-AUC, ma trận nhầm lẫn (Confusion Matrix), đồ thị phân phối khoảng cách và biểu đồ sụt giảm hiệu năng.

### 2. Sản phẩm bàn giao (Deliverables)
* Các model đã huấn luyện lưu tại [`output/models/`](file:///d:/data_miner/dtd/output/models).
* Toàn bộ bảng số liệu đánh giá lưu tại [`output/reports/`](file:///d:/data_miner/dtd/output/reports).
* Hệ thống biểu đồ trực quan lưu tại [`output/plots/`](file:///d:/data_miner/dtd/output/plots).

### 3. Phân công Viết Báo cáo & Thuyết trình
* **Nội dung viết Báo cáo (Word / LaTeX)**:
  * Kiến trúc mô hình Random Forest & XGBoost trong bài toán phân loại xâm nhập mạng.
  * Phân tích Feature Importance (các đặc trưng nhạy cảm nhất với mã độc).
  * Chương Thực nghiệm & Thảo luận: Bảng so sánh hiệu năng, phân tích chi tiết khả năng nhận diện 17 đòn tấn công Novel.
* **Khi thuyết trình / Vấn đáp**:
  * Trình bày các kết quả thực nghiệm, giải thích ý nghĩa các chỉ số F1, ROC-AUC.
  * Làm rõ câu hỏi: *"Tại sao mô hình Supervised đạt độ chính xác cao nhưng vẫn cần Unsupervised?"*.

---

## 👤 THÀNH VIÊN 3: Kỹ sư Tích hợp SOC Wazuh & Quản trị Hệ thống (DevOps & SIEM Integration)
> **Trách nhiệm chính**: Tích hợp mô hình AI vào hệ sinh thái an ninh thực tế (Wazuh SIEM Homelab), chuẩn hóa pipeline chạy và phụ trách demo trực tiếp.

### 1. Nhiệm vụ kỹ thuật (Source Code & Pipeline)
* **Cấu hình & Tích hợp Wazuh SIEM** ([`src/wazuh_integration/`](file:///d:/data_miner/dtd/src/wazuh_integration)):
  * Xây dựng **Custom Decoder** ([`decoders/local_decoder.xml`](file:///d:/data_miner/dtd/src/wazuh_integration/decoders/local_decoder.xml)) để bóc tách các trường trong log JSON (`timestamp`, `src_ip`, `dst_ip`, `anomaly_score`, `mitre_attack`...).
  * Viết **Custom Rules** ([`rules/local_rules.xml`](file:///d:/data_miner/dtd/src/wazuh_integration/rules/local_rules.xml)) quy định các cấp độ nguy hiểm (Level 8 - 14):
    * Rule 100201: Dò quét mạng (Probe - MITRE `T1046`).
    * Rule 100202: Từ chối dịch vụ (DoS - MITRE `T1499`).
    * Rule 100203: Tấn công từ xa (R2L - MITRE `T1190`).
    * Rule 100204: Leo thang đặc quyền (U2R - MITRE `T1068`).
    * Rule 100205: Tấn công mới / Zero-Day dị biệt (Novel Attack - MITRE `T1203`).
* **Động cơ suy luận & Sinh log SOC** ([`wazuh_detector.py`](file:///d:/data_miner/dtd/src/wazuh_integration/wazuh_detector.py), [`replay_to_wazuh.py`](file:///d:/data_miner/dtd/src/wazuh_integration/replay_to_wazuh.py)):
  * Kết hợp đầu ra của Thành viên 1 (Anomaly Score) và Thành viên 2 (Attack Class) để tạo payload JSON chuẩn format SOC.
  * Xây dựng tool giả lập replay traffic thời gian thực đẩy log vào [`output/wazuh_alerts.json`](file:///d:/data_miner/dtd/output/wazuh_alerts.json).
* **Quản trị Pipeline & CLI** ([`main.py`](file:///d:/data_miner/dtd/main.py), [`requirements.txt`](file:///d:/data_miner/dtd/requirements.txt)):
  * Chuẩn hóa CLI arguments (`--train`, `--eval`, `--wazuh-demo`, `--all`).
  * Quản lý môi trường thực thi, đóng gói mã nguồn và kiểm thử hệ thống.

### 2. Sản phẩm bàn giao (Deliverables)
* Môi trường Wazuh SIEM Homelab hoạt động hoàn chỉnh (Wazuh Manager + Agent).
* Bộ luật custom rules & decoder chuẩn MITRE ATT&CK.
* Luồng phát traffic tự động và hiển thị alert trực quan trên Wazuh Dashboard.

### 3. Phân công Viết Báo cáo & Thuyết trình
* **Nội dung viết Báo cáo (Word / LaTeX)**:
  * Kiến trúc tích hợp mô hình AI vào SOC SIEM hiện đại.
  * Quy trình thiết lập Wazuh Manager, Agent, cơ chế hoạt động của Decoders và Rules.
  * Bảng ánh xạ ma trận kỹ thuật MITRE ATT&CK với các dạng tấn công mạng.
* **Khi thuyết trình / Vấn đáp**:
  * Trực tiếp thực hiện **Live Demo** trên Wazuh Dashboard: Cho hệ thống replay traffic, chỉ ra các alert Level 10-14 xuất hiện theo thời gian thực.
  * Giải thích vai trò của AI trong việc giảm tải cảnh báo cho các chuyên viên SOC (SOC Tier-1 Analysts).

---

## 📊 BẢNG TỔNG HỢP PHÂN CÔNG & MA TRẬN TRÁCH NHIỆM

| Hạng mục so sánh | Người 1 (Data & Unsupervised) | Người 2 (Supervised & Benchmark) | Người 3 (SOC SIEM & System) |
| :--- | :--- | :--- | :--- |
| **Vai trò** | Data Scientist & Anomaly Engineer | Machine Learning Benchmark Engineer | SecOps & SIEM Integration Engineer |
| **Module phụ trách** | `preprocess.py`, `unsupervised.py`, `eda_exploration.py` | `supervised.py`, `evaluate.py`, `visualize.py` | `src/wazuh_integration/`, `main.py`, requirements |
| **Kỹ thuật & Thuật toán** | PCA, K-Means, Mahalanobis Distance, DBSCAN | Random Forest, XGBoost, Multi-class, ROC-AUC | MITRE ATT&CK, XML Decoder/Rules, JSON Streaming |
| **Deliverables chính** | Model Anomaly, Scaler pipeline, Anomaly Scores | Supervised Models, Báo cáo đối sánh Zero-Day, Plots | Wazuh SIEM Homelab, Alert pipeline, CLI Runner |
| **Phần viết báo cáo** | Khảo sát dữ liệu, Tiền xử lý, Lý thuyết Unsupervised | Mô hình Supervised, Phân tích số liệu thực nghiệm | Kiến trúc SIEM Wazuh, Ánh xạ MITRE, Kết luận |
| **Nhiệm vụ khi bảo vệ** | Trình bày luồng dữ liệu & cơ chế phát hiện dị biệt | Trình bày kết quả đo lường & năng lực bắt Novel Attack | Thuyết trình kiến trúc kết nối & **Trực tiếp Live Demo** |
