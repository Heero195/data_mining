# 🧪 HƯỚNG DẪN CHI TIẾT CÁC CÁCH TEST WAZUH SIEM (ML-NIDS)

Tài liệu này hướng dẫn đầy đủ **3 phương pháp kiểm thử (Test)** hệ thống Wazuh SIEM tích hợp mô hình Machine Learning phát hiện xâm nhập mạng (ML-NIDS), từ kiểm tra nhanh cú pháp đến chạy demo trực tiếp trên Wazuh Dashboard.

---

## 📌 MỤC LỤC
1. [Phương pháp 1: Test nhanh với công cụ `wazuh-logtest` (Khuyên dùng)](#-phương-pháp-1-test-nhanh-với-wazuh-logtest)
   - [Cách mở trên Giao diện Web (Wazuh Dashboard)](#11-thực-hiện-trên-giao-diện-web-ui)
   - [Cách mở trên Terminal Linux](#12-thực-hiện-trên-terminal-linux)
   - [5 Kịch bản Log mẫu để Test](#13-5-kịch-bản-log-mẫu-để-test)
2. [Phương pháp 2: Test phát luồng dữ liệu tự động (Traffic Replay qua Wazuh Agent)](#-phương-pháp-2-test-phát-luồng-replay-traffic-qua-wazuh-agent)
3. [Phương pháp 3: Test bắn Log qua Syslog UDP (Không cần cài Agent)](#-phương-pháp-3-test-bắn-log-syslog-udp-trực-tiếp)
4. [Bảng tra cứu Rule ID, Mức độ Severity & MITRE ATT&CK](#-bảng-tra-cứu-rule-id--mitre-attck)
5. [Khắc phục sự cố thường gặp (Troubleshooting)](#-khắc-phục-sự-cố-thường-gặp)

---

## 🚀 PHƯƠNG PHÁP 1: Test nhanh với `wazuh-logtest`

> 💡 **Mục đích**: Kiểm tra ngay lập tức xem Decoder có bóc tách được định dạng JSON không và Rules có nổ đúng Rule ID, đúng Level và đúng mã MITRE ATT&CK hay không.

### 1.1. Thực hiện trên Giao diện Web (UI)
1. Đăng nhập vào Wazuh Dashboard: `https://<IP_WAZUH_MANAGER>/` (ví dụ `https://192.168.214.138/`).
2. Bấm vào biểu tượng **Menu 3 dấu gạch ngang** (góc trên cùng bên trái).
3. Chọn **Tools** $\rightarrow$ **Ruleset Test** (hoặc **Test rules**).
4. Copy một trong các dòng log JSON ở mục 1.3 dán vào ô **Log message** và bấm **Test**.

### 1.2. Thực hiện trên Terminal Linux
Mở terminal máy chủ Wazuh Manager (quyền root) và gõ lệnh:
```bash
/var/ossec/bin/wazuh-logtest
```
Sau đó dán dòng log JSON vào và nhấn **Enter**.

---

### 1.3. 5 Kịch bản Log mẫu để Test

#### 🟢 Kịch bản 1: Lưu lượng bình thường (Normal Traffic)
*Dán dòng này vào để kiểm tra:*
```json
{"timestamp": "2026-11-10T10:00:00+00:00", "ml_nids": {"decision": "NORMAL", "src_ip": "192.168.1.105", "dst_ip": "192.168.1.50", "src_port": 40074, "dst_port": 80, "protocol": "tcp", "service": "http", "flag": "SF", "anomaly_score": 4.33, "is_novel_attack": false, "predicted_attack": "Normal", "confidence": 100.0, "distance_metrics": {"mahalanobis_distance": 0.719, "euclidean_distance": 0.822, "dbscan_outlier": 0}}}
```
* **Kết quả mong đợi**:
  - **Phase 2 (Decoder)**: Khớp `ml_nids_json` $\rightarrow$ `JSON_Decoder`.
  - **Phase 3 (Rule)**: Không kích hoạt rule cảnh báo nguy hiểm (hoặc nổ rule nền Level 3 nếu có), vì đây là traffic an toàn.

---

#### 🔴 Kịch bản 2: Tấn công Từ chối dịch vụ DoS (Level 10 - MITRE T1499)
*Dán dòng này vào để kiểm tra:*
```json
{"timestamp": "2026-11-10T10:00:01+00:00", "ml_nids": {"decision": "ANOMALY", "src_ip": "192.168.1.188", "dst_ip": "192.168.1.20", "src_port": 40148, "dst_port": 22, "protocol": "icmp", "service": "ecr_i", "flag": "SF", "anomaly_score": 21.79, "is_novel_attack": false, "predicted_attack": "DoS", "confidence": 100.0, "distance_metrics": {"mahalanobis_distance": 3.856, "euclidean_distance": 3.88, "dbscan_outlier": 0}}}
```
* **Kết quả mong đợi**:
  - **Rule ID**: `100202`
  - **Level**: `10`
  - **Description**: `ML-NIDS: Denial of Service attack detected`
  - **MITRE**: `T1499`

---

#### 🟡 Kịch bản 3: Quét cổng / Dò mạng Probe (Level 8 - MITRE T1046)
*Dán dòng này vào để kiểm tra:*
```json
{"timestamp": "2026-11-10T10:00:02+00:00", "ml_nids": {"decision": "ANOMALY", "src_ip": "192.168.1.192", "dst_ip": "192.168.1.20", "src_port": 40481, "dst_port": 22, "protocol": "tcp", "service": "telnet", "flag": "SF", "anomaly_score": 26.03, "is_novel_attack": false, "predicted_attack": "Probe", "confidence": 80.2, "distance_metrics": {"mahalanobis_distance": 2.767, "euclidean_distance": 2.932, "dbscan_outlier": 1}}}
```
* **Kết quả mong đợi**:
  - **Rule ID**: `100201`
  - **Level**: `8`
  - **Description**: `ML-NIDS: Reconnaissance or Port-scanning activity detected`
  - **MITRE**: `T1046`

---

#### 🟠 Kịch bản 4: Xâm nhập từ xa R2L hoặc Leo thang đặc quyền U2R
*Dán dòng này vào để test U2R (Level 14 - Cao nhất):*
```json
{"timestamp": "2026-11-10T10:00:03+00:00", "ml_nids": {"decision": "ANOMALY", "src_ip": "10.0.0.45", "dst_ip": "192.168.1.10", "src_port": 42100, "dst_port": 22, "protocol": "tcp", "service": "telnet", "flag": "SF", "anomaly_score": 45.12, "is_novel_attack": false, "predicted_attack": "U2R", "confidence": 85.0, "distance_metrics": {"mahalanobis_distance": 5.12, "euclidean_distance": 6.01, "dbscan_outlier": 1}}}
```
* **Kết quả mong đợi**:
  - **Rule ID**: `100204`
  - **Level**: `14` (Mức nguy hiểm tối đa)
  - **MITRE**: `T1068`

---

#### 🚨 Kịch bản 5: Đòn tấn công Mới lạ / Zero-Day dị biệt (Level 13 - MITRE T1203)
*Dán dòng này vào để test khả năng phát hiện Zero-Day:*
```json
{"timestamp": "2026-11-10T10:00:04+00:00", "ml_nids": {"decision": "ANOMALY", "src_ip": "172.16.20.15", "dst_ip": "192.168.1.20", "src_port": 40259, "dst_port": 22, "protocol": "tcp", "service": "private", "flag": "REJ", "anomaly_score": 49.52, "is_novel_attack": true, "predicted_attack": "Probe", "confidence": 100.0, "distance_metrics": {"mahalanobis_distance": 6.568, "euclidean_distance": 7.505, "dbscan_outlier": 1}}}
```
* **Kết quả mong đợi**:
  - **Rule ID**: `100205`
  - **Level**: `13`
  - **Description**: `ML-NIDS CRITICAL: Zero-Day or Novel Attack Signature isolated`
  - **MITRE**: `T1203` (Execution)

---

## 📡 PHƯƠNG PHÁP 2: Test phát luồng Replay Traffic qua Wazuh Agent

> 💡 **Mục đích**: Dùng để **Live Demo / Thuyết trình**. Cho mô hình AI tự động đọc các luồng traffic thực tế, chấm điểm bất thường và đẩy liên tục vào Wazuh Dashboard theo thời gian thực.

### Bước 1: Cấu hình Wazuh Agent thu thập file log JSON
Trên máy tính đang chạy mã nguồn này (đã cài Wazuh Agent):
1. Mở file cấu hình Wazuh Agent:
   - Trên **Windows**: `C:\Program Files (x86)\ossec-agent\ossec.conf`
   - Trên **Linux**: `/var/ossec/etc/ossec.conf`
2. Thêm đoạn cấu hình sau vào bên trong thẻ `<ossec_config>`:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>D:\data_miner\dtd\output\wazuh_alerts.json</location>
   </localfile>
   ```
   *(Lưu ý: Nếu chạy trên Linux, thay đường dẫn bằng path tương ứng).*
3. Khởi động lại dịch vụ Wazuh Agent:
   - Trên Windows PowerShell (Run as Administrator):
     ```powershell
     Restart-Service Wazuh
     ```
   - Trên Linux:
     ```bash
     sudo systemctl restart wazuh-agent
     ```

### Bước 2: Chạy lệnh phát luồng Replay
Mở terminal trong thư mục project `d:\data_miner\dtd` và chạy:
```bash
python main.py --wazuh-demo
```
*Hệ thống sẽ tự động:*
- Lấy mẫu các kết nối (Bình thường, Tấn công đã biết, Tấn công Zero-Day).
- Đẩy qua bộ Preprocessing $\rightarrow$ Unsupervised Mahalanobis $\rightarrow$ Supervised Classifier.
- Ghi từng sự kiện kèm điểm số Anomaly Score vào file `output/wazuh_alerts.json`.

### Bước 3: Quan sát trên Wazuh SOC Dashboard
1. Truy cập Wazuh Dashboard: `https://192.168.214.138/`
2. Vào **Security events** (hoặc **Threat Hunting** $\rightarrow$ **Events**).
3. Đặt bộ lọc tìm kiếm (Filter):
   ```
   rule.groups : ml_nids
   ```
4. Bạn sẽ thấy các cảnh báo màu vàng, cam, đỏ tương ứng với các cấp độ (Level 8, 10, 12, 13, 14) nổi bật trên giao diện theo thời gian thực!

---

## 🌐 PHƯƠNG PHÁP 3: Test bắn log Syslog UDP trực tiếp

> 💡 **Mục đích**: Bắn log trực tiếp qua mạng từ máy chạy Python sang Wazuh Manager mà không cần cài đặt Wazuh Agent.

### Bước 1: Mở cổng Syslog trên Wazuh Manager
Trên máy chủ **Wazuh Manager**, mở file `/var/ossec/etc/ossec.conf` và thêm cấu hình nhận Syslog:
```xml
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.0.0/16</allowed-ips>
  </remote>
</ossec_config>
```
Sau đó khởi động lại Manager: `systemctl restart wazuh-manager`.

### Bước 2: Chạy script gửi Syslog
Trên máy project, chạy lệnh:
```bash
python -m src.wazuh_integration.replay_to_wazuh --host 192.168.214.138 --port 514 --count 20
```

---

## 📋 BẢNG TRA CỨU RULE ID & MITRE ATT&CK

| Rule ID | Cấp độ (Severity) | Phân loại | Tên tấn công / Hành vi | Kỹ thuật MITRE ATT&CK |
| :---: | :---: | :--- | :--- | :---: |
| **`100200`** | **Level 3** | Base Rule | Phát hiện bất thường từ mô hình ML | — |
| **`100201`** | **Level 8** | `Probe` | Quét mạng, rà soát cổng, gián điệp | `T1046` (Network Service Discovery) |
| **`100202`** | **Level 10** | `DoS` | Tấn công từ chối dịch vụ, làm sập server | `T1499` (Endpoint Denial of Service) |
| **`100203`** | **Level 12** | `R2L` | Khai thác ứng dụng từ xa chiếm quyền | `T1190` (Exploit Public-Facing App) |
| **`100204`** | **Level 14** *(Cao nhất)* | `U2R` | Chiếm quyền quản trị máy chủ (Root/Admin) | `T1068` (Privilege Escalation) |
| **`100205`** | **Level 13** *(Khẩn cấp)* | `Novel / Zero-Day` | **Tấn công Mới chưa từng thấy** | `T1203` (Exploitation for Execution) |

---

## 🛠️ KHẮC PHỤC SỰ CỐ THƯỜNG GẶP

1. **Gặp lỗi `XML syntax error (1113)` khi lưu Rules:**
   - Đảm bảo trong thẻ `<mitre>` chỉ có duy nhất thẻ con `<id>...</id>`. Tuyệt đối không để thẻ `<tactic>` hay `<technique>`.
   - Kiểm tra không có ký tự lạ hoặc chữ thừa ở cuối file.

2. **Chạy `wazuh-logtest` mà không thấy Rule kích hoạt (No rule matched):**
   - Kiểm tra lại file `local_decoder.xml`. Decoder phải nhận diện được chuỗi log bắt đầu bằng `{"timestamp"`.
   - Kiểm tra xem đã khởi động lại Wazuh Manager chưa (`systemctl restart wazuh-manager`).

3. **Dashboard không hiện sự kiện mới:**
   - Kiểm tra bộ lọc thời gian (Time picker) ở góc trên bên phải Dashboard, chọn **`Last 15 minutes`** hoặc **`Today`**.
   - Kiểm tra file `output/wazuh_alerts.json` có dữ liệu mới sinh ra hay không.

