
# 🌐 Eboli AI Security Proxy  
### Industrial IoT (IIoT) Cyber Defense System  
*Developed by Lunar Labs* 🚀🔒

---

<div align="center">
  <img src="https://i.imgur.com/J3EmW6G.png" alt="Eboli Architecture" width="400" />
  <p><i>AI-powered network traffic analysis & threat mitigation proxy for IIoT environments</i></p>
</div>

---

## 🌟 Project Overview

**Eboli** is an advanced AI-powered security proxy tailored for **Industrial IoT (IIoT)** networks. It acts as a **smart gateway** that inspects incoming network requests, detects malicious behavior, and prevents attacks in real-time.

> Industrial IoT devices such as robots, sensors, and PLCs often lack dedicated firewalls or complex security. Eboli fills this gap by providing an autonomous, ML-based defense mechanism embedded directly as a proxy in your network infrastructure.  
>
> It analyzes detailed network features — from packet sizes and rates to login attempts and error rates — to classify traffic as **Normal** or **Malicious**, safeguarding your critical IIoT systems.

---

### 🛠️ How Eboli Works: System Workflow

<div align="center">
  <img src="https://i.imgur.com/YC2zMib.png" alt="Eboli Working Mechanism" width="600" />
  <p><i>Flow of network traffic through Eboli AI Security Proxy</i></p>
</div>

1. **Incoming Network Traffic**: Packets from external devices or internal IoT components arrive at the proxy.  
2. **Feature Extraction Module**: Extracts 43 detailed features per packet/request, including packet size, protocol type, login attempts, error rates, etc.  
3. **Preprocessing & Scaling**: Features are normalized to align with model training parameters.  
4. **Random Forest Classifier**: The trained AI model predicts the traffic type — Normal or specific Attack (DDoS, Spoofing, etc.).  
5. **Decision & Action**:  
    - If **Normal** → Traffic allowed to proceed normally.  
    - If **Malicious** → Traffic is blocked, logged, and flagged for alerting.  
6. **Logging & Monitoring**: All decisions and traffic metadata are logged with timestamps for audits and further analysis.  

---

## 🛡️ Threat Landscape & Defense

### 1️⃣ Distributed Denial of Service (DDoS)  
- **Description:** Floods network with high-volume traffic, overwhelming IIoT nodes.  
- **Detected by:**  
  - Extremely high packet rate (e.g., hundreds/thousands packets/sec)  
  - Abnormal error rates (`serror_rate`, `rerror_rate`)  
  - Repeated service counts (`srv_count`)  
- **Defense:** Immediate proxy blocking, alerts, and IP blacklisting.  

---

### 2️⃣ Spoofing Attacks  
- **Description:** Impersonates legitimate devices by faking IP/MAC addresses or login credentials.  
- **Detected by:**  
  - Inconsistent fragment counts (`wrong_fragment`)  
  - Abnormal login failures (`num_failed_logins`, `logged_in`)  
  - Suspicious root shell or command attempts (`root_shell`, `su_attempted`)  
- **Defense:** Flagging and isolating spoofed devices at network edge.  

---

### 3️⃣ Brute Force Attacks  
- **Description:** Rapid, repeated login attempts to gain unauthorized access.  
- **Detected by:**  
  - Number of failed login attempts  
  - Multiple root or file creation commands within a short window  
- **Defense:** Throttling, lockouts, and alert generation.  

---

### 4️⃣ Port Scanning  
- **Description:** Enumeration of open ports to find vulnerabilities.  
- **Detected by:**  
  - High connection counts with short duration (`count`, `srv_count`)  
  - High error rates on services  
- **Defense:** Rate limiting and connection blacklisting.  

---

### 5️⃣ Other Malicious Patterns  
- Fragmentation abuse, anomalous traffic distribution, unauthorized file access commands, and abnormal protocol usage are detected through a comprehensive feature set.

---

## ⚙️ Technical Architecture

| Component       | Technology                | Purpose                                     |
|-----------------|---------------------------|---------------------------------------------|
| **Model**       | Scikit-learn RandomForest | Classifies network traffic as normal/malicious |
| **Feature Set** | 43 features including packet size, error rates, login attempts | Capture detailed traffic patterns          |
| **API Server**  | Flask + Waitress           | Provides REST interface `/check` for proxy use |
| **Scaler**      | StandardScaler (joblib)    | Normalizes input features for model         |
| **Logging**     | Python logging             | Tracks prediction events with timestamps    |

---

## 🐾 Installation & Usage

### 1. Install Dependencies  
```bash
pip install -r requirements.txt
````

### 2. Start the API Server

```bash
python eboli.py
```

Server listens on port `5000`, ready to accept JSON POST requests at `/check`.

### 3. Sending Requests

Use the included shell script to simulate traffic:

```bash
chmod +x test.sh
./test.sh
```

This tests normal traffic, DDoS, and spoofing attacks with pre-configured feature sets.

---

## 🔌 API Reference

### POST `/check`

* **Description:** Analyze incoming traffic and classify as normal or malicious.
* **Request:** JSON object with 43 traffic features (see `FEATURE_NAMES` in code).
* **Response:**

```json
{
  "status": "success",
  "prediction": 1,
  "attack_type": "DDoS",
  "probabilities": {
    "Normal": 0.03,
    "DDoS": 0.85,
    "Spoofing": 0.05,
    "Port Scan": 0.04,
    "Brute Force": 0.02,
    "Malware": 0.01
  },
  "is_malicious": true
}
```

---

## 🎯 Example Outputs

### Normal Traffic Request

```bash
curl -X POST http://localhost:5000/check \
-H "Content-Type: application/json" \
-d '{ "packet_size": 512, "packet_rate": 1.2, "protocol_type": 0, ... }'
```

**Response:**

```json
{
  "prediction": 0,
  "attack_type": "Normal",
  "is_malicious": false
}
```

### Detected DDoS Attack

```bash
curl -X POST http://localhost:5000/check \
-H "Content-Type: application/json" \
-d '{ "packet_size": 64, "packet_rate": 850.0, "protocol_type": 0, ... }'
```

**Response:**

```json
{
  "prediction": 1,
  "attack_type": "DDoS",
  "is_malicious": true
}
```

---

## 📈 Performance & Metrics

* **Latency:** Average classification response time ≤ 50 ms
* **Accuracy:** 95%+ on diverse IIoT attack datasets
* **Scalability:** Handles thousands of concurrent requests via waitress production server

---

## ❓ Frequently Asked Questions

### Why is Eboli ideal for IIoT?

IIoT devices often have limited security controls and are vulnerable to network-layer attacks. Eboli acts as an intelligent gatekeeper at the network edge, providing autonomous, real-time protection without heavy resource usage.

### How is this different from traditional firewalls?

Eboli uses behavioral AI to detect evolving threats instead of static rules or signature databases, allowing adaptive defense against zero-day attacks common in IIoT.

### Can I customize detection thresholds?

Yes! Model retraining with updated data and tuning can refine sensitivity per your environment.

---

## 🤝 Contributing & License

Contributions, bug reports, and suggestions are welcome! Please submit pull requests or open issues.

Licensed under **MIT License**. See LICENSE file for details.

---

<div align="center">  
  <img src="https://i.imgur.com/m5Q0xHd.png" width="150" />  
  <p><i>Made with passion by Lunar Labs 🚀</i></p>  
</div>
```
