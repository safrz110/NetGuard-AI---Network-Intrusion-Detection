<div align="center">

<img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" />
<img src="https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
<img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" />

<br /><br />

# 🛡️ NetGuard AI — Network Intrusion Detection System

**A real-time network traffic classifier powered by a Support Vector Machine (RBF kernel), trained on NSL-KDD intrusion patterns to detect 5 classes of network attacks with 99%+ accuracy.**

<br />

| Metric | Score |
|:---|:---:|
|  Accuracy | **99.8%** |
|  Algorithm | **SVM (RBF Kernel)** |
|  Attack Classes | **5** |
|  Input Features | **24** |

<br />

</div>

---

##  Table of Contents

- [Project Overview](#-project-overview)
- [Live Demo](#-live-demo)
- [ML Pipeline](#-ml-pipeline)
- [App Features](#-app-features)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Key Input Features](#-key-input-features)
- [Attack Classes Explained](#-attack-classes-explained)
- [Model Performance](#-model-performance)
- [Tech Stack](#-tech-stack)
- [Future Enhancements](#-future-enhancements)
- [Author](#-author)

---

##  Project Overview

Network Intrusion Detection Systems (NIDS) are a core layer of enterprise cyber defence — they monitor traffic in real time and flag connections that match known attack signatures. This project implements a **machine learning–based NIDS** trained on the **NSL-KDD dataset**, a refined and widely-used benchmark derived from the original KDD Cup '99 dataset.

**What makes this project stand out:**

- Classifies traffic into **5 categories**: `Normal`, `DoS`, `Probe`, `R2L` (Remote-to-Local), and `U2R` (User-to-Root)
- Uses a **Support Vector Machine with RBF kernel** — the gold-standard algorithm for high-dimensional, non-linearly-separable intrusion data
- **Platt-scaled probability outputs** — the SVM's raw decision function is calibrated into class probabilities via sigmoid fitting
- **Balanced class weighting** — handles the severe class imbalance inherent to intrusion datasets (U2R attacks are <1% of traffic)
- Deployed as a **SOC-style dark terminal UI** with live probability bars and severity-coded incident response guidance

---

##  Live Demo

> Clone the repo and run locally — see [Quick Start](#-quick-start)

**Normal traffic:**
```
 Normal
SVM decision confidence: 98.7%
→ Traffic pattern appears benign. Continue standard monitoring.
```

**DoS attack detected:**
```
 DoS
SVM decision confidence: 96.2%
→ Denial-of-Service attack detected. Rate-limit source IP immediately.
```

---

##  ML Pipeline

```
Raw Network Connection (24 features)
              │
              ▼
┌─────────────────────────┐
│   ColumnTransformer     │  ← StandardScaler on 21 numerical features
│   (Preprocessing)       │  ← OneHotEncoder on protocol_type, service, flag
└────────────┬────────────┘     → 98-dimensional feature vector
             │
             ▼
┌─────────────────────────┐
│   SVC (RBF Kernel)      │  ← C=10, gamma='scale'
│   probability=True      │  ← class_weight='balanced'
│   (Platt Scaling)       │  ← Sigmoid-calibrated probability output
└────────────┬────────────┘
             │
             ▼
   Normal / DoS / Probe / R2L / U2R
        + Class Probabilities
```

**Why SVM with RBF kernel for intrusion detection?**

Network traffic features live in a high-dimensional space (98 dimensions after encoding) where attack and normal traffic are **not linearly separable** — a DoS flood and a Probe scan can share similar byte counts but differ sharply in service-rate ratios. The RBF kernel implicitly maps inputs into an infinite-dimensional space, allowing the SVM to draw curved decision boundaries around each attack cluster. `class_weight='balanced'` is critical here because U2R and R2L attacks make up a tiny fraction of real traffic — without it, the SVM would simply predict "Normal" for everything and still score ~85% accuracy while missing every real attack.

---

##  App Features

- ** Real-time SVM inference** — instant classification on slider/dropdown input
- ** 5-class probability bars** — visualises confidence across all attack types, not just the top prediction
- ** SOC terminal aesthetic** — dark theme, scanline overlay, monospace data typography (Space Mono)
- ** 12 curated inputs** from 24 raw features, grouped into 4 operationally meaningful sections
- ** Severity-coded result panels** — green/red/orange/purple by attack type
- ** Incident-response guidance** — contextual next-step recommendation per classification
- ** Live signal chips** — DoS/Probe risk heuristics computed from connection-rate features
- **⚡ Cached model training** — `@st.cache_resource` avoids re-training on every interaction

---

##  Project Structure

```
netguard-ai/
│
├── netguard_app.py          # Main Streamlit application
├── best_model.pkl           # Fitted ColumnTransformer (StandardScaler + OneHotEncoder)
├── feature_columns.pkl      # Ordered list of 24 input feature names
│
├── notebooks/
│   ├── 01_EDA.ipynb          # NSL-KDD exploratory analysis
│   ├── 02_Preprocessing.ipynb # ColumnTransformer fitting
│   └── 03_SVM_Training.ipynb  # SVM hyperparameter tuning & evaluation
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

##  Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/your-username/netguard-ai.git
cd netguard-ai
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch the app
```bash
streamlit run netguard_app.py
```

Open **http://localhost:8501** in your browser.

>  **First load takes ~10-15 seconds** — the SVM trains on startup and is cached via `@st.cache_resource` for instant subsequent predictions.

---

##  Requirements

```
streamlit>=1.32.0
scikit-learn>=1.3.0
joblib>=1.3.0
numpy>=1.24.0
pandas>=2.0.0
```

---

##  Key Input Features

The app uses **12 high-signal inputs** from the 24-feature NSL-KDD schema, grouped into 4 operational categories:

###  Connection Profile
| Feature | Description |
|---|---|
| `protocol_type` | Network protocol — `tcp`, `udp`, `icmp` |
| `service` | Destination service — `http`, `ftp`, `smtp`, `ssh`, etc. |
| `flag` | Connection status flag — `SF` (normal), `S0`/`REJ` (failed handshakes) |

###  Traffic Volume & Bytes
| Feature | Description |
|---|---|
| `log_src_bytes` | Log of bytes sent source → destination |
| `log_dst_bytes` | Log of bytes sent destination → source |
| `log_duration` | Log of connection duration |
| `count` | Connections to same host in last 2 seconds |

###  Service Rate Signals
| Feature | Description |
|---|---|
| `srv_count` | Connections to same service in last 2 seconds |
| `same_srv_rate` | % of connections to the same service |
| `serror_rate` | % of connections with SYN errors |
| `diff_srv_rate` | % of connections to different services |

###  Destination Host Behaviour
| Feature | Description |
|---|---|
| `dst_host_count` | Connections to same destination host (last 100) |
| `dst_host_srv_diff_host_rate` | Same service from different source hosts |
| `dst_host_same_src_port_rate` | Connections from same source port |
| `error_rate` | Composite SYN + RST error rate |

> The remaining 12 features (`total_bytes`, `byte_ratio`, `wrong_fragment`, `urgent`, `rerror_rate`, `dst_host_srv_count`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `host_risk`, etc.) are derived automatically from the 12 user inputs to preserve compatibility with the fitted `ColumnTransformer`.

---

##  Attack Classes Explained

| Class | Full Name | Description | Key Signal |
|---|---|---|---|
|  **Normal** | — | Legitimate user traffic | Balanced byte ratios, low error rates |
|  **DoS** | Denial of Service | Floods a host to exhaust resources | Very high `count`, near-zero duration, high `serror_rate` |
|  **Probe** | Surveillance/Scanning | Reconnaissance to map open ports/services | High `diff_srv_rate`, varying protocols |
|  **R2L** | Remote to Local | Unauthorized access from remote machine | Long duration, normal-looking byte counts |
| ⚡ **U2R** | User to Root | Privilege escalation after gaining access | Very low connection/service counts, long duration |

---

##  Model Performance

### SVM Configuration

| Parameter | Value | Reasoning |
|---|---|---|
| `kernel` | `rbf` | Captures non-linear attack boundaries |
| `C` | `10` | Moderate regularisation — balances margin width vs. misclassification |
| `gamma` | `scale` | Auto-scales based on feature variance (1 / (n_features × X.var())) |
| `class_weight` | `balanced` | Compensates for severe class imbalance (U2R < 1% of data) |
| `probability` | `True` | Enables Platt-scaled probability outputs for the UI |

### Test Set Results

| Class | Precision | Recall | F1-Score |
|---|:---:|:---:|:---:|
| Normal | 1.00 | 1.00 | 1.00 |
| DoS | 1.00 | 1.00 | 1.00 |
| Probe | 1.00 | 1.00 | 1.00 |
| R2L | 1.00 | 0.97 | 0.98 |
| U2R | 0.94 | 1.00 | 0.97 |
| **Weighted Avg** | **1.00** | **1.00** | **1.00** |

**Overall Accuracy: 99.8%**

---

##  Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.9+ |
| ML Model | scikit-learn `SVC` (RBF kernel) |
| Preprocessing | `ColumnTransformer`, `StandardScaler`, `OneHotEncoder` |
| Web Framework | Streamlit |
| Data Processing | NumPy, Pandas |
| UI Styling | Custom CSS — SOC terminal theme (Space Grotesk + Space Mono) |
| Model Serialisation | joblib / pickle |
| Dataset | NSL-KDD Intrusion Detection Benchmark |
| Version Control | Git / GitHub |

---

##  Future Enhancements

- [ ] Add SHAP-based explainability for individual SVM predictions
- [ ] Compare SVM against Random Forest, XGBoost, and Neural Networks
- [ ] Real-time packet capture integration via `scapy` or `pyshark`
- [ ] Batch CSV upload for analysing full traffic logs
- [ ] Deploy to Streamlit Cloud / Hugging Face Spaces
- [ ] Integrate with SIEM tools (Splunk, ELK) via REST API

---

## 👨‍💻 Author

**Sarfaraz Ali**



---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

⭐ **Found this useful? Drop a star — it helps others discover the project!** ⭐



</div>
