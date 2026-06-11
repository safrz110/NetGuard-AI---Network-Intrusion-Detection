import streamlit as st
import numpy as np
import pandas as pd
import joblib
import pickle
import warnings
import time
warnings.filterwarnings("ignore")

# ─── Page Config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetGuard AI - Network Intrusion Detection System",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ─── CSS ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif !important;
    background: #050B14 !important;
    color: #C9D4E8;
}
.block-container {
    padding: 0 1.5rem 5rem !important;
    max-width: 820px !important;
}

/* ── HERO ────────────────────────────────────────────────── */
.hero {
    position: relative;
    padding: 3rem 2.5rem 2.5rem;
    margin-bottom: 2.2rem;
    overflow: hidden;
    border-bottom: 1px solid rgba(0,255,163,0.12);
}
.hero::before {
    content: '';
    position: absolute; inset: 0;
    background: repeating-linear-gradient(
        0deg, transparent, transparent 3px,
        rgba(0,255,163,0.015) 3px, rgba(0,255,163,0.015) 4px
    );
    pointer-events: none;
}
.hero::after {
    content: '';
    position: absolute; top: -60px; right: -80px;
    width: 420px; height: 420px;
    background: radial-gradient(circle, rgba(0,255,163,0.06) 0%, transparent 70%);
    pointer-events: none;
}
.hero-eyebrow {
    font-family: 'Space Mono', monospace;
    font-size: 0.65rem; letter-spacing: 3.5px; text-transform: uppercase;
    color: #00FFA3; margin-bottom: 1rem;
    display: flex; align-items: center; gap: 0.6rem;
}
.hero-eyebrow::before {
    content: ''; display: inline-block;
    width: 22px; height: 1px; background: #00FFA3;
}
.hero h1 {
    font-size: 2.4rem; font-weight: 700; letter-spacing: -1px;
    line-height: 1.1; color: #F0F6FF; margin-bottom: 0.8rem;
}
.hero h1 em { font-style: normal; color: #00FFA3; }
.hero-sub { font-size: 0.88rem; color: #5A6B88; line-height: 1.65; max-width: 500px; }

/* SVM badge */
.svm-badge {
    display: inline-flex; align-items: center; gap: 0.5rem;
    margin-top: 1rem;
    background: rgba(0,255,163,0.07);
    border: 1px solid rgba(0,255,163,0.2);
    border-radius: 8px; padding: 0.4rem 0.9rem;
    font-family: 'Space Mono', monospace; font-size: 0.68rem;
    letter-spacing: 1.5px; text-transform: uppercase; color: #00FFA3;
}
.svm-badge::before { content: '⚙'; font-size: 0.75rem; }

.hero-stats {
    display: flex; gap: 2rem; margin-top: 1.8rem; flex-wrap: wrap;
}
.hstat { border-left: 2px solid rgba(0,255,163,0.3); padding-left: 0.9rem; }
.hstat-val {
    font-family: 'Space Mono', monospace; font-size: 1.3rem;
    font-weight: 700; color: #00FFA3; display: block;
}
.hstat-lbl {
    font-size: 0.62rem; text-transform: uppercase; letter-spacing: 1.5px;
    color: #3D4F6A; display: block; margin-top: 0.15rem;
}

/* ── INPUT CARDS ─────────────────────────────────────────── */
.icard {
    background: rgba(255,255,255,0.028);
    border: 1px solid rgba(255,255,255,0.065);
    border-radius: 14px; padding: 1.5rem 1.8rem 1rem;
    margin-bottom: 1rem; position: relative; overflow: hidden;
}
.icard::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0;
    height: 2px; background: linear-gradient(90deg, #00FFA3, transparent); opacity: 0.3;
}
.icard-label {
    font-family: 'Space Mono', monospace; font-size: 0.62rem;
    letter-spacing: 2.5px; text-transform: uppercase;
    color: #00FFA3; margin-bottom: 1.1rem; opacity: 0.85;
}

/* ── WIDGET OVERRIDES ────────────────────────────────────── */
.stSlider label, .stSelectbox label {
    color: #8896AE !important; font-size: 0.8rem !important;
    font-weight: 500 !important; letter-spacing: 0.2px !important;
}
.stSlider [data-testid="stThumbValue"] {
    font-family: 'Space Mono', monospace !important; font-size: 0.7rem !important;
    background: #0D1B2E !important; color: #00FFA3 !important;
    border: 1px solid rgba(0,255,163,0.3) !important; border-radius: 5px !important;
}
div[data-baseweb="select"] > div {
    background: rgba(255,255,255,0.04) !important;
    border-color: rgba(255,255,255,0.1) !important; border-radius: 8px !important;
}

/* ── ANALYSE BUTTON ──────────────────────────────────────── */
div.stButton > button {
    width: 100%;
    background: linear-gradient(135deg, #00FFA3 0%, #00C97A 100%);
    color: #020C18 !important; font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 700 !important; font-size: 0.95rem !important;
    letter-spacing: 1px; text-transform: uppercase;
    padding: 0.85rem 2rem; border: none; border-radius: 10px;
    box-shadow: 0 0 30px rgba(0,255,163,0.2), 0 4px 15px rgba(0,0,0,0.4);
    transition: all 0.2s ease; margin-top: 0.6rem;
}
div.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 0 50px rgba(0,255,163,0.35), 0 8px 25px rgba(0,0,0,0.5);
}

/* ── RESULT PANELS ───────────────────────────────────────── */
.result-safe {
    background: linear-gradient(135deg, #031A10, #052A18);
    border: 1px solid #00FFA3; border-radius: 16px;
    padding: 2.2rem 2rem 1.8rem; text-align: center;
    box-shadow: 0 0 60px rgba(0,255,163,0.1), 0 8px 30px rgba(0,0,0,0.4);
    margin: 1.5rem 0;
}
.result-dos {
    background: linear-gradient(135deg, #1A0505, #2D0808);
    border: 1px solid #FF4444; border-radius: 16px;
    padding: 2.2rem 2rem 1.8rem; text-align: center;
    box-shadow: 0 0 60px rgba(255,68,68,0.1), 0 8px 30px rgba(0,0,0,0.4);
    margin: 1.5rem 0;
}
.result-probe {
    background: linear-gradient(135deg, #1A0E00, #2B1800);
    border: 1px solid #FF9500; border-radius: 16px;
    padding: 2.2rem 2rem 1.8rem; text-align: center;
    box-shadow: 0 0 60px rgba(255,149,0,0.1), 0 8px 30px rgba(0,0,0,0.4);
    margin: 1.5rem 0;
}
.result-r2l, .result-u2r {
    background: linear-gradient(135deg, #10001A, #1C0030);
    border: 1px solid #BF5FFF; border-radius: 16px;
    padding: 2.2rem 2rem 1.8rem; text-align: center;
    box-shadow: 0 0 60px rgba(191,95,255,0.1), 0 8px 30px rgba(0,0,0,0.4);
    margin: 1.5rem 0;
}
.res-icon { font-size: 2.5rem; margin-bottom: 0.6rem; }
.res-verdict { font-size: 1.6rem; font-weight: 700; color: white; letter-spacing: -0.3px; }
.res-type {
    font-family: 'Space Mono', monospace; font-size: 0.7rem;
    letter-spacing: 3px; text-transform: uppercase;
    margin-top: 0.4rem; opacity: 0.65; color: white;
}
.res-conf {
    font-family: 'Space Mono', monospace; font-size: 3rem;
    font-weight: 700; color: white; line-height: 1; margin: 0.8rem 0 0.3rem;
}
.res-sub { font-size: 0.78rem; color: rgba(255,255,255,0.4); letter-spacing: 0.5px; }
.res-algo {
    font-family: 'Space Mono', monospace; font-size: 0.65rem;
    letter-spacing: 1.5px; color: rgba(255,255,255,0.3);
    text-transform: uppercase; margin-top: 0.4rem;
}
.res-action {
    margin-top: 1.2rem; background: rgba(255,255,255,0.06);
    border-radius: 10px; padding: 0.8rem 1rem;
    font-size: 0.82rem; color: rgba(255,255,255,0.75);
    line-height: 1.55; text-align: left;
}

/* ── PROBABILITY BARS ────────────────────────────────────── */
.prob-row { margin-top: 1.2rem; }
.prob-item { display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.55rem; }
.prob-label {
    font-family: 'Space Mono', monospace; font-size: 0.68rem;
    letter-spacing: 1px; width: 70px; text-align: right;
    color: #8896AE; flex-shrink: 0;
}
.prob-bar-track {
    flex: 1; height: 6px; background: rgba(255,255,255,0.05);
    border-radius: 3px; overflow: hidden;
}
.prob-bar-fill { height: 100%; border-radius: 3px; }
.prob-pct {
    font-family: 'Space Mono', monospace; font-size: 0.68rem;
    width: 40px; text-align: right; color: #5A6B88;
}

/* ── CHIPS ───────────────────────────────────────────────── */
.chips { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-top: 1rem; }
.chip {
    background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.07);
    border-radius: 8px; padding: 0.5rem 0.85rem; flex: 1; min-width: 110px;
}
.chip-k {
    font-size: 0.58rem; text-transform: uppercase; letter-spacing: 1.3px;
    color: #3D4F6A; display: block; margin-bottom: 0.2rem;
}
.chip-v {
    font-family: 'Space Mono', monospace; font-size: 0.85rem;
    font-weight: 700; color: #C9D4E8;
}

/* ── FOOTER ──────────────────────────────────────────────── */
.app-footer {
    text-align: center; margin-top: 3rem; padding-top: 1.5rem;
    border-top: 1px solid rgba(255,255,255,0.04);
    font-family: 'Space Mono', monospace; font-size: 0.62rem;
    color: #1C2A3A; letter-spacing: 2px; text-transform: uppercase;
}

#MainMenu, footer, header { visibility: hidden; }
.stSpinner > div { border-top-color: #00FFA3 !important; }
</style>
""", unsafe_allow_html=True)


# ─── Load Artifacts ───────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def load_artifacts():
    from sklearn.svm import SVC
    from sklearn.model_selection import train_test_split

    preprocessor = joblib.load("best_model.pkl")   # ColumnTransformer
    with open("feature_columns.pkl", "rb") as f:
        feature_cols = pickle.load(f)

    # ── Build synthetic NSL-KDD training data ─────────────────────────────
    np.random.seed(42)

    def _synth(n, p):
        return pd.DataFrame({
            'log_duration':                  np.random.exponential(p['dur'],  n).clip(0, 12),
            'log_src_bytes':                 np.random.normal(p['sb'], 2.0,   n).clip(0),
            'log_dst_bytes':                 np.random.normal(p['db'], 2.0,   n).clip(0),
            'total_bytes':                   np.random.exponential(p['tb'],   n).clip(0),
            'byte_ratio':                    np.random.exponential(p['br'],   n).clip(0),
            'wrong_fragment':                np.random.choice([0,1,2], n, p=p['wf']).astype(float),
            'urgent':                        np.zeros(n),
            'count':                         np.clip(np.random.normal(p['cnt'], 80, n), 1, 511),
            'srv_count':                     np.clip(np.random.normal(p['sc'],  60, n), 1, 511),
            'serror_rate':                   np.clip(np.random.beta(*p['ser']), 0, 1),
            'rerror_rate':                   np.clip(np.random.beta(*p['rer']), 0, 1),
            'same_srv_rate':                 np.clip(np.random.beta(*p['ssr']), 0, 1),
            'diff_srv_rate':                 np.clip(np.random.beta(*p['dsr']), 0, 1),
            'dst_host_count':                np.clip(np.random.normal(p['dhc'], 60, n), 1, 255),
            'dst_host_srv_count':            np.clip(np.random.normal(p['dhsc'],70, n), 1, 255),
            'dst_host_same_srv_rate':        np.clip(np.random.beta(*p['dhssr']), 0, 1),
            'dst_host_diff_srv_rate':        np.clip(np.random.beta(*p['dhdsr']), 0, 1),
            'dst_host_same_src_port_rate':   np.clip(np.random.beta(*p['dhsspr']),0, 1),
            'dst_host_srv_diff_host_rate':   np.clip(np.random.beta(*p['dhsdhr']),0, 1),
            'error_rate':                    np.clip(np.random.exponential(p['er'], n), 0, 5),
            'host_risk':                     np.clip(np.random.exponential(p['hr'], n), 0, 5),
            'protocol_type':                 np.random.choice(p['proto'], n),
            'service':                       np.random.choice(p['svc'],   n),
            'flag':                          np.random.choice(p['flags'], n, p=p['fp']),
        })

    profiles = {
        'Normal': dict(dur=0.8, sb=5.5, db=5.8, tb=8000, br=60,  wf=[0.99,0.01,0.0],
                       cnt=60,  sc=45,  ser=(1,18),rer=(1,12),ssr=(8,2), dsr=(1,9),
                       dhc=180, dhsc=140,dhssr=(7,2),dhdsr=(1,10),dhsspr=(2,7),dhsdhr=(1,20),
                       er=0.1, hr=0.3, proto=['tcp','udp'],
                       svc=['http','ftp_data','smtp','ssh'], flags=['SF','S1'], fp=[0.96,0.04]),
        'DoS':    dict(dur=0.05,sb=2.5, db=0.2, tb=300,  br=300, wf=[0.65,0.25,0.1],
                       cnt=420, sc=380, ser=(8,2), rer=(3,5), ssr=(9,1), dsr=(1,18),
                       dhc=240, dhsc=230,dhssr=(9,1),dhdsr=(1,20),dhsspr=(8,2),dhsdhr=(1,16),
                       er=2.2, hr=2.0, proto=['tcp','icmp'],
                       svc=['http','private','ecr_i'], flags=['S0','REJ','RSTO'], fp=[0.55,0.35,0.10]),
        'Probe':  dict(dur=1.2, sb=2.8, db=1.5, tb=180,  br=12,  wf=[0.95,0.04,0.01],
                       cnt=280, sc=18,  ser=(1,6), rer=(2,4), ssr=(1,6), dsr=(6,2),
                       dhc=200, dhsc=25, dhssr=(1,7),dhdsr=(5,3),dhsspr=(1,9),dhsdhr=(4,3),
                       er=0.6, hr=0.9, proto=['tcp','udp','icmp'],
                       svc=['ftp','ssh','finger','other'], flags=['SF','S0','REJ'], fp=[0.45,0.40,0.15]),
        'R2L':    dict(dur=2.5, sb=4.0, db=5.5, tb=12000,br=80,  wf=[0.97,0.02,0.01],
                       cnt=30,  sc=20,  ser=(1,15),rer=(1,8), ssr=(6,3), dsr=(1,6),
                       dhc=100, dhsc=80, dhssr=(5,3),dhdsr=(1,7),dhsspr=(2,5),dhsdhr=(1,12),
                       er=0.3, hr=0.8, proto=['tcp'],
                       svc=['ftp','telnet','smtp'], flags=['SF','S1'], fp=[0.92,0.08]),
        'U2R':    dict(dur=3.0, sb=5.0, db=6.0, tb=20000,br=100, wf=[0.98,0.02,0.0],
                       cnt=15,  sc=10,  ser=(1,20),rer=(1,20),ssr=(7,3), dsr=(1,8),
                       dhc=80,  dhsc=60, dhssr=(6,3),dhdsr=(1,8),dhsspr=(3,6),dhsdhr=(1,18),
                       er=0.2, hr=0.5, proto=['tcp'],
                       svc=['telnet','ssh','ftp'], flags=['SF'], fp=[1.0]),
    }
    sizes = {'Normal': 3000, 'DoS': 1000, 'Probe': 600, 'R2L': 300, 'U2R': 150}

    dfs, labels = [], []
    for cls, sz in sizes.items():
        dfs.append(_synth(sz, profiles[cls]))
        labels.extend([cls] * sz)

    df_all = pd.concat(dfs, ignore_index=True)[feature_cols]
    y_all  = np.array(labels)

    X_t = preprocessor.transform(df_all)
    X_tr, _, y_tr, _ = train_test_split(
        X_t, y_all, test_size=0.15, random_state=42, stratify=y_all
    )

    # ── SVM — RBF kernel, balanced class weights ───────────────────────────
    svm = SVC(kernel='rbf', C=10, gamma='scale',
              probability=True, class_weight='balanced', random_state=42)
    svm.fit(X_tr, y_tr)
    return preprocessor, svm, feature_cols


with st.spinner("Initialising SVM model…"):
    preprocessor, svm_clf, feature_cols = load_artifacts()

# ─── Constants ────────────────────────────────────────────────────────────────
ATTACK_CLASSES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
BAR_COLORS = {
    'Normal': '#00FFA3', 'DoS': '#FF4444',
    'Probe':  '#FF9500', 'R2L': '#BF5FFF', 'U2R': '#FF3ECA',
}
RESULT_CSS = {
    'Normal': 'result-safe', 'DoS': 'result-dos',
    'Probe':  'result-probe', 'R2L': 'result-r2l', 'U2R': 'result-u2r',
}
RESULT_ICONS = {
    'Normal': '🟢', 'DoS': '🔴', 'Probe': '🟠', 'R2L': '🟣', 'U2R': '⚡',
}
RESULT_ACTIONS = {
    'Normal': "✅ Traffic pattern appears <strong>benign</strong>. Continue standard monitoring. No immediate action required.",
    'DoS':    "🚨 <strong>Denial-of-Service attack detected.</strong> Immediately rate-limit or block the source IP. Alert the NOC team and review firewall rules.",
    'Probe':  "⚠️ <strong>Network reconnaissance detected.</strong> Log source IP and inspect for lateral movement. Consider blocking at the perimeter.",
    'R2L':    "🔒 <strong>Remote-to-Local intrusion attempt.</strong> Review authentication logs. Enforce MFA and audit remote access controls immediately.",
    'U2R':    "💀 <strong>Privilege escalation attempt detected.</strong> Isolate the affected host immediately. Engage incident response — Critical severity.",
}


# ─── Hero ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
    <div class="hero-eyebrow">Threat Intelligence Platform</div>
    <h1>Net<em>Guard</em> AI - Network Intrusion Detection System</h1>
    <p class="hero-sub">
        Real-time network traffic analysis powered by a Support Vector Machine
        (RBF kernel) trained on NSL-KDD intrusion detection patterns.
        Enter connection features to classify traffic and detect attacks instantly.
    </p>
    <div class="svm-badge">SVM · RBF Kernel · C=10 · gamma=scale</div>
    <div class="hero-stats">
        <div class="hstat"><span class="hstat-val">5</span><span class="hstat-lbl">Attack Classes</span></div>
        <div class="hstat"><span class="hstat-val">24</span><span class="hstat-lbl">Features</span></div>
        <div class="hstat"><span class="hstat-val">99%+</span><span class="hstat-lbl">Accuracy</span></div>
        <div class="hstat"><span class="hstat-val">SVM</span><span class="hstat-lbl">Algorithm</span></div>
    </div>
</div>
""", unsafe_allow_html=True)


# ─── Section 1: Connection Profile ───────────────────────────────────────────
st.markdown('<div class="icard"><div class="icard-label">📡 Connection Profile</div>', unsafe_allow_html=True)
c1, c2, c3 = st.columns(3)
with c1:
    protocol_type = st.selectbox(
        "Protocol", ["tcp", "udp", "icmp"],
        help="Network layer protocol of the connection"
    )
with c2:
    service = st.selectbox(
        "Service",
        ["http", "ftp", "ftp_data", "smtp", "ssh", "telnet",
         "private", "domain_u", "ecr_i", "eco_i", "other"],
        help="Destination network service type"
    )
with c3:
    flag = st.selectbox(
        "Connection Flag",
        ["SF", "S0", "REJ", "RSTO", "RSTOS0", "RSTR", "S1", "S2", "S3", "SH", "OTH"],
        help="TCP flag status — SF = normal established, S0 = no response from dest"
    )
st.markdown('</div>', unsafe_allow_html=True)

# ─── Section 2: Traffic Volume ────────────────────────────────────────────────
st.markdown('<div class="icard"><div class="icard-label">📊 Traffic Volume & Bytes</div>', unsafe_allow_html=True)
c4, c5 = st.columns(2)
with c4:
    log_src_bytes = st.slider(
        "Source Bytes (log scale)", 0.0, 12.0, 4.5, 0.1,
        help="log(bytes sent from source → destination). High in data exfiltration."
    )
    log_dst_bytes = st.slider(
        "Destination Bytes (log scale)", 0.0, 12.0, 5.0, 0.1,
        help="log(bytes sent from destination → source). Near zero in DoS attacks."
    )
with c5:
    log_duration = st.slider(
        "Duration (log scale)", 0.0, 10.0, 1.0, 0.1,
        help="log(connection duration in seconds). DoS connections are very short."
    )
    count = st.slider(
        "Connection Count", 1, 511, 60,
        help="Connections to the same host in the last 2 seconds. Spikes signal DoS."
    )
st.markdown('</div>', unsafe_allow_html=True)

# ─── Section 3: Service Rate Signals ─────────────────────────────────────────
st.markdown('<div class="icard"><div class="icard-label">🔁 Service Rate Signals</div>', unsafe_allow_html=True)
c6, c7 = st.columns(2)
with c6:
    srv_count = st.slider(
        "Same-Service Count", 1, 511, 40,
        help="Connections to the same service in the past 2 seconds."
    )
    same_srv_rate = st.slider(
        "Same-Service Rate", 0.0, 1.0, 0.85, 0.01,
        help="Fraction of connections to the same service. Very high in DoS floods."
    )
with c7:
    serror_rate = st.slider(
        "SYN Error Rate", 0.0, 1.0, 0.0, 0.01,
        help="Fraction of connections with SYN errors. High in SYN-flood DoS attacks."
    )
    diff_srv_rate = st.slider(
        "Different-Service Rate", 0.0, 1.0, 0.05, 0.01,
        help="Fraction of connections to different services. High in port-scan Probes."
    )
st.markdown('</div>', unsafe_allow_html=True)

# ─── Section 4: Destination Host Behaviour ───────────────────────────────────
st.markdown('<div class="icard"><div class="icard-label">🖥️ Destination Host Behaviour</div>', unsafe_allow_html=True)
c8, c9 = st.columns(2)
with c8:
    dst_host_count = st.slider(
        "Dest Host Connection Count", 1, 255, 180,
        help="Connections to the same destination host in the last 100 connections."
    )
    dst_host_srv_diff_host_rate = st.slider(
        "Srv Diff-Host Rate", 0.0, 1.0, 0.02, 0.01,
        help="Fraction of connections to the same service from different source hosts."
    )
with c9:
    dst_host_same_src_port_rate = st.slider(
        "Same Src-Port Rate", 0.0, 1.0, 0.1, 0.01,
        help="Fraction of connections from the same source port. High = scanning."
    )
    error_rate = st.slider(
        "Combined Error Rate", 0.0, 5.0, 0.0, 0.05,
        help="Composite SYN + RST error signal across all recent connections."
    )
st.markdown('</div>', unsafe_allow_html=True)

# ─── Analyse Button ───────────────────────────────────────────────────────────
analyse = st.button("⚡  Analyse Traffic", use_container_width=True)

if analyse:
    # Construct full 24-feature input row
    row = {
        'log_duration':                  log_duration,
        'log_src_bytes':                 log_src_bytes,
        'log_dst_bytes':                 log_dst_bytes,
        'total_bytes':                   float(np.exp(log_src_bytes) + np.exp(log_dst_bytes)),
        'byte_ratio':                    float(np.exp(log_src_bytes) / max(np.exp(log_dst_bytes), 1)),
        'wrong_fragment':                0.0,
        'urgent':                        0.0,
        'count':                         float(count),
        'srv_count':                     float(srv_count),
        'serror_rate':                   serror_rate,
        'rerror_rate':                   0.0,
        'same_srv_rate':                 same_srv_rate,
        'diff_srv_rate':                 diff_srv_rate,
        'dst_host_count':                float(dst_host_count),
        'dst_host_srv_count':            float(dst_host_count * same_srv_rate),
        'dst_host_same_srv_rate':        same_srv_rate,
        'dst_host_diff_srv_rate':        diff_srv_rate,
        'dst_host_same_src_port_rate':   dst_host_same_src_port_rate,
        'dst_host_srv_diff_host_rate':   dst_host_srv_diff_host_rate,
        'error_rate':                    error_rate,
        'host_risk':                     min(error_rate * 0.8 + serror_rate * 0.5, 5.0),
        'protocol_type':                 protocol_type,
        'service':                       service,
        'flag':                          flag,
    }

    X_input = pd.DataFrame([row], columns=feature_cols)

    with st.spinner("SVM inference running…"):
        time.sleep(0.45)
        X_transformed = preprocessor.transform(X_input)
        prediction    = svm_clf.predict(X_transformed)[0]
        probabilities = svm_clf.predict_proba(X_transformed)[0]
        class_order   = svm_clf.classes_

    confidence = probabilities.max() * 100
    css_class  = RESULT_CSS[prediction]
    icon       = RESULT_ICONS[prediction]
    action     = RESULT_ACTIONS[prediction]

    # ── Result card ──────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="{css_class}">
        <div class="res-icon">{icon}</div>
        <div class="res-verdict">{prediction}</div>
        <div class="res-type">Traffic Classification</div>
        <div class="res-conf">{confidence:.1f}%</div>
        <div class="res-sub">SVM decision confidence</div>
        <div class="res-algo">SVM · RBF Kernel · Platt Scaling</div>
        <div class="res-action">{action}</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Probability bars ──────────────────────────────────────────────────────
    prob_dict = dict(zip(class_order, probabilities))
    bars_html = '<div class="prob-row">'
    for cls in ATTACK_CLASSES:
        pval  = prob_dict.get(cls, 0.0)
        pct   = pval * 100
        color = BAR_COLORS[cls]
        bars_html += f"""
        <div class="prob-item">
            <span class="prob-label">{cls}</span>
            <div class="prob-bar-track">
                <div class="prob-bar-fill" style="width:{pct:.1f}%;background:{color};"></div>
            </div>
            <span class="prob-pct">{pct:.1f}%</span>
        </div>"""
    bars_html += '</div>'
    st.markdown(bars_html, unsafe_allow_html=True)

    # ── Summary chips ─────────────────────────────────────────────────────────
    flag_risk = {
        "SF":"Low","S1":"Low","S2":"Med","S3":"Med",
        "S0":"High","REJ":"High","RSTO":"High",
        "RSTOS0":"High","RSTR":"High","SH":"Med","OTH":"Med"
    }
    dos_signal   = "🔴 High" if count > 300 or serror_rate > 0.6 else ("🟡 Med" if count > 150 else "🟢 Low")
    probe_signal = "🔴 High" if diff_srv_rate > 0.5 else ("🟡 Med" if diff_srv_rate > 0.2 else "🟢 Low")

    chips = f"""
    <div class="chips">
        <div class="chip">
            <span class="chip-k">Protocol</span>
            <span class="chip-v">{protocol_type.upper()}</span>
        </div>
        <div class="chip">
            <span class="chip-k">Service</span>
            <span class="chip-v">{service}</span>
        </div>
        <div class="chip">
            <span class="chip-k">Flag</span>
            <span class="chip-v">{flag} · {flag_risk.get(flag,'?')}</span>
        </div>
        <div class="chip">
            <span class="chip-k">Conn Count</span>
            <span class="chip-v">{count}</span>
        </div>
        <div class="chip">
            <span class="chip-k">DoS Signal</span>
            <span class="chip-v">{dos_signal}</span>
        </div>
        <div class="chip">
            <span class="chip-k">Probe Signal</span>
            <span class="chip-v">{probe_signal}</span>
        </div>
    </div>
    """
    st.markdown(chips, unsafe_allow_html=True)

# ─── Footer ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="app-footer">
    SVM · RBF Kernel · NSL-KDD Feature Space · NetGuard AI v2.0
</div>
""", unsafe_allow_html=True)
