"""
PDF Malware Scanner - Microservice
Exposes /scan endpoint called by Kestra.
Extracts all 25 features (20 raw + 5 engineered) and returns prediction.
"""

import os, re, math, pickle, logging, warnings, sqlite3, numpy as np
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/app/model.pkl"))  # retrained balanced model
DB_PATH    = Path(os.getenv("DB_PATH",    "/app/data/scans.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── Load model ────────────────────────────────────────────────────────────────
try:
    with open(MODEL_PATH, "rb") as f:
        MODEL = pickle.load(f)
    log.info("Model loaded — expects %d features", MODEL.n_features_in_)
except Exception as e:
    log.error("Could not load model: %s", e)
    MODEL = None

# ── Init SQLite ───────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            filename   TEXT,
            prediction TEXT,
            threat     TEXT,
            probability REAL,
            features   TEXT,
            scanned_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ── Feature extraction ────────────────────────────────────────────────────────
def extract_features(pdf_bytes: bytes, filename: str) -> dict:
    if not pdf_bytes.startswith(b"%PDF"):
        raise ValueError("Not a valid PDF file.")

    def count(kw): return pdf_bytes.count(kw)
    def has(kw):   return 1 if kw in pdf_bytes else 0

    pdfsize  = round(len(pdf_bytes) / 1024, 3)
    pages    = len(re.findall(rb"/Type\s*/Page[^s]", pdf_bytes)) or max(1, count(b"/Page"))
    title_m  = re.search(rb"/Title\s*\(([^)]*)\)", pdf_bytes)
    title_ch = len(title_m.group(1)) if title_m else 0
    images   = count(b"/Subtype /Image") + count(b"/Subtype/Image")

    obj        = count(b" obj")
    endobj     = count(b"endobj")
    stream     = count(b"stream")
    endstream  = count(b"endstream")
    xref       = count(b"xref")
    trailer    = count(b"trailer")
    startxref  = count(b"startxref")
    obj_stm    = count(b"/ObjStm")

    js             = has(b"/JS")
    obs_js         = has(b"/JS ")
    javascript     = has(b"/JavaScript")
    obs_javascript = has(b"/JavaScript ")
    open_action    = has(b"/OpenAction")
    obs_open       = has(b"/OpenAction ")
    acroform       = has(b"/AcroForm")
    obs_acro       = has(b"/AcroForm ")

    ratio = obj / endobj if endobj > 0 else 0.0
    if not math.isfinite(ratio): ratio = 1e10

    return {
        "pdfsize": pdfsize, "pages": pages, "title characters": title_ch,
        "images": images, "obj": obj, "endobj": endobj, "stream": stream,
        "endstream": endstream, "xref": xref, "trailer": trailer,
        "startxref": startxref, "ObjStm": obj_stm,
        "JS": js, "OBS_JS": obs_js, "Javascript": javascript,
        "OBS_Javascript": obs_javascript, "OpenAction": open_action,
        "OBS_OpenAction": obs_open, "Acroform": acroform, "OBS_Acroform": obs_acro,
        # engineered
        "obj_to_endobj_ratio": ratio,
        "has_xref_table": 1 if xref > 0 else 0,
        "trailer_size_ratio": round(trailer / pdfsize, 6) if pdfsize > 0 else 0.0,
        "has_javascript": 1 if (js or javascript) else 0,
        "has_suspicious_obsolete_elements": 1 if (obs_js or obs_javascript or obs_open or obs_acro) else 0,
    }

def smart_verdict(prob: float, features: dict):
    """
    Smart verdict combining model probability + actual suspicious features.
    The training dataset (Evasive-PDF) contains only 1-page PDFs as benign,
    so multi-page normal PDFs get high raw probability.
    We require suspicious PDF features (JS, OpenAction, ObjStm) for HIGH/MEDIUM.
    """
    has_js         = features.get("has_javascript", 0) == 1
    has_openaction = features.get("OpenAction", 0) == 1
    has_objstm     = features.get("ObjStm", 0) > 0
    has_obs        = features.get("has_suspicious_obsolete_elements", 0) == 1
    has_suspicious = has_js or has_openaction or has_objstm or has_obs

    if prob >= 0.95 and has_suspicious:
        return "Malicious", "HIGH"
    elif prob >= 0.80 and has_suspicious:
        return "Malicious", "MEDIUM"
    elif prob >= 0.95 and not has_suspicious:
        # High model score but no suspicious features = likely dataset bias
        return "Suspicious", "LOW"
    elif prob >= 0.70 and has_suspicious:
        return "Suspicious", "MEDIUM"
    else:
        return "Benign", "LOW"

def threat_level(prob: float) -> str:
    return "HIGH" if prob >= 0.85 else ("MEDIUM" if prob >= 0.55 else "LOW")

def save_result(filename, prediction, threat, probability, features):
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (filename, prediction, threat, probability, features, scanned_at) VALUES (?,?,?,?,?,?)",
        (filename, prediction, threat, probability, json.dumps(features), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "model_loaded": MODEL is not None})

@app.route("/scan", methods=["POST"])
def scan():
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 503
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400

    file = request.files["file"]
    if not file.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only PDF files accepted"}), 400

    pdf_bytes = file.read()
    try:
        features = extract_features(pdf_bytes, file.filename)
    except ValueError as e:
        return jsonify({"error": str(e)}), 422

    vec   = np.array(list(features.values()), dtype=float).reshape(1, -1)
    pred  = int(MODEL.predict(vec)[0])
    prob  = round(float(MODEL.predict_proba(vec)[0][1]), 4)
    label, threat = smart_verdict(prob, features)

    save_result(file.filename, label, threat, prob, features)
    log.info("%s → %s | %s | %.1f%%", file.filename, label, threat, prob * 100)

    return jsonify({
        "filename":     file.filename,
        "prediction":   label,
        "threat_level": threat,
        "probability":  prob,
        "is_malicious": label == "Malicious",
        "features":     features,
        "scanned_at":   datetime.utcnow().isoformat(),
    })

@app.route("/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT filename, prediction, threat, probability, scanned_at FROM scans ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([
        {"filename": r[0], "prediction": r[1], "threat": r[2],
         "probability": r[3], "scanned_at": r[4]} for r in rows
    ])

@app.route("/stats")
def stats():
    conn = sqlite3.connect(DB_PATH)
    total     = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    malicious = conn.execute("SELECT COUNT(*) FROM scans WHERE prediction='Malicious'").fetchone()[0]
    high      = conn.execute("SELECT COUNT(*) FROM scans WHERE threat='HIGH'").fetchone()[0]
    conn.close()
    return jsonify({
        "total_scans": total,
        "malicious":   malicious,
        "benign":      total - malicious,
        "high_threat": high,
        "malicious_rate": round(malicious / total * 100, 1) if total else 0,
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)), debug=False)
