import os
import sys
import time
import uuid
import base64
import hashlib
import threading
import logging

from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from SevenEngine import load_model, scan_bytes, is_pe, FEATURE_DIM, MALWARE_THRESHOLD

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sevenengine")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024

MODEL = None
MODEL_LOCK = threading.Lock()
START_TIME = time.time()
MAX_FILE_BYTES = 300 * 1024 * 1024


HISTORY = []
HISTORY_LOCK = threading.Lock()
HISTORY_MAX = 500
HASH_CACHE = {}
HASH_CACHE_LOCK = threading.Lock()
HASH_CACHE_MAX = 10000

STATS = {"total": 0, "malware": 0, "clean": 0, "error": 0, "ms_sum": 0}
STATS_LOCK = threading.Lock()


def _record(name, r, size):
    entry = {"name": name, "status": r["status"], "score": r["score"],
             "size": size, "ms": r["ms"], "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    with HISTORY_LOCK:
        HISTORY.append(entry)
        if len(HISTORY) > HISTORY_MAX:
            del HISTORY[:len(HISTORY) - HISTORY_MAX]
    with STATS_LOCK:
        STATS["total"] += 1
        STATS[r["status"] if r["status"] in ("malware", "clean", "error") else "error"] += 1
        STATS["ms_sum"] += r["ms"]
    return entry


def get_model():
    global MODEL
    if MODEL is None:
        with MODEL_LOCK:
            if MODEL is None:
                log.info("loading model from %s", os.path.join(BASE_DIR, "Model", "SevenML.onnx"))
                MODEL = load_model()
                log.info("model ready")
    return MODEL


@app.before_request
def _warm():
    try:
        get_model()
    except Exception as e:
        log.error("model warm failed: %s", e)


@app.route("/")
def page_index():
    return render_template("index.html")


@app.route("/scan")
def page_scan():
    return render_template("scan.html")


@app.route("/about")
def page_about():
    return render_template("about.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(BASE_DIR, "static"), filename)


def _classify(data):
    t0 = time.time()
    model = get_model()
    if not is_pe(data):
        return {"status": "error", "score": None, "label": "Not a PE file", "ms": 0}
    status, score = scan_bytes(data, model)
    ms = int((time.time() - t0) * 1000)
    if status == "malware":
        label = "Malware"
    elif status == "clean":
        label = "Clean"
    else:
        label = "Error"
    return {"status": status, "score": score, "label": label, "ms": ms}


@app.route("/api/health")
def api_health():
    ok = False
    try:
        get_model()
        ok = True
    except Exception:
        ok = False
    return jsonify({
        "ok": ok,
        "engine": "SevenEngine V3 Flash",
        "feature_dim": FEATURE_DIM,
        "threshold": MALWARE_THRESHOLD,
        "uptime_sec": int(time.time() - START_TIME),
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "missing file field"}), 400
    f = request.files["file"]
    if not f or f.filename == "":
        return jsonify({"ok": False, "error": "empty filename"}), 400
    data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        return jsonify({"ok": False, "error": "file too large (>300MB)"}), 413
    name = secure_filename(f.filename) or "upload.bin"
    sha = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    with HASH_CACHE_LOCK:
        cached = HASH_CACHE.get(sha)
    if cached is not None:
        r = dict(cached)
        r["cached"] = True
    else:
        r = _classify(data)
        r["sha256"] = sha
        r["md5"] = md5
        with HASH_CACHE_LOCK:
            if len(HASH_CACHE) >= HASH_CACHE_MAX:
                HASH_CACHE.pop(next(iter(HASH_CACHE)))
            HASH_CACHE[sha] = dict(r)
    r.update({"ok": True, "name": name, "size": len(data)})
    if r.get("status") in ("malware", "clean"):
        _record(name, r, len(data))
    return jsonify(r)


@app.route("/api/stats")
def api_stats():
    with STATS_LOCK:
        s = dict(STATS)
    total = s["total"]
    avg = round(s["ms_sum"] / total, 1) if total else 0
    return jsonify({
        "ok": True,
        "total": total,
        "malware": s["malware"],
        "clean": s["clean"],
        "error": s["error"],
        "avg_ms": avg,
        "cache_size": len(HASH_CACHE),
        "engine": "SevenEngine V3 Flash",
        "uptime_sec": int(time.time() - START_TIME),
    })


@app.route("/api/history")
def api_history():
    limit = min(int(request.args.get("limit", 100)), HISTORY_MAX)
    with HISTORY_LOCK:
        items = list(HISTORY[-limit:])
    items.reverse()
    return jsonify({"ok": True, "count": len(items), "items": items})


@app.route("/api/scan/hash", methods=["POST"])
def api_scan_hash():
    j = request.get_json(silent=True) or {}
    h = (j.get("sha256") or j.get("md5") or "").strip().lower()
    if not h or len(h) not in (32, 64) or not all(c in "0123456789abcdef" for c in h):
        return jsonify({"ok": False, "error": "provide sha256 or md5 hex"}), 400
    with HASH_CACHE_LOCK:
        for r in HASH_CACHE.values():
            if r.get("sha256") == h or r.get("md5") == h:
                out = dict(r)
                out.update({"ok": True, "lookup": "cache-hit"})
                return jsonify(out)
    return jsonify({"ok": True, "lookup": "unknown", "found": False,
                    "hint": "hash not seen on this node; upload the sample to /api/scan"}), 200


@app.route("/api/scan/base64", methods=["POST"])
def api_scan_base64():
    j = request.get_json(silent=True) or {}
    b64 = j.get("data") or ""
    name = secure_filename(j.get("name") or "sample.bin")
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception:
        return jsonify({"ok": False, "error": "invalid base64"}), 400
    if not raw:
        return jsonify({"ok": False, "error": "empty payload"}), 400
    if len(raw) > MAX_FILE_BYTES:
        return jsonify({"ok": False, "error": "file too large (>16MB)"}), 413
    r = _classify(raw)
    r.update({"ok": True, "name": name, "size": len(raw)})
    if r.get("status") in ("malware", "clean"):
        _record(name, r, len(raw))
    return jsonify(r)


@app.route("/api/scan/text", methods=["POST"])
def api_scan_text():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "missing file field"}), 400
    f = request.files["file"]
    data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        return "Return:Error\nScore:None\n", 413
    r = _classify(data)
    if r["status"] == "malware":
        body = "Return:ML:Gen.Malware\nScore:%s\n" % r["score"]
    elif r["status"] == "clean":
        body = "Return:ML:Clean\nScore:%s\n" % r["score"]
    else:
        body = "Return:Error\nScore:None\n"
    resp = app.response_class(body, mimetype="text/plain")
    resp.headers["X-SevenEngine-Status"] = r["status"] or "error"
    return resp


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.errorhandler(413)
def too_large(e):
    return jsonify({"ok": False, "error": "payload too large"}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    get_model()
    app.run(host="0.0.0.0", port=port, threaded=True)
