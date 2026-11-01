# SevenEngine V3 Flash - Cloud Scan

Cloud inference front-end for the SevenEngine static PE detection engine.

## Layout

    SevenEngineV3Flash\
    |- SevenEngine.py       engine core (untouched)
    |- Model\SevenML.onnx   LightGBM booster (1.8 MB)
    |- render.yaml          Render blueprint
    +- cloud\
       |- app.py            Flask service (pages + REST API)
       |- Procfile          gunicorn start command
       |- requirements.txt  python deps
       |- runtime.txt       python 3.13
       |- static\logo.svg   shield logo
       +- templates\        index / scan / tasks / about

## Pages

| Route   | Purpose                          |
|---------|----------------------------------|
| /       | Overview, live engine status     |
| /scan   | Single-file scan, gauge verdict  |
| /tasks  | Batch upload (32 files), polling |
| /about  | Engine identity, pipeline docs   |

## REST API

| Method | Path             | Body / Params              | Returns                                   |
|--------|------------------|----------------------------|-------------------------------------------|
| GET    | /api/health      | -                          | engine status, feature_dim, threshold, uptime |
| GET    | /api/stats       | -                          | totals, malware/clean/error, avg ms, cache size |
| GET    | /api/history     | ?limit=100                 | recent scans (ring buffer, 500 max)       |
| POST   | /api/scan        | multipart file=<binary>    | status, score, md5, sha256, ms            |
| POST   | /api/scan        | (repeat uploads)           | cached=true when sha256 already seen      |
| POST   | /api/scan/text   | multipart file=<binary>    | plain text "Return:ML:... / Score:N"      |
| POST   | /api/scan/base64 | JSON {name, data(b64)}     | same as /api/scan                         |
| POST   | /api/scan/hash   | JSON {sha256 or md5}       | cache hit verdict or "unknown"            |
| POST   | /api/scan/batch  | multipart files=<n> (<=32) | task_id for polling                       |
| GET    | /api/task/<id>   | -                          | task progress + per-file results          |

All responses carry `Access-Control-Allow-Origin: *`.

## Verdicts

- score >= 85 -> Malware
- score < 85  -> Clean
- not a PE    -> Error / N/A

## Run locally

    cd cloud
    pip install -r requirements.txt
    python app.py            # listens on :8000

## Deploy (Render)

1. Push this folder to a GitHub repo (model is 1.8 MB, well under limits).
2. Render Dashboard -> New + -> Blueprint -> pick the repo.
3. render.yaml defines a free web service rooted at `cloud/` with
   health check `/api/health`. First deploy builds in ~3 minutes.

Free plan notes: instance sleeps after 15 min idle (first request wakes it,
about 30 s), 750 instance-hours per month, no persistent disk (history,
stats and hash cache reset on restart).
