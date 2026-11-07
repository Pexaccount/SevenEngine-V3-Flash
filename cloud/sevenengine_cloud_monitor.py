# -*- coding: utf-8 -*-
"""
SevenEngine Cloud 服务状态监控面板（详情增强版）
==================================================
单文件 Flask Web UI：
  - 服务状态页签：并发探活全部端点，每项可展开查看原始 JSON 响应
  - 扫描历史页签：/api/history 全量列表（时间/文件/大小/分数/判定/耗时），
    支持判定筛选与文件名搜索

用法：
  python sevenengine_cloud_monitor.py
  浏览器打开 http://127.0.0.1:8765
依赖：flask（pip install flask）
"""

import base64
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

DEFAULT_BASE = "https://sevenengine-cloud.onrender.com"
PROBE_TIMEOUT = 20          # 单端点超时（秒）
ZERO_SHA256 = "0" * 64      # hash 探针：任何节点都不会见过的哈希


# --------------------------------------------------------------------------
# HTTP 探针
# --------------------------------------------------------------------------

def http_probe(base: str, method: str, path: str, payload=None):
    """请求一个端点，返回 (http_status, ms, body_dict_or_text, error)。"""
    url = base.rstrip("/") + path
    headers = {"User-Agent": "SevenEngine-Cloud-Monitor/1.1"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
            body = resp.read(262144).decode("utf-8", "replace")
            return resp.status, (time.time() - t0) * 1000, body, None
    except urllib.error.HTTPError as e:
        body = e.read(262144).decode("utf-8", "replace")
        return e.code, (time.time() - t0) * 1000, body, None
    except Exception as e:  # DNS/超时/连接拒绝等
        return None, (time.time() - t0) * 1000, "", f"{type(e).__name__}: {e}"


def try_json(body: str):
    try:
        return json.loads(body)
    except Exception:
        return None


# --------------------------------------------------------------------------
# 各端点检查逻辑（raw 字段 = 原始响应，前端展开显示）
# --------------------------------------------------------------------------

def check_webui(base):
    code, ms, body, err = http_probe(base, "GET", "/")
    ok = code == 200 and "SevenEngine" in body
    return {"name": "Web UI 入口", "method": "GET", "path": "/",
            "ok": ok, "http": code, "ms": ms, "error": err,
            "detail": "页面可达" if ok else (f"HTTP {code}" if code else "不可达"),
            "raw": {"title_snippet": body[body.find("<title>") + 7: body.find("</title>")] if "<title>" in body else None,
                    "bytes": len(body)}}


def check_docs(base):
    code, ms, body, err = http_probe(base, "GET", "/docs")
    ok = code == 200 and "API" in body
    return {"name": "API 参考页", "method": "GET", "path": "/docs",
            "ok": ok, "http": code, "ms": ms, "error": err,
            "detail": "文档可达" if ok else (f"HTTP {code}" if code else "不可达"),
            "raw": {"bytes": len(body)}}


def check_health(base):
    code, ms, body, err = http_probe(base, "GET", "/api/health")
    j = try_json(body)
    ok = code == 200 and bool(j and j.get("ok"))
    detail = "不可达" if code is None else f"HTTP {code}"
    if ok:
        detail = (f'{j.get("engine", "?")} · 维度 {j.get("feature_dim", "?")} · '
                  f'阈值 {j.get("threshold", "?")} · 运行 {j.get("uptime_sec", 0)}s')
    return {"name": "引擎健康检查", "method": "GET", "path": "/api/health",
            "ok": ok, "http": code, "ms": ms, "error": err, "detail": detail,
            "raw": j if j is not None else body[:500]}


def check_stats(base):
    code, ms, body, err = http_probe(base, "GET", "/api/stats")
    j = try_json(body)
    ok = code == 200 and bool(j and j.get("ok"))
    detail = "不可达" if code is None else f"HTTP {code}"
    if ok:
        detail = (f'累计 {j.get("total", 0)} 次（干净 {j.get("clean", 0)} / '
                  f'恶意 {j.get("malware", 0)} / 错误 {j.get("error", 0)}）· '
                  f'平均 {j.get("avg_ms", 0):.0f}ms')
    return {"name": "扫描统计", "method": "GET", "path": "/api/stats",
            "ok": ok, "http": code, "ms": ms, "error": err, "detail": detail,
            "raw": j if j is not None else body[:500]}


def check_history(base):
    code, ms, body, err = http_probe(base, "GET", "/api/history")
    j = try_json(body)
    ok = code == 200
    detail = "不可达" if code is None else f"HTTP {code}"
    raw = j if j is not None else body[:500]
    if ok and isinstance(j, dict):
        n = j.get("count", len(j.get("items", [])))
        detail = f"{n} 条历史记录"
        raw = j
    elif ok and isinstance(j, list):
        detail = f"{len(j)} 条历史记录"
    return {"name": "历史记录", "method": "GET", "path": "/api/history",
            "ok": ok, "http": code, "ms": ms, "error": err, "detail": detail,
            "raw": raw}


def check_scan_hash(base):
    """hash 探针：预期 200 + lookup=unknown（节点没见过零哈希 = 链路正常）。"""
    code, ms, body, err = http_probe(base, "POST", "/api/scan/hash",
                                     {"sha256": ZERO_SHA256})
    j = try_json(body)
    ok = code == 200 and bool(j and j.get("ok"))
    detail = "不可达" if code is None else f"HTTP {code}"
    if ok:
        detail = f'链路正常 · lookup={j.get("lookup", "?")}'
    return {"name": "Hash 查询链路", "method": "POST", "path": "/api/scan/hash",
            "ok": ok, "http": code, "ms": ms, "error": err, "detail": detail,
            "raw": j if j is not None else body[:500]}


def check_scan_base64(base):
    """base64 探针：上传 4 字节假数据，预期 200 + label='Not a PE file'（非 PE 被正确拒判 = 分析引擎活着）。"""
    blob = base64.b64encode(b"\x00wb\x01").decode()
    code, ms, body, err = http_probe(base, "POST", "/api/scan/base64",
                                     {"name": "probe.bin", "data": blob})
    j = try_json(body)
    ok = code == 200 and bool(j and j.get("ok"))
    detail = "不可达" if code is None else f"HTTP {code}"
    if ok:
        detail = f'分析引擎正常 · 判定 "{j.get("label", "?")}"'
    return {"name": "Base64 扫描链路", "method": "POST", "path": "/api/scan/base64",
            "ok": ok, "http": code, "ms": ms, "error": err, "detail": detail,
            "raw": j if j is not None else body[:500]}


CHECKS = [check_webui, check_docs, check_health, check_stats,
          check_history, check_scan_hash, check_scan_base64]


def run_all_checks(base: str):
    with ThreadPoolExecutor(max_workers=len(CHECKS)) as pool:
        results = list(pool.map(lambda fn: fn(base), CHECKS))
    all_ok = all(r["ok"] for r in results)
    return {
        "base": base,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "all_ok": all_ok,
        "ok_count": sum(1 for r in results if r["ok"]),
        "total": len(results),
        "results": results,
    }


# --------------------------------------------------------------------------
# Flask 路由
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(PAGE_HTML)


@app.route("/api/check")
def api_check():
    base = (request.args.get("base") or DEFAULT_BASE).strip()
    return jsonify(run_all_checks(base))


@app.route("/api/history")
def api_history():
    """历史记录代理：全量转发云端 /api/history。"""
    base = (request.args.get("base") or DEFAULT_BASE).strip().rstrip("/")
    code, ms, body, err = http_probe(base, "GET", "/api/history")
    j = try_json(body)
    if j is not None:
        return jsonify({"http": code, "ms": ms, "data": j, "error": err})
    return jsonify({"http": code, "ms": ms, "data": None,
                    "error": err or body[:300]})


# --------------------------------------------------------------------------
# 前端页面（内嵌模板，浅色专业风，双页签 + 详情展开）
# --------------------------------------------------------------------------

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SevenEngine Cloud · 服务状态监控</title>
<style>
  :root{
    --bg:#f5f7fa; --panel:#ffffff; --border:#e3e8ef; --text:#1f2937;
    --muted:#6b7280; --accent:#2563eb; --accent-soft:#eff4ff;
    --ok:#16a34a; --ok-soft:#dcfce7; --bad:#dc2626; --bad-soft:#fee2e2;
    --warn:#d97706; --warn-soft:#fef3c7;
    --mono:Consolas,"Courier New",monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px;padding:28px}
  .wrap{max-width:1080px;margin:0 auto}
  header{display:flex;align-items:center;gap:12px;margin-bottom:16px}
  header h1{font-size:20px;font-weight:600}
  header .logo{width:34px;height:34px;border-radius:8px;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:15px}
  .toolbar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
  .toolbar input[type=text]{flex:1;min-width:260px;padding:8px 12px;border:1px solid var(--border);border-radius:8px;font-family:var(--mono);font-size:12.5px;background:var(--panel)}
  .toolbar input:focus{outline:none;border-color:var(--accent)}
  button{padding:8px 16px;border:none;border-radius:8px;background:var(--accent);color:#fff;font-size:13px;cursor:pointer}
  button:hover{opacity:.9}
  button:disabled{opacity:.5;cursor:wait}
  label.auto{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12.5px;user-select:none;cursor:pointer}
  .tabs{display:flex;gap:6px;margin-bottom:14px}
  .tabs .tab{padding:8px 18px;border-radius:8px 8px 0 0;background:transparent;color:var(--muted);font-size:13.5px;border:none;cursor:pointer;border-bottom:2px solid transparent}
  .tabs .tab.active{color:var(--accent);background:var(--panel);border-bottom-color:var(--accent);font-weight:600}
  .banner{padding:14px 18px;border-radius:10px;margin-bottom:16px;font-size:14.5px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
  .banner.ok{background:var(--ok-soft);color:var(--ok);border:1px solid #bbf7d0}
  .banner.bad{background:var(--bad-soft);color:var(--bad);border:1px solid #fecaca}
  .banner small{font-weight:400;font-size:12px;opacity:.85}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
  table{width:100%;border-collapse:collapse}
  th{background:#f8fafc;text-align:left;padding:10px 14px;font-size:12px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border)}
  td{padding:11px 14px;border-bottom:1px solid #eef1f5;font-size:13px;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tbody tr.click{cursor:pointer}
  tbody tr.click:hover td{background:#fafbfc}
  tr.detailrow td{background:#f8fafc;padding:0}
  .ep{font-family:var(--mono);font-size:12.5px}
  .ep small{color:var(--muted);font-size:11px;margin-left:6px}
  .caret{display:inline-block;transition:transform .15s;margin-right:6px;color:var(--muted);font-size:11px}
  tr.open .caret{transform:rotate(90deg)}
  .pill{display:inline-block;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600}
  .pill.ok{background:var(--ok-soft);color:var(--ok)}
  .pill.bad{background:var(--bad-soft);color:var(--bad)}
  .pill.warn{background:var(--warn-soft);color:var(--warn)}
  .ms{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
  .ms.fast{color:var(--ok)}
  .ms.slow{color:var(--warn)}
  .detail{font-size:12.5px;color:var(--muted)}
  .detail.err{color:var(--bad);font-family:var(--mono);font-size:11.5px}
  .rawwrap{max-height:340px;overflow:auto;padding:14px 18px}
  .rawwrap pre{font-family:var(--mono);font-size:12px;line-height:1.5;color:#334155;white-space:pre-wrap;word-break:break-all}
  .filters{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
  .filters .fbtn{padding:6px 14px;border:1px solid var(--border);border-radius:99px;background:var(--panel);color:var(--muted);font-size:12.5px}
  .filters .fbtn.active{border-color:var(--accent);color:var(--accent);background:var(--accent-soft);font-weight:600}
  .filters input{flex:1;min-width:200px;padding:8px 12px;border:1px solid var(--border);border-radius:8px;font-size:12.5px}
  .filters input:focus{outline:none;border-color:var(--accent)}
  .scorebar{display:inline-flex;align-items:center;gap:8px}
  .scorebar .bar{width:64px;height:6px;border-radius:3px;background:#e5e7eb;overflow:hidden}
  .scorebar .bar i{display:block;height:100%;border-radius:3px}
  .fname{font-family:var(--mono);font-size:12.5px;word-break:break-all}
  .sz{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .foot{margin-top:14px;color:var(--muted);font-size:12px;text-align:center}
  .empty{text-align:center;padding:40px;color:var(--muted)}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:r .7s linear infinite;vertical-align:-2px;margin-right:6px}
  @keyframes r{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">SE</div>
    <h1>SevenEngine Cloud · 服务状态监控</h1>
  </header>

  <div class="toolbar">
    <input type="text" id="base" placeholder="服务地址，默认 https://sevenengine-cloud.onrender.com">
    <button id="btn" onclick="refreshAll()">立即检查</button>
    <label class="auto"><input type="checkbox" id="auto"> 每 30 秒自动刷新</label>
  </div>

  <div class="tabs">
    <button class="tab active" data-tab="svc" onclick="switchTab('svc')">服务状态</button>
    <button class="tab" data-tab="hist" onclick="switchTab('hist')">扫描历史</button>
  </div>

  <div id="banner" class="banner ok" style="display:none"></div>

  <!-- 页签 1：服务状态 -->
  <div id="tab-svc">
    <div class="card">
      <table>
        <thead><tr><th style="width:26%">服务 / 端点</th><th style="width:10%">状态</th><th style="width:8%">HTTP</th><th style="width:9%">耗时</th><th>详情（点击行展开原始响应）</th></tr></thead>
        <tbody id="rows"><tr><td colspan="5" class="empty">点击「立即检查」开始探测</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- 页签 2：扫描历史 -->
  <div id="tab-hist" style="display:none">
    <div class="filters">
      <button class="fbtn active" data-f="all" onclick="setFilter('all')">全部</button>
      <button class="fbtn" data-f="clean" onclick="setFilter('clean')">干净</button>
      <button class="fbtn" data-f="malware" onclick="setFilter('malware')">恶意</button>
      <button class="fbtn" data-f="error" onclick="setFilter('error')">错误</button>
      <input type="text" id="search" placeholder="按文件名搜索…" oninput="renderHistory()">
      <span class="detail" id="histcount"></span>
    </div>
    <div class="card">
      <table>
        <thead><tr><th style="width:17%">时间</th><th style="width:30%">文件名</th><th style="width:10%">大小</th><th style="width:18%">分数</th><th style="width:10%">判定</th><th>耗时</th></tr></thead>
        <tbody id="histrows"><tr><td colspan="6" class="empty">切换到此页签或点击「立即检查」加载</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="foot">探针不含真实样本 · hash 用零哈希 · base64 用 4 字节假数据（预期拒判） · 历史数据来自云端 /api/history</div>
</div>

<script>
let timer = null;
let lastData = null;
let histData = null;      // {items:[...], count}
let histFilter = 'all';
let base = '';
const $ = id => document.getElementById(id);

function msClass(v){ return v==null ? '' : (v<300 ? 'fast' : v<1500 ? '' : 'slow'); }
function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':String(s); return d.innerHTML; }
function fmtSize(n){
  if(n==null) return '—';
  if(n<1024) return n+' B';
  if(n<1048576) return (n/1024).toFixed(1)+' KB';
  return (n/1048576).toFixed(2)+' MB';
}
function scoreColor(score, status){
  if(status==='error') return '#94a3b8';
  if(score==null) return '#94a3b8';
  if(score>=85) return '#dc2626';
  if(score>=40) return '#d97706';
  return '#16a34a';
}

/* ---------- 页签 ---------- */
function switchTab(t){
  document.querySelectorAll('.tabs .tab').forEach(b=>b.classList.toggle('active', b.dataset.tab===t));
  $('tab-svc').style.display = t==='svc' ? '' : 'none';
  $('tab-hist').style.display = t==='hist' ? '' : 'none';
  if(t==='hist') loadHistory();
}

/* ---------- 服务状态 ---------- */
async function refreshSvc(){
  const btn = $('btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>检查中…';
  try{
    const q = base ? '?base=' + encodeURIComponent(base) : '';
    const r = await fetch('/api/check' + q);
    const d = await r.json();
    lastData = d;
    base = d.base;
    $('base').value = d.base;
    localStorage.setItem('se_base', d.base);
    renderSvc(d);
  }catch(e){
    const b = $('banner');
    b.style.display='flex'; b.className='banner bad';
    b.innerHTML='监控面板请求失败：' + esc(String(e));
  }finally{
    btn.disabled = false;
    btn.textContent = '立即检查';
  }
}

function renderSvc(d){
  const b = $('banner');
  b.style.display = 'flex';
  if(d.all_ok){
    b.className='banner ok';
    b.innerHTML = `<span>✔ 全部 ${d.total} 项服务正常</span><small>检查于 ${d.checked_at}</small>`;
  }else{
    b.className='banner bad';
    b.innerHTML = `<span>✘ ${d.total - d.ok_count} / ${d.total} 项异常</span><small>检查于 ${d.checked_at}</small>`;
  }
  $('rows').innerHTML = d.results.map((r,i) => svcRow(r,i)).join('');
  d.results.forEach((r,i)=>{ if(r.raw!==undefined) bindToggle(i); });
}

function svcRow(r,i){
  return `
  <tr class="click" id="row${i}" onclick="toggleDetail(${i})">
    <td class="ep"><span class="caret">▶</span>${esc(r.name)}<small>${r.method} ${esc(r.path)}</small></td>
    <td><span class="pill ${r.ok?'ok':'bad'}">${r.ok?'正常':'异常'}</span></td>
    <td class="ms">${r.http ?? '—'}</td>
    <td class="ms ${msClass(r.ms)}">${r.ms==null?'—':r.ms.toFixed(0)+'ms'}</td>
    <td class="detail ${r.ok?'':'err'}">${esc(r.detail)}${r.error?' · '+esc(r.error):''}</td>
  </tr>
  <tr class="detailrow" id="drow${i}" style="display:none"><td colspan="5">
    <div class="rawwrap"><pre>${esc(JSON.stringify(r.raw, null, 2))}</pre></div>
  </td></tr>`;
}
function toggleDetail(i){
  const d = $('drow'+i);
  const open = d.style.display==='none';
  d.style.display = open ? '' : 'none';
  $('row'+i).classList.toggle('open', open);
}
function bindToggle(i){}

/* ---------- 扫描历史 ---------- */
async function loadHistory(){
  $('histrows').innerHTML = '<tr><td colspan="6" class="empty"><span class="spin" style="border-color:#dbeafe;border-top-color:var(--accent)"></span>加载历史记录…</td></tr>';
  try{
    const q = base ? '?base=' + encodeURIComponent(base) : '';
    const r = await fetch('/api/history' + q);
    const d = await r.json();
    if(d.data && Array.isArray(d.data.items)){
      histData = d.data;
    }else{
      histData = {count:0, items:[]};
      $('histrows').innerHTML = `<tr><td colspan="6" class="empty detail err">加载失败：${esc(d.error||('HTTP '+d.http))}</td></tr>`;
    }
  }catch(e){
    histData = {count:0, items:[]};
    $('histrows').innerHTML = `<tr><td colspan="6" class="empty detail err">加载失败：${esc(String(e))}</td></tr>`;
  }
  renderHistory();
}

function setFilter(f){
  histFilter = f;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.toggle('active', b.dataset.f===f));
  renderHistory();
}

function renderHistory(){
  if(!histData) return;
  const kw = $('search').value.trim().toLowerCase();
  let items = histData.items.filter(it =>
    (histFilter==='all' || (it.status||'').toLowerCase()===histFilter) &&
    (!kw || (it.name||'').toLowerCase().includes(kw))
  );
  $('histcount').textContent = `显示 ${items.length} / ${histData.count ?? histData.items.length} 条`;
  if(!items.length){
    $('histrows').innerHTML = '<tr><td colspan="6" class="empty">无匹配记录</td></tr>';
    return;
  }
  $('histrows').innerHTML = items.map(it=>{
    const st = (it.status||'unknown').toLowerCase();
    const pill = st==='clean' ? '<span class="pill ok">clean</span>'
               : st==='malware' ? '<span class="pill bad">malware</span>'
               : st==='error' ? '<span class="pill warn">error</span>'
               : `<span class="pill warn">${esc(st)}</span>`;
    const c = scoreColor(it.score, st);
    return `
    <tr>
      <td class="sz">${esc(it.time)}</td>
      <td class="fname">${esc(it.name)}</td>
      <td class="sz">${fmtSize(it.size)}</td>
      <td><span class="scorebar"><span class="sz" style="color:${c};font-weight:600">${it.score ?? '—'}</span><span class="bar"><i style="width:${Math.min(it.score??0,100)}%;background:${c}"></i></span></span></td>
      <td>${pill}</td>
      <td class="ms ${msClass(it.ms)}">${it.ms ?? '—'}ms</td>
    </tr>`;
  }).join('');
}

/* ---------- 总控 ---------- */
function refreshAll(){
  refreshSvc();
  if(!$('tab-hist').style.display) loadHistory();
}
$('base').value = localStorage.getItem('se_base') || '';
$('auto').addEventListener('change', e => {
  if(e.target.checked){ refreshAll(); timer = setInterval(refreshAll, 30000); }
  else { clearInterval(timer); }
});
refreshAll();
</script>
</body>
</html>"""


if __name__ == "__main__":
    print("SevenEngine Cloud 服务状态监控  ->  http://127.0.0.1:8765")
    app.run(host="127.0.0.1", port=8765, debug=False)
