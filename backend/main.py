"""FRIDAY - AI Incident Investigation & Root-Cause Analysis (prototype backend)."""
import os, json, re, sqlite3, asyncio, random, uuid, time
from collections import deque, defaultdict, Counter
from datetime import datetime, timezone
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Body, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import collectors

DB = os.getenv("FRIDAY_DB", "friday.db"); TICK = float(os.getenv("FRIDAY_TICK", "1.5"))
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").lower(); LLM_MODEL = os.getenv("LLM_MODEL", "")
LLM_API_KEY = os.getenv("LLM_API_KEY", ""); LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")

app = FastAPI(title="FRIDAY")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
con = sqlite3.connect(DB, check_same_thread=False); con.row_factory = sqlite3.Row
con.executescript("""
CREATE TABLE IF NOT EXISTS telemetry_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, service TEXT, severity TEXT,
 event_type TEXT, message TEXT, trace_id TEXT, request_id TEXT, host TEXT, environment TEXT, metric TEXT, value REAL,
 source TEXT, incident_id TEXT, anomalous INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_inc ON telemetry_events(incident_id); CREATE INDEX IF NOT EXISTS ix_met ON telemetry_events(metric);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, service TEXT, status TEXT, severity TEXT, started TEXT, source TEXT,
 reason TEXT, start_eid INTEGER, actions TEXT DEFAULT '[]', resolved_at TEXT, verification TEXT);
CREATE TABLE IF NOT EXISTS incident_memory(id TEXT PRIMARY KEY, fingerprint TEXT, services TEXT, summary TEXT,
 timeline TEXT, hypotheses TEXT, resolution TEXT, recovery TEXT, created TEXT);
""")

DN = {"instagram-api": "Instagram API", "postgresql": "PostgreSQL", "nginx": "Nginx", "redis": "Redis", "external-service": "External Service"}
dn = lambda s: DN.get(s, s)
ERR = ("ERROR", "CRITICAL"); CHANGE = ("deployment", "config_change", "restart", "version_change")
SEVMAP = {"warn": "WARNING", "warning": "WARNING", "err": "ERROR", "error": "ERROR", "fatal": "CRITICAL", "critical": "CRITICAL", "info": "INFO", "debug": "DEBUG", "trace": "DEBUG"}
ANOM = {"db_latency_ms": 400, "pool_util": 80, "api_latency_ms": 1000, "http_5xx_pct": 5}
OPEN = {"pool_util": 90, "api_latency_ms": 2000, "http_5xx_pct": 5}
NODES = [("user", "User", 60, 150), ("nginx", "Nginx", 230, 150), ("instagram-api", "Instagram API", 410, 150),
         ("redis", "Redis", 610, 50), ("postgresql", "PostgreSQL", 610, 150), ("external-service", "External Service", 610, 250)]
EDGES = [("user", "nginx"), ("nginx", "instagram-api"), ("instagram-api", "redis"), ("instagram-api", "postgresql"), ("instagram-api", "external-service")]
PARENT = {b: a for a, b in EDGES}

recent = defaultdict(lambda: deque(maxlen=20)); stamps = deque(maxlen=5000); clients = set()
now = lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")

# ---------------------------------------------------------------- normalisation
def norm(d, source):
    g = lambda *k: next((d[x] for x in k if d.get(x) not in (None, "")), None)
    sev = str(g("severity", "level", "severityText") or "INFO").lower()
    v = g("value")
    try: v = float(v) if v is not None else None
    except Exception: v = None
    metric = g("metric")
    return dict(ts=str(g("timestamp", "time", "ts", "@timestamp") or now()), service=str(g("service", "service.name", "app") or "unknown"),
        severity=SEVMAP.get(sev, sev.upper()), event_type=str(g("event_type", "type") or ("metric" if metric else "log")),
        message=str(g("message", "msg", "body") or metric or ""), trace_id=g("trace_id", "traceId"), request_id=g("request_id", "requestId"),
        host=g("host"), environment=g("environment", "env"), metric=metric, value=v, source=source)

def is_anom(e):
    m, v = e["metric"], e["value"]
    if m in ANOM: return v is not None and v >= ANOM[m]
    return (e["event_type"] in ("timeout", "user_failure", "exception", "slow_query", "pool_warning") or e["severity"] in ERR
            or (e["event_type"] == "trace" and e["severity"] == "WARNING"))

def should_open(e, rec):
    m, v = e["metric"], e["value"]
    if m in OPEN and v is not None and v >= OPEN[m]: return f"{m} reached {v:g}"
    if e["event_type"] in ("restart", "service_failure"): return "Service restart/failure detected"
    if e["severity"] in ERR and sum(1 for s in rec if s in ERR) >= 5: return f"Repeated errors in {e['service']}"

def open_incident(e, why):
    iid = f"FR-{1024 + con.execute('select count(*) c from incidents').fetchone()['c']}"
    con.execute("update telemetry_events set incident_id=? where incident_id is null and source=? and id>? and (anomalous=1 or id=?)", (iid, e["source"], e["id"] - 400, e["id"]))
    s = con.execute("select min(id) m from telemetry_events where incident_id=?", (iid,)).fetchone()["m"]
    sev = "Critical" if e["metric"] in OPEN or e["severity"] == "CRITICAL" else "High"
    con.execute("insert into incidents(id,service,status,severity,started,source,reason,start_eid) values(?,?,?,?,?,?,?,?)", (iid, e["service"], "Investigating", sev, e["ts"], e["source"], why, s))
    return iid

def ingest(d, source):
    e = norm(d, source); e["anomalous"] = int(is_anom(e))
    inc = con.execute("select id from incidents where status not in ('Resolved','Closed') order by rowid desc limit 1").fetchone()
    e["incident_id"] = inc["id"] if inc and e["anomalous"] else None
    cur = con.execute("insert into telemetry_events(ts,service,severity,event_type,message,trace_id,request_id,host,environment,metric,value,source,incident_id,anomalous) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (e["ts"], e["service"], e["severity"], e["event_type"], e["message"], e["trace_id"], e["request_id"], e["host"], e["environment"], e["metric"], e["value"], e["source"], e["incident_id"], e["anomalous"]))
    e["id"] = cur.lastrowid; stamps.append(time.time()); recent[e["service"]].append(e["severity"])
    opened = None
    if not inc:
        why = should_open(e, recent[e["service"]])
        if why: opened = open_incident(e, why)
    return e, opened

async def broadcast(m):
    for c in list(clients):
        try: await c.send_text(json.dumps(m, default=str))
        except Exception: clients.discard(c)

async def run(items, source, live=True):
    pairs = [ingest(d, source) for d in items if isinstance(d, dict)]; con.commit()
    if live:
        for e, _ in pairs[-200:]: await broadcast({"type": "event", "data": e})
    for _, o in pairs:
        if o: await broadcast({"type": "incident", "data": summary(o)})
    if not live: await broadcast({"type": "refresh"})
    return {"accepted": len(pairs), "incidents_opened": [o for _, o in pairs if o]}

# ---------------------------------------------------------------- analysis helpers
def evs(iid): return [dict(r) for r in con.execute("select * from telemetry_events where incident_id=? order by id", (iid,))]
def first(E, p): return next((e for e in E if p(e)), None)
def T(x):
    try:
        d = datetime.fromisoformat((x["ts"] if isinstance(x, dict) else x).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception: return None
def hms(x):
    t = T(x); return t.strftime("%H:%M:%S") if t else str(x["ts"] if isinstance(x, dict) else x)[-12:]
def gap(a, b):
    x, y = T(a), T(b); return round((y - x).total_seconds()) if x and y else None
def allm(name): return [r["value"] for r in con.execute("select value from telemetry_events where metric=? order by id", (name,))]
def lastavg(m, n=3):
    v = [r["value"] for r in con.execute("select value from telemetry_events where metric=? order by id desc limit ?", (m, n))]
    return sum(v) / len(v) if v else None

KEY = {"db_latency_ms": ("root", "PostgreSQL latency increased ({:.0f} ms)"), "pool_util": ("contributing", "Connection pool saturation detected ({:.0f}%)"),
       "api_latency_ms": ("contributing", "API latency increased ({:.0f} ms)"), "http_5xx_pct": ("downstream", "HTTP 5xx errors increased ({:.1f}%)")}

def timeline(E):
    seen, out = {}, []
    for e in E:
        msg = e["message"] or ""
        k = (e["service"], e["metric"]) if e["metric"] in KEY else (e["service"], e["event_type"], re.sub(r"[\d.]+", "#", msg)[:60])
        if k in seen: seen[k]["count"] += 1; continue
        if e["metric"] in KEY: st, tx = KEY[e["metric"]]; text = tx.format(e["value"])
        elif e["event_type"] == "timeout": st, text = "downstream", "Timeout events started: " + msg
        elif e["event_type"] == "user_failure": st, text = "impact", "User failures increased: " + msg
        else: st, text = ("downstream" if e["severity"] in ERR else "contributing"), msg
        it = dict(id=e["id"], ts=e["ts"], time=hms(e), service=e["service"], stage=st, text=text, trace_id=e["trace_id"], count=1, severity=e["severity"])
        seen[k] = it; out.append(it)
    if out and not any(i["stage"] == "root" for i in out): out[0]["stage"] = "root"
    return out[:80]

def strength(S, C):
    sc = len(S) - 0.5 * len(C)
    return sc, ("Strong" if sc >= 5 else "Moderate" if sc >= 3 else "Partial" if sc >= 1.5 else "Weak")

def quality():
    c = lambda sql: con.execute(sql).fetchone()[0] or 0
    logs = c("select count(*) from telemetry_events where metric is null and event_type!='trace'")
    mets = c("select count(distinct metric) from telemetry_events where metric is not null")
    trs = c("select count(*) from telemetry_events where event_type='trace' or trace_id is not null")
    dbm = c("select count(*) from telemetry_events where service in ('postgresql','mysql') and metric is not null")
    cpu = c("select count(*) from telemetry_events where metric='db_cpu_pct'")
    bad = c("select count(*) from telemetry_events where ts not like '____-__-__T%'")
    Q = [("Logs", "ok" if logs else "missing"), ("Metrics", "ok" if mets >= 3 else "partial" if mets else "missing"),
         ("Traces", "ok" if trs >= 50 else "partial" if trs else "missing"),
         ("Database telemetry", "missing" if not dbm else "ok" if cpu else "partial"), ("Timestamp synchronization", "ok" if not bad else "partial")]
    gaps = []
    if dbm and not cpu: gaps.append("database CPU telemetry is unavailable")
    if not mets: gaps.append("no metrics were collected")
    if not trs: gaps.append("no trace telemetry was collected")
    if 0 < trs < 50: gaps.append("trace coverage is partial")
    return [dict(name=n, status=s) for n, s in Q], gaps

def changes(iid):
    inc = con.execute("select * from incidents where id=?", (iid,)).fetchone()
    ch = [dict(r) for r in con.execute("select ts,service,event_type,message from telemetry_events where event_type in (?,?,?,?) and id<=? order by id desc limit 5", (*CHANGE, inc["start_eid"] or 0))][::-1]
    cmp = []
    for m in ("rps", "db_latency_ms", "pool_util", "api_latency_ms", "http_5xx_pct", "cache_hit_pct"):
        b = [r["value"] for r in con.execute("select value from telemetry_events where metric=? and id<? order by id desc limit 5", (m, inc["start_eid"] or 0))]
        n = lastavg(m)
        if b and n is not None: cmp.append(dict(metric=m, before=round(sum(b) / len(b), 1), now=round(n, 1)))
    note = ("Candidate change correlated with incident onset. Correlation alone does not establish that it caused the incident." if ch
            else "No deployment, configuration or restart events found in the available telemetry.")
    return dict(changes=ch, comparison=cmp, note=note)

def similar(tl, iid):
    fp = {f"{i['service']}:{i['stage']}" for i in tl}; best = None
    for m in con.execute("select * from incident_memory where id!=?", (iid,)):
        old = set(json.loads(m["fingerprint"])); j = len(fp & old) / max(1, len(fp | old))
        if j >= .7 and (not best or j > best[0]): best = (j, m)
    if not best: return None
    j, m = best
    return dict(id=m["id"], similarity=round(j, 2), summary=m["summary"], resolution=m["resolution"], recovery=json.loads(m["recovery"] or "null"), created=m["created"])

def analyze(iid):
    r = con.execute("select * from incidents where id=?", (iid,)).fetchone()
    if not r: raise HTTPException(404, "incident not found")
    E = evs(iid); tl = timeline(E); H = []; rel = {}
    mf = lambda n: first(E, lambda e: e["metric"] == n)
    db, pool, api, err = mf("db_latency_ms"), mf("pool_util"), mf("api_latency_ms"), mf("http_5xx_pct")
    to = first(E, lambda e: e["event_type"] == "timeout"); spans = [e for e in E if e["event_type"] == "trace"]
    qual, gaps = quality(); pen = 0.85 if gaps else 1.0
    def add(kind, title, S, M, C, why, suspect=None):
        sc, st = strength(S, C)
        H.append(dict(kind=kind, title=title, strength=st, score=sc, confidence=round(min(.9, max(.05, sc / 7)) * pen, 2), why=why, supporting=S, missing=M, conflicting=C, suspect=suspect))
    kind = None
    if db and pool:
        kind = "db"; pk = max(e["value"] for e in E if e["metric"] == "pool_util")
        S = [f"PostgreSQL latency exceeded {ANOM['db_latency_ms']} ms at {hms(db)}", f"Connection pool utilization reached {pk:.0f}% (first ≥{ANOM['pool_util']}% at {hms(pool)})"]; C = []; M = []
        if api: (S if db["id"] < api["id"] else C).append(f"API latency increased at {hms(api)}, {'after' if db['id'] < api['id'] else 'before'} the DB degradation")
        if to: (S if to["id"] > db["id"] else C).append(f"Timeout events {'followed' if to['id'] > db['id'] else 'appeared before'} DB degradation ({sum(1 for e in E if e['event_type'] == 'timeout')} events, first at {hms(to)})")
        if err: (S if err["id"] > db["id"] else C).append(f"HTTP 5xx rate crossed {ANOM['http_5xx_pct']}% at {hms(err)}, after the DB degradation" if err["id"] > db["id"] else "HTTP 5xx errors started before the DB degradation")
        w = [e for e in spans if "wait" in (e["message"] or "")]
        (S.append(f"{len(w)} related trace span(s) show DB connection wait") if w else M.append("No trace evidence of DB wait time"))
        if not allm("db_cpu_pct"): M.append("Database CPU telemetry unavailable")
        if not first(E, lambda e: e["event_type"] == "slow_query"): M.append("No PostgreSQL slow-query telemetry")
        add("db", "PostgreSQL connection saturation", S, M, C, "The earliest anomalous signal is PostgreSQL latency, followed by pool saturation and downstream API failures.", "postgresql")
        rp = allm("rps")
        if len(rp) >= 6:
            base = sum(rp[:5]) / 5; ratio = max(rp) / base if base else 1
            if ratio >= 1.5: add("traffic", "Traffic spike", [f"Request rate rose {ratio:.1f}x over baseline"], [], [], "A surge in concurrent requests can exhaust a connection pool.", "nginx")
            else: add("traffic", "Traffic spike", [], [], [f"Request rate stayed within {abs(ratio - 1) * 100:.0f}% of baseline"], "A surge in concurrent requests can exhaust a connection pool.", "nginx")
        else: add("traffic", "Traffic spike", [], ["No request-rate telemetry"], [], "A surge in concurrent requests can exhaust a connection pool.", "nginx")
        if to:
            S = ["Timeout events observed in the API"] + (["API latency crossed the 2000 ms timeout budget"] if api and max(e["value"] for e in E if e["metric"] == "api_latency_ms") >= 2000 else [])
            C = ["Timeouts began after upstream latency increased, so they look like a symptom"] if api and to["id"] > api["id"] else []
            add("timeout", "API timeout configuration", S, ["Timeout configuration values not present in telemetry"], C, "Aggressive timeouts can convert slow dependencies into hard failures.", "instagram-api")
        add("network", "Network latency", [], ["No network latency or packet-loss telemetry"], [], "Cross-service network delay can mimic database slowness.", None)
    else:
        errs = [e for e in E if e["severity"] in ERR]
        if errs:
            kind = "errors"; svc, n = Counter(e["service"] for e in errs).most_common(1)[0]
            msg, k = Counter((e["message"] or "")[:90] for e in errs if e["service"] == svc).most_common(1)[0]
            add("errors", f"Repeated failures in {dn(svc)}", [f"{n} error events from {dn(svc)}", f"Most frequent error ({k}x): {msg}", f"First error at {hms(errs[0])}"],
                ["No metric telemetry correlated with these errors"] if not any(e["metric"] for e in E) else [], [], "Repeated errors in one service are the strongest available signal.", svc)
    H.sort(key=lambda h: -h["confidence"])
    verdict = None
    if not H: verdict = "Insufficient telemetry to confidently determine the root cause."
    elif H[0]["strength"] == "Weak": verdict = "No dominant hypothesis identified. Continue collecting telemetry."
    elif len(H) > 1 and abs(H[0]["score"] - H[1]["score"]) < 1: verdict = "Telemetry conflict detected. Additional investigation recommended."
    if E:
        keep = lambda f, n: [dict(ts=e["ts"], time=hms(e), service=e["service"], message=e["message"], trace_id=e["trace_id"]) for e in E if f(e)][:n]
        rel = dict(logs=keep(lambda e: not e["metric"] and e["event_type"] != "trace", 6),
                   metrics=[dict(time=hms(x), service=x["service"], metric=x["metric"], value=round(x["value"], 1)) for x in [mf(m) for m in KEY] if x], traces=keep(lambda e: e["trace_id"], 5))
    tr = defaultdict(set)
    for e in E:
        if e["trace_id"]: tr[e["trace_id"]].add(e["service"])
    shared = sum(1 for s in tr.values() if len(s) > 1)
    corr = [it["text"] + (f" (+{gap(tl[i - 1]['ts'], it['ts'])}s)" if i and gap(tl[i - 1]["ts"], it["ts"]) else "") for i, it in enumerate(tl[:12])]
    if shared: corr.append(f"Same trace IDs affected across services ({shared} traces)")
    ch = changes(iid); chtxt = "; ".join(f"{hms(c['ts'])} {c['message']}" for c in ch["changes"]) or "no change events recorded"
    if kind == "db":
        pk = max(e["value"] for e in E if e["metric"] == "pool_util")
        rec = [("Inspect the PostgreSQL connection pool", f"Pool reached {pk:.0f}% and is the strongest link between DB and API symptoms."),
               ("Inspect slow queries", "Slow queries hold connections longer, which drives saturation."),
               ("Check database resource utilization (CPU / IO)", "DB CPU telemetry is missing, so resource pressure is unconfirmed."),
               ("Inspect affected trace IDs", f"{shared or len(tr)} traces span multiple services and show where time was spent."),
               ("Compare deployment / configuration changes", f"Change context: {chtxt}.")]
        action = "Increase database connection capacity / investigate pool saturation"
    elif kind == "errors":
        rec = [("Inspect the most frequent error and its stack trace", H[0]["supporting"][1]), ("Inspect affected trace / request IDs", f"{len(tr)} trace IDs appear in the incident events."),
               ("Check recent deployments or config changes", f"Change context: {chtxt}."), ("Send metrics and traces for the affected service", "Only logs are available, so confidence is limited.")]
        action = f"Investigate errors in {dn(H[0]['suspect'])}; consider rollback only if a correlated change is confirmed"
    else: rec, action = [], None
    return dict(hypotheses=H, verdict=verdict, quality=qual, quality_note=("RCA confidence is limited because " + " and ".join(gaps) + ".") if gaps else "Telemetry coverage is sufficient for RCA.",
        timeline=tl, correlated=corr, related=rel, recommendations=[dict(step=a, why=b) for a, b in rec], action=action, requires_approval=True,
        suspect=H[0]["suspect"] if H and not verdict else None, similar=similar(tl, iid), early=[])

def summary(iid):
    r = dict(con.execute("select * from incidents where id=?", (iid,)).fetchone()); E = evs(iid); sv = []
    for e in E:
        if e["service"] not in sv: sv.append(e["service"])
    p = "instagram-api" if "instagram-api" in sv else (sv[0] if sv else r["service"])
    return dict(id=r["id"], service=dn(p), status=r["status"], severity=r["severity"], started=hms(E[0]) if E else hms(r["started"]), affected_services=len(sv), source=r["source"], reason=r["reason"], resolved_at=r["resolved_at"])

def path_to(s):
    p = []
    while s in PARENT: s = PARENT[s]; p.append(s)
    return p

def discover_edges():
    """Infer service call relationships from trace correlation: services sharing a trace_id,
    ordered by first-seen timestamp within that trace, are treated as a call hop."""
    rows = con.execute("select trace_id, service, ts from telemetry_events where trace_id is not null order by trace_id, id").fetchall()
    groups = defaultdict(list)
    for r in rows: groups[r["trace_id"]].append((r["ts"], r["service"]))
    w = Counter()
    for tid, seq in groups.items():
        seq.sort(key=lambda x: x[0]); seen = []
        for _, svc in seq:
            if not seen or seen[-1] != svc: seen.append(svc)
        for a, b in zip(seen, seen[1:]):
            if a != b: w[(a, b)] += 1
    return w

def deps(iid):
    a = analyze(iid); aff = {e["service"] for e in evs(iid)}; sus = a["suspect"]; up = path_to(sus) if sus else []
    cnt = {r["service"]: r["c"] for r in con.execute("select service, count(*) c from telemetry_events group by service")}
    disc = discover_edges(); known = {(x, y) for x, y in EDGES}; known_ids = {n[0] for n in NODES}
    extra_svcs = sorted((aff | {s for pair in disc for s in pair}) - known_ids)
    nodes = []
    for k, l, x, y in NODES + [(s, s, 60 + i * 170, 340) for i, s in enumerate(extra_svcs)]:
        st = "failing" if k == sus else "affected" if (k in aff or k in up) else "healthy"
        nodes.append(dict(id=k, label=dn(l), x=x, y=y, status=st, telemetry="n/a" if k == "user" else f"{cnt[k]} events" if k in cnt else "no telemetry"))
    on = set(up + ([sus] if sus else []))
    edges = [dict(a=x, b=y, hot=x in on and y in on, source="known", weight=disc.get((x, y), 0)) for x, y in EDGES]
    for (x, y), wt in disc.items():
        if (x, y) in known or (y, x) in known: continue
        edges.append(dict(a=x, b=y, hot=x in on and y in on, source="discovered", weight=wt))
    return dict(nodes=nodes, edges=edges, suspect=sus, discovered_edges=sum(1 for e in edges if e["source"] == "discovered"))

def blast(iid):
    E = evs(iid); sv = sorted({e["service"] for e in E}); sus = analyze(iid)["suspect"]; up = [s for s in (path_to(sus) if sus else []) if s != "user"]
    if not E:
        return dict(affected_services=[], affected_service_names=[], affected_requests=0, affected_users=0, upstream=[], downstream=[],
            endpoints=[], affected_traces=0, trace_sample=[], per_service=[], impact_score=0, estimate=True, note="No telemetry captured for this incident yet.")
    tr = {e["trace_id"] for e in E if e["trace_id"]}
    ep = Counter(m.group(0) for e in E for m in [re.search(r"(GET|POST|PUT|DELETE|PATCH) /[\w/\-.]*", e["message"] or "")] if m)
    # Integrate affected requests over the incident window: pair each rps sample with the nearest
    # error-rate sample by position, and sum (requests_in_tick * error_share) rather than a single
    # snapshot multiplied by duration. This tracks the error ramp instead of assuming a flat rate.
    rps_s = [e["value"] for e in E if e["metric"] == "rps"]; err_s = [e["value"] for e in E if e["metric"] == "http_5xx_pct"]
    n = min(len(rps_s), len(err_s))
    if n >= 2:
        affected_requests = int(sum(rps_s[i] * TICK * (err_s[i] / 100) for i in range(n)))
        peak_err = max(err_s)
    else:
        affected_requests = sum(1 for e in E if e["severity"] in ERR); peak_err = max([e["value"] for e in E if e["metric"] == "http_5xx_pct"] or [0])
    # Unique users: prefer real distinct request_id telemetry when present; otherwise fall back to a
    # documented session-density heuristic (~1 unique user per 3 affected requests).
    uids = {e["request_id"] for e in E if e["request_id"]}
    real_users = bool(uids)
    affected_users = len(uids) if real_users else int(affected_requests * .34)
    per_service = []
    for s in sv:
        se = [e for e in E if e["service"] == s]; errs = sum(1 for e in se if e["severity"] in ERR)
        per_service.append(dict(service=dn(s), events=len(se), errors=errs, error_rate=round(100 * errs / len(se), 1) if se else 0))
    per_service.sort(key=lambda x: -x["errors"])
    # Impact score (0-100): weighted blend of peak error rate, breadth of affected services, and
    # how many distinct traces were touched — a simple, explainable composite rather than a raw count.
    impact_score = min(100, round(peak_err * .5 + len(sv) * 9 + min(len(tr), 40) * .5))
    sim_ = any(e["source"] == "DEMO" for e in E)
    both = sorted(set(sv) | set(up))
    note = ("Peak error rate observed; requests estimated by integrating request-rate and error-rate telemetry over the incident window." +
        (" User count is a session-density estimate — no request_id telemetry was present." if not real_users else " User count uses distinct request IDs observed in telemetry.") +
        (" Underlying traffic is simulated demo telemetry." if sim_ else ""))
    return dict(affected_services=both, affected_service_names=[dn(s) for s in both], affected_requests=affected_requests, affected_users=affected_users,
        upstream=[dn(s) for s in up], downstream=[dn(c) for a, c in EDGES if a == sus], endpoints=[dict(endpoint=k, hits=v) for k, v in ep.most_common(6)],
        affected_traces=len(tr), trace_sample=sorted(tr)[:6], per_service=per_service, impact_score=impact_score, estimate=not real_users, note=note)

def verify(iid):
    rows = [("PostgreSQL latency", "db_latency_ms", 200, "ms"), ("API latency", "api_latency_ms", 500, "ms"), ("HTTP 5xx rate", "http_5xx_pct", 1, "%"), ("Pool utilization", "pool_util", 75, "%")]; items = []
    for lab, m, thr, u in rows:
        b = con.execute("select max(value) v from telemetry_events where metric=? and incident_id=?", (m, iid)).fetchone()["v"]; a = lastavg(m)
        if b is not None and a is not None: items.append(dict(label=lab, before=round(b, 1), after=round(a, 1), ok=a <= thr, unit=u))
    if not items: return dict(status="unknown", message="Not enough comparable metrics to verify recovery.", items=[])
    ok = all(i["ok"] for i in items)
    return dict(status="recovered" if ok else "abnormal", message="Recovery signals detected" if ok else "Incident may not be fully resolved", items=items)

def narrative(a):
    if not a["hypotheses"]: return a["verdict"]
    h = a["hypotheses"][0]
    return (f"Leading hypothesis: {h['title']} ({h['strength']} evidence). " + " ".join(h["supporting"][:4]) +
            (f" Uncertain: {'; '.join(h['missing'][:2])}." if h["missing"] else "") + f" {a['quality_note']}")

def story(iid):
    a = analyze(iid); a["early"] = warning(); a["narrative"] = narrative(a)
    return dict(incident=summary(iid), analysis=a, blast=blast(iid), deps=deps(iid), changes=changes(iid), verification=verify(iid),
                actions=json.loads(con.execute("select actions from incidents where id=?", (iid,)).fetchone()["actions"]))

def slope_of(vals):
    """Least-squares linear regression slope (per-tick rate of change)."""
    n = len(vals)
    if n < 2: return 0.0
    xs = list(range(n)); mx = sum(xs) / n; my = sum(vals) / n
    num = sum((xs[i] - mx) * (vals[i] - my) for i in range(n)); den = sum((xs[i] - mx) ** 2 for i in range(n)) or 1
    return num / den

def warning():
    if con.execute("select 1 from incidents where status not in ('Resolved','Closed') limit 1").fetchone(): return []
    W = []
    for m, lab, lim in (("pool_util", "Connection pool utilization", OPEN["pool_util"]), ("api_latency_ms", "API latency", OPEN["api_latency_ms"]), ("db_latency_ms", "Database latency", ANOM["db_latency_ms"])):
        v = allm(m)[-8:]
        if len(v) < 4: continue
        s = slope_of(v); cur = v[-1]
        if s <= 0 or cur < .5 * lim: continue
        proximity = min(100, cur / lim * 100)
        # steepness component is capped so a slow-but-steady climb still scores below a sharp one
        steep = min(30, s / max(lim, 1) * 300)
        risk = round(min(100, proximity * .7 + steep))
        if risk < 35: continue
        remaining = lim - cur
        eta = f"~{max(1, round(remaining / s * TICK))}s to threshold" if remaining > 0 else "at/above threshold"
        W.append(dict(signal=lab, trend=[round(x) for x in v], limit=lim, risk=risk, eta=eta, slope=round(s, 1)))
    W.sort(key=lambda w: -w["risk"])
    return W

# ---------------------------------------------------------------- AI layer
SYSTEM = (
"You are FRIDAY, an AI incident investigation copilot embedded in an SRE observability platform. "
"You are given the full evidence JSON for ONE incident: ranked root-cause hypotheses with supporting/missing/"
"conflicting evidence, a reconstructed timeline, blast-radius impact, telemetry quality, and what-changed context. "
"Ground every claim in that JSON — never invent a metric, timestamp, service name or event that isn't in it. "
"Speak like a senior engineer briefing a teammate mid-incident: direct, specific, cites exact timestamps and "
"numbers from the evidence, and no filler like 'I hope this helps'. "
"Prefer the strongest hypothesis but name credible alternatives when the evidence is close. "
"If evidence is thin, say so plainly ('Insufficient telemetry to confidently determine the root cause') rather than "
"guessing. If the engineer's question isn't answered by the evidence, say what's missing and what telemetry would "
"resolve it, instead of speculating. Keep answers under ~120 words unless asked for detail. This is a live "
"conversation — use prior turns for context but always re-ground new claims in the evidence JSON."
)
async def llm(messages, system=SYSTEM):
    """messages: list of {'role': 'user'|'assistant', 'content': str} — full conversation so far."""
    if LLM_PROVIDER == "none" or not LLM_API_KEY or not LLM_MODEL: return None
    try:
        async with httpx.AsyncClient(timeout=40) as c:
            if LLM_PROVIDER == "anthropic":
                r = await c.post("https://api.anthropic.com/v1/messages", headers={"x-api-key": LLM_API_KEY, "anthropic-version": "2023-06-01"},
                    json={"model": LLM_MODEL, "max_tokens": 700, "system": system, "messages": messages})
                j = r.json()
                if "content" not in j: return None
                return "".join(b.get("text", "") for b in j["content"] if b.get("type") == "text") or None
            if LLM_PROVIDER == "gemini":
                # Gemini has no separate "assistant" role — it uses "model" — and no top-level system param pre-1.5 style,
                # so we fold the system prompt into the first turn and remap roles.
                contents = [{"role": "user", "parts": [{"text": system}]}, {"role": "model", "parts": [{"text": "Understood."}]}]
                for m in messages:
                    contents.append({"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]})
                r = await c.post(f"https://generativelanguage.googleapis.com/v1beta/models/{LLM_MODEL}:generateContent?key={LLM_API_KEY}",
                    json={"contents": contents, "generationConfig": {"maxOutputTokens": 700}})
                j = r.json()
                cands = j.get("candidates") or []
                if not cands: return None
                parts = cands[0].get("content", {}).get("parts", [])
                return "".join(p.get("text", "") for p in parts) or None
            r = await c.post(f"{LLM_BASE_URL}/chat/completions", headers={"Authorization": f"Bearer {LLM_API_KEY}"},
                json={"model": LLM_MODEL, "messages": [{"role": "system", "content": system}] + messages})
            j = r.json()
            return j.get("choices", [{}])[0].get("message", {}).get("content")
    except Exception: return None

def rule_answer(q, s):
    a, b, c = s["analysis"], s["blast"], s["changes"]; H = a["hypotheses"]
    if not H: return a["verdict"] or "Insufficient telemetry to confidently determine the root cause."
    h = H[0]
    if any(k in q for k in ("check", "first", "next", "should", "investigate", "fix", "recommend")):
        return "Suggested order, based on the collected evidence:\n" + "\n".join(f"{i + 1}. {r['step']} - {r['why']}" for i, r in enumerate(a["recommendations"]))
    if any(k in q for k in ("affect", "impact", "blast", "user")):
        return f"{len(b['affected_services'])} services affected ({', '.join(b['affected_service_names'])}); ~{b['affected_requests']:,} requests and ~{b['affected_users']:,} users. {b['note']}"
    if any(k in q for k in ("change", "deploy", "version")):
        return c["note"] + (" " + "; ".join(f"{hms(x['ts'])} {x['message']}" for x in c["changes"]) if c["changes"] else "")
    if any(k in q for k in ("missing", "uncertain", "confiden", "sure", "conflict")):
        return f"Missing: {'; '.join(h['missing']) or 'nothing notable'}. Conflicting: {'; '.join(h['conflicting']) or 'none observed'}. {a['quality_note']}"
    if any(k in q for k in ("why", "cause", "db", "database", "think", "evidence")):
        return f"{h['title']} is the leading root-cause hypothesis ({h['strength']} evidence). " + " ".join(h["supporting"]) + " This temporal sequence supports the hypothesis but does not prove it."
    return a["narrative"]

# ---------------------------------------------------------------- simulator (Insta demo)
BASE = dict(rps=520, db=40, pool=30, api=120, err=0.2, cache=96)
sim = dict(on=False, t=0, rec=False, v=dict(BASE), task=None, noted=0)
async def sim_loop():
    while sim["on"]:
        t = sim["t"]; sim["t"] += 1; v = sim["v"]; tg = dict(BASE)
        if t >= 10: tg["db"] = min(950, 40 + (t - 10) * 90)
        if t >= 11: tg["pool"] = min(98, 30 + (t - 11) * 10)
        if t >= 16: tg["api"] = min(3200, 120 + (t - 15) * 450)
        if t >= 19: tg["err"] = min(22, (t - 18) * 4)
        for k in v: v[k] = BASE[k] + (v[k] - BASE[k]) * .45 if sim["rec"] else tg[k]
        nz = lambda k: v[k] * random.uniform(.97, 1.03); tid = uuid.uuid4().hex[:8]; ts = now(); I = []
        for svc, m, val in (("nginx", "rps", nz("rps")), ("postgresql", "db_latency_ms", nz("db")), ("postgresql", "pool_util", min(100, nz("pool"))),
                            ("instagram-api", "api_latency_ms", nz("api")), ("instagram-api", "http_5xx_pct", nz("err")), ("redis", "cache_hit_pct", nz("cache"))):
            I.append(dict(service=svc, metric=m, value=round(val, 1), event_type="metric", environment="demo", timestamp=ts, message=f"{m}={val:.1f}"))
        L = lambda svc, sev, et, msg, trace=None, val=None: I.append(dict(service=svc, severity=sev, event_type=et, message=msg, trace_id=trace, value=val, environment="demo", timestamp=ts))
        if t == 8: L("instagram-api", "INFO", "deployment", "API version changed from v2.3.1 to v2.3.2")
        if v["db"] >= 400: L("postgresql", "WARNING", "slow_query", f"Slow query: SELECT * FROM posts WHERE user_id=? ({v['db']:.0f} ms)")
        if v["pool"] >= 80: L("postgresql", "WARNING", "pool_warning", f"Connection pool utilization high ({v['pool']:.0f}%)")
        if v["pool"] >= 85: L("instagram-api", "WARNING", "trace", f"span db.query waited for connection {v['db'] * 1.6:.0f} ms", tid, v["db"] * 1.6)
        if v["api"] >= 1900: L("instagram-api", "ERROR", "timeout", "Upstream timeout: GET /feed exceeded 2000 ms", tid)
        if v["err"] >= 4: L("instagram-api", "ERROR", "log", "HTTP 500 Internal Server Error on GET /feed", tid)
        if v["err"] >= 6: L("nginx", "ERROR", "user_failure", "User request failed: 502 upstream error on GET /feed", tid)
        if v["err"] < 4: L("instagram-api", "INFO", "log", "GET /feed 200 OK", tid)
        if sim["rec"] and v["pool"] < 50 and not sim["noted"]: sim["noted"] = 1; L("postgresql", "INFO", "log", "Connection pool utilization back to normal")
        await run(I, "DEMO"); await asyncio.sleep(TICK)

# ---------------------------------------------------------------- upload / OTLP parsing
LINE = re.compile(r"^\[?(\d{4}-\d\d-\d\d[T ][\d:.,]+Z?|\d\d:\d\d:\d\d(?:[.,]\d+)?)\]?\s+\[?(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\]?\s*(?:([\w.\-]+):\s+)?(.*)$", re.I)
def iso(s):
    try:
        if re.match(r"^\d\d:", s): s = datetime.now(timezone.utc).strftime("%Y-%m-%d") + "T" + s
        d = datetime.fromisoformat(s.replace(" ", "T").replace(",", ".").rstrip("Z")); return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat()
    except Exception: return s
def parse_text(txt, name):
    txt = txt.strip(); out = []
    if txt.startswith("["):
        try: return [x for x in json.loads(txt) if isinstance(x, dict)]
        except Exception: pass
    for ln in txt.splitlines()[:20000]:
        ln = ln.strip()
        if not ln: continue
        if ln.startswith("{"):
            try: out.append(json.loads(ln)); continue
            except Exception: pass
        d = {"message": ln, "service": name, "severity": "ERROR" if re.search(r"\b(error|exception|fatal)\b", ln, re.I) else "INFO"}; m = LINE.match(ln)
        if m:
            d.update(timestamp=iso(m[1]), severity=m[2], message=m[4] or ln)
            if m[3]: d["service"] = m[3]
        t = re.search(r"trace[_-]?id[=: ]+([\w-]+)", ln, re.I); q = re.search(r"request[_-]?id[=: ]+([\w-]+)", ln, re.I)
        if t: d["trace_id"] = t[1]
        if q: d["request_id"] = q[1]
        out.append(d)
    return out

def otlp(b):
    out = []; at = lambda a: {x["key"]: next(iter(x.get("value", {}).values()), None) for x in a or []}
    ns = lambda n: datetime.fromtimestamp(int(n) / 1e9, timezone.utc).isoformat() if n else None
    for rl in b.get("resourceLogs", []):
        svc = at(rl.get("resource", {}).get("attributes")).get("service.name", "unknown")
        for sl in rl.get("scopeLogs", []):
            for r in sl.get("logRecords", []):
                out.append(dict(service=svc, severity=r.get("severityText", "INFO"), message=(r.get("body") or {}).get("stringValue", ""), trace_id=r.get("traceId"), span_id=r.get("spanId"), timestamp=ns(r.get("timeUnixNano")), event_type="log"))
    for rm in b.get("resourceMetrics", []):
        svc = at(rm.get("resource", {}).get("attributes")).get("service.name", "unknown")
        for sm in rm.get("scopeMetrics", []):
            for m in sm.get("metrics", []):
                for p in (m.get("gauge") or m.get("sum") or {}).get("dataPoints", []):
                    v = p.get("asDouble", p.get("asInt"))
                    if v is not None: out.append(dict(service=svc, metric=m.get("name"), value=float(v), timestamp=ns(p.get("timeUnixNano")), event_type="metric"))
    for rs in b.get("resourceSpans", []):
        svc = at(rs.get("resource", {}).get("attributes")).get("service.name", "unknown")
        for ss in rs.get("scopeSpans", []):
            for s in ss.get("spans", []):
                dur = (int(s.get("endTimeUnixNano", 0)) - int(s.get("startTimeUnixNano", 0))) / 1e6; bad = (s.get("status") or {}).get("code") in (2, "STATUS_CODE_ERROR")
                out.append(dict(service=svc, event_type="trace", severity="ERROR" if bad else "INFO", message=f"span {s.get('name')} {dur:.0f} ms", value=dur, trace_id=s.get("traceId"), span_id=s.get("spanId"), timestamp=ns(s.get("startTimeUnixNano"))))
    return out

# ---------------------------------------------------------------- API
@app.websocket("/ws")
async def ws(w: WebSocket):
    await w.accept(); clients.add(w)
    try:
        while True: await w.receive_text()
    except WebSocketDisconnect: clients.discard(w)

@app.post("/api/telemetry/logs")
async def t_logs(body=Body(...)): return await run(body if isinstance(body, list) else body.get("logs", [body]), "API")
@app.post("/api/telemetry/metrics")
async def t_metrics(body=Body(...)):
    items = body if isinstance(body, list) else body.get("metrics", [body]); [i.setdefault("event_type", "metric") for i in items]; return await run(items, "API")
@app.post("/api/telemetry/traces")
async def t_traces(body=Body(...)):
    items = body if isinstance(body, list) else body.get("spans", [body])
    return await run([dict(i, event_type="trace", message=i.get("message") or f"span {i.get('name', '')} {i.get('duration_ms', '')} ms", value=i.get("duration_ms", i.get("value")), severity="ERROR" if i.get("status") == "error" else i.get("severity", "INFO")) for i in items], "API")
@app.post("/api/telemetry/otlp")
async def t_otlp(body=Body(...)): return await run(otlp(body), "OTLP")
@app.post("/api/telemetry/agent")
async def t_agent(body=Body(...), authorization: str = Header(None)):
    """Real Windows/Linux host metrics from backend/agent.py (and, optionally, that host's Docker containers)."""
    if AGENT_TOKEN and authorization != f"Bearer {AGENT_TOKEN}": raise HTTPException(401, "unauthorized")
    items = body if isinstance(body, list) else body.get("metrics", [body])
    [i.setdefault("event_type", "metric") for i in items]
    return await run(items, "AGENT")
@app.post("/api/telemetry/upload")
async def upload(file: UploadFile = File(...)):
    items = parse_text((await file.read()).decode("utf-8", "ignore"), (file.filename or "upload").rsplit(".", 1)[0])
    return dict(await run(items, "UPLOADED", live=False), parsed=len(items), filename=file.filename)

@app.get("/api/events")
def events(limit: int = 100): return [dict(r) for r in con.execute("select * from telemetry_events order by id desc limit ?", (limit,))]

@app.get("/api/overview")
def overview():
    S = {m: allm(m)[-40:] for m in ("api_latency_ms", "http_5xx_pct", "db_latency_ms", "pool_util", "rps")}; t = time.time()
    active = con.execute("select count(*) c from incidents where status not in ('Resolved','Closed')").fetchone()["c"]
    last = lambda m: S[m][-1] if S[m] else None
    er = last("http_5xx_pct")
    if er is None:
        rows = [r["severity"] for r in con.execute("select severity from telemetry_events order by id desc limit 100")]; er = 100 * sum(1 for s in rows if s in ERR) / len(rows) if rows else 0
    return dict(health="Critical" if active and (last("http_5xx_pct") or 0) >= 5 else "Degraded" if active else "Healthy", active_incidents=active,
        services=con.execute("select count(distinct service) c from telemetry_events").fetchone()["c"], error_rate=round(er, 1), avg_latency=last("api_latency_ms"),
        eps=round(sum(1 for x in stamps if x > t - 5) / 5, 1), series=S, early=warning(), demo_running=sim["on"])

@app.get("/api/incidents")
def incidents():
    out = []
    for r in con.execute("select id from incidents order by rowid desc").fetchall():
        s = summary(r["id"]); a = analyze(r["id"]); s["title"] = a["hypotheses"][0]["title"] if a["hypotheses"] and not a["verdict"] else "No dominant hypothesis"; out.append(s)
    return out
@app.get("/api/incidents/{iid}")
def inc_get(iid: str): return story(iid)
@app.get("/api/incidents/{iid}/story")
def inc_story(iid: str): return story(iid)
@app.get("/api/incidents/{iid}/timeline")
def inc_tl(iid: str): return analyze(iid)["timeline"]
@app.get("/api/incidents/{iid}/evidence")
def inc_ev(iid: str): a = analyze(iid); return dict(hypotheses=a["hypotheses"], related=a["related"], quality=a["quality"], note=a["quality_note"])
@app.get("/api/incidents/{iid}/dependencies")
def inc_dep(iid: str): return deps(iid)
@app.get("/api/incidents/{iid}/blast-radius")
def inc_blast(iid: str): return blast(iid)
@app.get("/api/incidents/{iid}/what-changed")
def inc_ch(iid: str): return changes(iid)
@app.post("/api/incidents/{iid}/investigate")
async def inc_inv(iid: str):
    s = story(iid)
    prompt = ("Incident evidence JSON:\n" + json.dumps({k: s["analysis"][k] for k in ("hypotheses", "verdict", "quality_note", "timeline")}, default=str)[:12000] +
              "\nWrite a concise (4-6 sentence) incident narrative an on-call engineer would read first: what happened, the evidence chain, and what's still uncertain.")
    t = await llm([{"role": "user", "content": prompt}])
    if t: s["analysis"]["narrative"] = t
    return s
@app.post("/api/incidents/{iid}/replay")
def inc_replay(iid: str):
    E = evs(iid)[:300]; st = {i["id"]: i["stage"] for i in timeline(E)}
    return dict(steps=[dict(i=i, time=hms(e), service=e["service"], severity=e["severity"], text=e["message"], trace_id=e["trace_id"], stage=st.get(e["id"])) for i, e in enumerate(E)])
@app.post("/api/incidents/{iid}/verify")
def inc_verify(iid: str): return verify(iid)

@app.post("/api/incidents/{iid}/action")
async def inc_action(iid: str, body=Body(...)):
    a = body.get("action"); r = con.execute("select * from incidents where id=?", (iid,)).fetchone()
    if not r or a not in ("review", "approve", "reject", "investigated", "followup", "resolve"): raise HTTPException(400, "bad request")
    acts = json.loads(r["actions"]); acts.append(dict(ts=now(), action=a, note=body.get("note", "")))
    con.execute("update incidents set actions=? where id=?", (json.dumps(acts), iid))
    if a == "approve" and r["source"] == "DEMO": sim["rec"] = True
    if a == "resolve":
        an = analyze(iid); v = verify(iid); h = an["hypotheses"][0] if an["hypotheses"] else None
        con.execute("update incidents set status='Resolved', resolved_at=?, verification=? where id=?", (now(), json.dumps(v), iid))
        con.execute("insert or replace into incident_memory values(?,?,?,?,?,?,?,?,?)", (iid, json.dumps(sorted({f"{i['service']}:{i['stage']}" for i in an["timeline"]})), json.dumps(sorted({i["service"] for i in an["timeline"]})),
            h["title"] if h else "Unknown", json.dumps(an["timeline"][:10]), json.dumps(an["hypotheses"][:3]), "; ".join(x["action"] for x in acts if x["action"] in ("approve", "investigated")) or "Resolved by engineer", json.dumps(v), now()))
    con.commit(); await broadcast({"type": "incident", "data": summary(iid)})
    return dict(ok=True, message="Approved (simulated). No production change was executed." if a == "approve" else "Recorded.")

@app.post("/api/copilot/query")
async def copilot(body=Body(...)):
    iid = body.get("incident_id") or (con.execute("select id from incidents order by rowid desc limit 1").fetchone() or [None])[0]
    if not iid: return dict(answer="No incident exists yet. Start the demo or ingest telemetry first.", grounded=False)
    s = story(iid); q = (body.get("question") or "").lower(); ans = rule_answer(q, s)
    # history: prior turns from this conversation, e.g. [{"role":"user"|"assistant","content":str}, ...]
    history = [h for h in (body.get("history") or []) if h.get("role") in ("user", "assistant") and h.get("content")][-8:]
    evidence_msg = (f"Incident evidence JSON:\n{json.dumps(s['analysis'], default=str)[:12000]}\n"
                     f"Blast radius: {json.dumps(s['blast'], default=str)}\nWhat changed: {json.dumps(s['changes'], default=str)}")
    messages = [{"role": "user", "content": evidence_msg}, {"role": "assistant", "content": "Understood — I'll ground every answer in this evidence only."}] + history + [{"role": "user", "content": body.get("question") or ""}]
    t = await llm(messages)
    return dict(answer=t or ans, grounded=True, incident_id=iid, engine=LLM_PROVIDER if t else "rules")

@app.get("/api/sources")
def sources():
    return dict(counts={r["source"]: r["c"] for r in con.execute("select source, count(*) c from telemetry_events group by source")}, demo_running=sim["on"],
        endpoints=["POST /api/telemetry/logs", "POST /api/telemetry/metrics", "POST /api/telemetry/traces", "POST /api/telemetry/otlp", "POST /api/telemetry/upload", "POST /api/telemetry/agent"],
        real_monitors=dict(postgresql=bool(collectors.PG_DSN), mysql=bool(collectors.MYSQL_DSN), redis=bool(collectors.REDIS_URL), docker=collectors.DOCKER_MONITOR))
@app.get("/api/settings")
def settings():
    return dict(llm_provider=LLM_PROVIDER, llm_model=LLM_MODEL or None, llm_key_configured=bool(LLM_API_KEY), database=DB, tick_seconds=TICK, thresholds=dict(anomaly=ANOM, open=OPEN),
        real_monitors=dict(postgresql=bool(collectors.PG_DSN), mysql=bool(collectors.MYSQL_DSN), redis=bool(collectors.REDIS_URL), docker=collectors.DOCKER_MONITOR),
        agent_token_required=bool(AGENT_TOKEN))

@app.on_event("startup")
async def start_real_monitors():
    """Launch any real Postgres/MySQL/Redis/Docker collectors whose env var is configured. No-ops otherwise."""
    collectors.start_all(run, asyncio.create_task)

@app.post("/api/demo/start")
async def demo_start():
    if sim["on"]: return dict(status="running")
    con.execute("update incidents set status='Closed' where status not in ('Resolved','Closed') and source='DEMO'"); con.commit()
    sim.update(on=True, t=0, rec=False, v=dict(BASE), noted=0); sim["task"] = asyncio.create_task(sim_loop()); return dict(status="started")
@app.post("/api/demo/stop")
async def demo_stop(): sim["on"] = False; return dict(status="stopped")
@app.post("/api/demo/reset")
async def demo_reset():
    sim["on"] = False; await asyncio.sleep(TICK + .2)
    for t in ("telemetry_events", "incidents", "incident_memory"): con.execute(f"delete from {t}")
    con.commit(); recent.clear(); stamps.clear(); await broadcast({"type": "refresh"}); return dict(status="reset")
