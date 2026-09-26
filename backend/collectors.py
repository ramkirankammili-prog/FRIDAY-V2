"""Real infrastructure monitoring collectors — PostgreSQL, MySQL, Redis, Docker.

Each collector polls a REAL service on an interval and feeds metrics into FRIDAY's
normal ingestion pipeline (the `run()` coroutine passed in from main.py), tagged with
source="REAL" so they're distinguishable from DEMO/simulated telemetry but still flow
through the same normalisation / anomaly-detection / incident-opening logic.

All third-party clients (psycopg2, mysql-connector, redis, docker) are imported lazily
and optionally — if a driver isn't installed, or its env var isn't set, that collector
simply logs a message and exits instead of crashing the app.
"""
import os, time, asyncio
from datetime import datetime, timezone

now = lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
INTERVAL = float(os.getenv("REAL_MONITOR_INTERVAL", "5"))

PG_DSN = os.getenv("PG_DSN", "")
MYSQL_DSN = os.getenv("MYSQL_DSN", "")  # e.g. host=localhost;user=root;password=pw;database=db
REDIS_URL = os.getenv("REDIS_URL", "")
DOCKER_MONITOR = os.getenv("DOCKER_MONITOR", "0") == "1"


def _parse_mysql_dsn(dsn):
    out = {}
    for part in dsn.split(";"):
        if "=" in part:
            k, v = part.split("=", 1); out[k.strip()] = v.strip()
    return out


async def postgres_loop(run):
    if not PG_DSN: return
    try:
        import psycopg2
    except ImportError:
        print("[collectors] psycopg2 not installed — pip install psycopg2-binary. PostgreSQL monitoring disabled."); return
    print("[collectors] Real PostgreSQL monitoring started.")
    while True:
        try:
            t0 = time.time()
            conn = psycopg2.connect(PG_DSN, connect_timeout=5); cur = conn.cursor()
            cur.execute("SELECT 1"); cur.fetchone()
            latency_ms = (time.time() - t0) * 1000
            cur.execute("SELECT count(*) FROM pg_stat_activity"); active = cur.fetchone()[0]
            cur.execute("SHOW max_connections"); max_conn = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM pg_stat_activity WHERE state='active' AND now()-query_start > interval '1 second'")
            slow = cur.fetchone()[0]
            cur.close(); conn.close()
            pool_util = round(100 * active / max_conn, 1) if max_conn else 0.0
            ts = now()
            items = [
                dict(service="postgresql", metric="db_latency_ms", value=round(latency_ms, 1), event_type="metric", timestamp=ts, message=f"db_latency_ms={latency_ms:.1f}"),
                dict(service="postgresql", metric="pool_util", value=pool_util, event_type="metric", timestamp=ts, message=f"pool_util={pool_util}% ({active}/{max_conn} connections)"),
            ]
            if slow: items.append(dict(service="postgresql", severity="WARNING", event_type="slow_query", message=f"{slow} slow quer{'y' if slow == 1 else 'ies'} (>1s) detected", timestamp=ts))
            await run(items, "REAL")
        except Exception as e:
            await run([dict(service="postgresql", severity="ERROR", event_type="service_failure", message=f"PostgreSQL monitor: connection failed ({e})", timestamp=now())], "REAL")
        await asyncio.sleep(INTERVAL)


async def mysql_loop(run):
    if not MYSQL_DSN: return
    try:
        import mysql.connector
    except ImportError:
        print("[collectors] mysql-connector-python not installed. MySQL monitoring disabled."); return
    print("[collectors] Real MySQL monitoring started.")
    cfg = _parse_mysql_dsn(MYSQL_DSN)
    while True:
        try:
            t0 = time.time()
            conn = mysql.connector.connect(connection_timeout=5, **cfg); cur = conn.cursor()
            cur.execute("SELECT 1"); cur.fetchone()
            latency_ms = (time.time() - t0) * 1000
            cur.execute("SHOW STATUS LIKE 'Threads_connected'"); active = int(cur.fetchone()[1])
            cur.execute("SHOW VARIABLES LIKE 'max_connections'"); max_conn = int(cur.fetchone()[1])
            cur.execute("SHOW STATUS LIKE 'Slow_queries'"); slow = int(cur.fetchone()[1])
            cur.close(); conn.close()
            pool_util = round(100 * active / max_conn, 1) if max_conn else 0.0
            ts = now()
            items = [
                dict(service="mysql", metric="db_latency_ms", value=round(latency_ms, 1), event_type="metric", timestamp=ts, message=f"db_latency_ms={latency_ms:.1f}"),
                dict(service="mysql", metric="pool_util", value=pool_util, event_type="metric", timestamp=ts, message=f"pool_util={pool_util}% ({active}/{max_conn} connections)"),
            ]
            if slow: items.append(dict(service="mysql", severity="WARNING", event_type="slow_query", message=f"Cumulative slow query count: {slow}", timestamp=ts))
            await run(items, "REAL")
        except Exception as e:
            await run([dict(service="mysql", severity="ERROR", event_type="service_failure", message=f"MySQL monitor: connection failed ({e})", timestamp=now())], "REAL")
        await asyncio.sleep(INTERVAL)


async def redis_loop(run):
    if not REDIS_URL: return
    try:
        import redis
    except ImportError:
        print("[collectors] redis-py not installed — pip install redis. Redis monitoring disabled."); return
    print("[collectors] Real Redis monitoring started.")
    client = redis.from_url(REDIS_URL, socket_connect_timeout=5, socket_timeout=5)
    while True:
        try:
            t0 = time.time(); client.ping(); latency_ms = (time.time() - t0) * 1000
            info = client.info()
            hits, misses = info.get("keyspace_hits", 0), info.get("keyspace_misses", 0)
            cache_hit_pct = round(100 * hits / (hits + misses), 1) if (hits + misses) else 100.0
            ts = now()
            items = [
                dict(service="redis", metric="db_latency_ms", value=round(latency_ms, 1), event_type="metric", timestamp=ts, message=f"redis latency={latency_ms:.1f} ms"),
                dict(service="redis", metric="cache_hit_pct", value=cache_hit_pct, event_type="metric", timestamp=ts, message=f"cache_hit_pct={cache_hit_pct}%"),
                dict(service="redis", metric="connected_clients", value=float(info.get("connected_clients", 0)), event_type="metric", timestamp=ts, message=f"connected_clients={info.get('connected_clients', 0)}"),
            ]
            used_mem, max_mem = info.get("used_memory", 0), info.get("maxmemory", 0)
            if max_mem: items.append(dict(service="redis", metric="pool_util", value=round(100 * used_mem / max_mem, 1), event_type="metric", timestamp=ts, message="memory utilization"))
            await run(items, "REAL")
        except Exception as e:
            await run([dict(service="redis", severity="ERROR", event_type="service_failure", message=f"Redis monitor: connection failed ({e})", timestamp=now())], "REAL")
        await asyncio.sleep(INTERVAL)


async def docker_loop(run):
    if not DOCKER_MONITOR: return
    try:
        import docker
    except ImportError:
        print("[collectors] docker SDK not installed — pip install docker. Docker monitoring disabled."); return
    try:
        client = docker.from_env()
    except Exception as e:
        print(f"[collectors] Docker daemon not reachable ({e}). Docker monitoring disabled."); return
    print("[collectors] Real Docker container monitoring started.")
    while True:
        try:
            ts = now(); items = []
            for c in client.containers.list(all=True):
                svc = f"docker:{c.name}"
                if c.status != "running":
                    items.append(dict(service=svc, severity="ERROR", event_type="service_failure", message=f"Container {c.name} is {c.status}", host=c.name, timestamp=ts)); continue
                try:
                    st = c.stats(stream=False)
                    cpu_delta = st["cpu_stats"]["cpu_usage"]["total_usage"] - st["precpu_stats"]["cpu_usage"]["total_usage"]
                    sys_delta = st["cpu_stats"]["system_cpu_usage"] - st["precpu_stats"]["system_cpu_usage"]
                    ncpu = st["cpu_stats"].get("online_cpus") or len(st["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1])
                    cpu_pct = round(100 * cpu_delta / sys_delta * ncpu, 1) if sys_delta > 0 else 0.0
                    mem_usage, mem_limit = st["memory_stats"].get("usage", 0), st["memory_stats"].get("limit", 1)
                    mem_pct = round(100 * mem_usage / mem_limit, 1) if mem_limit else 0.0
                    items.append(dict(service=svc, metric="cpu_pct", value=cpu_pct, event_type="metric", host=c.name, timestamp=ts, message=f"cpu_pct={cpu_pct}%"))
                    items.append(dict(service=svc, metric="mem_pct", value=mem_pct, event_type="metric", host=c.name, timestamp=ts, message=f"mem_pct={mem_pct}%"))
                    if cpu_pct >= 90: items.append(dict(service=svc, severity="WARNING", event_type="log", message=f"Container {c.name} CPU at {cpu_pct}%", host=c.name, timestamp=ts))
                except Exception: continue
            if items: await run(items, "REAL")
        except Exception as e:
            print(f"[collectors] docker loop error: {e}")
        await asyncio.sleep(INTERVAL)


def start_all(run, create_task):
    """Kick off every collector whose env var is configured. Safe to call unconditionally."""
    tasks = []
    for loop, enabled in ((postgres_loop, bool(PG_DSN)), (mysql_loop, bool(MYSQL_DSN)), (redis_loop, bool(REDIS_URL)), (docker_loop, DOCKER_MONITOR)):
        if enabled: tasks.append(create_task(loop(run)))
    return tasks
