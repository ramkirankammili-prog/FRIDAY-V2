"""
FRIDAY Agent — real Windows / Linux host monitoring.

Run this script ON the machine you want to monitor (Windows or Linux; anywhere
Python + psutil work). It collects REAL CPU, memory, disk, and network metrics
every few seconds and POSTs them to a running FRIDAY backend, where they flow
through the same ingestion → anomaly-detection → incident pipeline as every
other telemetry source (tagged source="AGENT").

Install:
    pip install psutil requests

    # optional, only needed if you also want this host's Docker containers monitored:
    pip install docker

Run:
    # Linux / macOS
    export FRIDAY_API_BASE=http://localhost:8000
    export AGENT_TOKEN=changeme        # must match backend's AGENT_TOKEN, if set
    python agent.py

    # Windows PowerShell
    $env:FRIDAY_API_BASE="http://localhost:8000"
    $env:AGENT_TOKEN="changeme"
    python agent.py

The agent works unmodified on both Windows and Linux — psutil abstracts the OS
differences (disk root is auto-detected: "C:\\" on Windows, "/" elsewhere).
"""
import os, sys, time, socket, platform, json

try:
    import psutil
except ImportError:
    sys.exit("psutil is required: pip install psutil")

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

API_BASE = os.getenv("FRIDAY_API_BASE", "http://localhost:8000").rstrip("/")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
INTERVAL = float(os.getenv("AGENT_INTERVAL", "5"))
HOST = os.getenv("AGENT_HOST_NAME", socket.gethostname())
OS_NAME = platform.system()  # "Windows", "Linux", "Darwin"
SERVICE = os.getenv("AGENT_SERVICE_NAME", f"host:{HOST}")
DISK_ROOT = os.getenv("AGENT_DISK_ROOT") or ("C:\\" if OS_NAME == "Windows" else "/")
ENABLE_DOCKER = os.getenv("AGENT_DOCKER", "0") == "1"

session = requests.Session()
if AGENT_TOKEN:
    session.headers.update({"Authorization": f"Bearer {AGENT_TOKEN}"})


def collect_host_metrics():
    ts = None  # let the backend stamp the receive time if we don't set one; we set it anyway below
    cpu = psutil.cpu_percent(interval=1)  # blocks ~1s, gives a real (not instantaneous-garbage) reading
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(DISK_ROOT)
    net = psutil.net_io_counters()
    load = None
    try:
        load = os.getloadavg()[0]  # not available on Windows
    except (AttributeError, OSError):
        pass

    items = [
        dict(service=SERVICE, metric="cpu_pct", value=round(cpu, 1), event_type="metric", host=HOST, environment=OS_NAME, message=f"cpu_pct={cpu:.1f}%"),
        dict(service=SERVICE, metric="mem_pct", value=round(mem.percent, 1), event_type="metric", host=HOST, environment=OS_NAME, message=f"mem_pct={mem.percent:.1f}% ({mem.used // (1024**2)}MB/{mem.total // (1024**2)}MB)"),
        dict(service=SERVICE, metric="disk_pct", value=round(disk.percent, 1), event_type="metric", host=HOST, environment=OS_NAME, message=f"disk_pct={disk.percent:.1f}% on {DISK_ROOT}"),
        dict(service=SERVICE, metric="net_sent_kb", value=round(net.bytes_sent / 1024, 1), event_type="metric", host=HOST, environment=OS_NAME, message="cumulative bytes sent"),
        dict(service=SERVICE, metric="net_recv_kb", value=round(net.bytes_recv / 1024, 1), event_type="metric", host=HOST, environment=OS_NAME, message="cumulative bytes received"),
    ]
    if load is not None:
        items.append(dict(service=SERVICE, metric="load_avg_1m", value=round(load, 2), event_type="metric", host=HOST, environment=OS_NAME, message=f"load_avg_1m={load:.2f}"))

    if cpu >= 90:
        items.append(dict(service=SERVICE, severity="WARNING", event_type="log", message=f"High CPU on {HOST}: {cpu:.1f}%", host=HOST, environment=OS_NAME))
    if mem.percent >= 90:
        items.append(dict(service=SERVICE, severity="WARNING", event_type="log", message=f"High memory on {HOST}: {mem.percent:.1f}%", host=HOST, environment=OS_NAME))
    if disk.percent >= 90:
        items.append(dict(service=SERVICE, severity="ERROR", event_type="log", message=f"Low disk space on {HOST}: {disk.percent:.1f}% used", host=HOST, environment=OS_NAME))
    return items


def collect_docker_metrics():
    try:
        import docker
    except ImportError:
        return []
    try:
        client = docker.from_env()
    except Exception:
        return []
    items = []
    for c in client.containers.list(all=True):
        svc = f"docker:{c.name}"
        if c.status != "running":
            items.append(dict(service=svc, severity="ERROR", event_type="service_failure", message=f"Container {c.name} is {c.status}", host=HOST))
            continue
        try:
            st = c.stats(stream=False)
            cpu_delta = st["cpu_stats"]["cpu_usage"]["total_usage"] - st["precpu_stats"]["cpu_usage"]["total_usage"]
            sys_delta = st["cpu_stats"]["system_cpu_usage"] - st["precpu_stats"]["system_cpu_usage"]
            ncpu = st["cpu_stats"].get("online_cpus") or len(st["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1])
            cpu_pct = round(100 * cpu_delta / sys_delta * ncpu, 1) if sys_delta > 0 else 0.0
            mem_usage, mem_limit = st["memory_stats"].get("usage", 0), st["memory_stats"].get("limit", 1)
            mem_pct = round(100 * mem_usage / mem_limit, 1) if mem_limit else 0.0
            items.append(dict(service=svc, metric="cpu_pct", value=cpu_pct, event_type="metric", host=HOST, message=f"cpu_pct={cpu_pct}%"))
            items.append(dict(service=svc, metric="mem_pct", value=mem_pct, event_type="metric", host=HOST, message=f"mem_pct={mem_pct}%"))
        except Exception:
            continue
    return items


def send(items):
    if not items: return
    try:
        r = session.post(f"{API_BASE}/api/telemetry/agent", json=items, timeout=10)
        if r.status_code >= 400:
            print(f"[agent] backend rejected batch: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[agent] failed to reach {API_BASE}: {e}")


def main():
    print(f"[agent] FRIDAY Agent starting — host={HOST} os={OS_NAME} target={API_BASE} interval={INTERVAL}s docker={ENABLE_DOCKER}")
    while True:
        items = collect_host_metrics()
        if ENABLE_DOCKER:
            items += collect_docker_metrics()
        send(items)
        time.sleep(max(0, INTERVAL - 1))  # cpu_percent(interval=1) already spent ~1s


if __name__ == "__main__":
    main()
