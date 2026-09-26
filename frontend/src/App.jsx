import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [logs, setLogs] = useState([]);
  const [incident, setIncident] = useState(null);
  const [connected, setConnected] = useState(false);
  const [replayIndex, setReplayIndex] = useState(-1);
  const [replaying, setReplaying] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [metrics, setMetrics] = useState({
  cpu: 0,
  memory: 0,
  disk: 0
});
  useEffect(() => {
    const ws = new WebSocket("wss://friday-jnbd.onrender.com/ws");

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);

      if (message.type === "log") {
        setLogs((previous) => [
          message.data,
          ...previous,
        ].slice(0, 40));
      }

      if (message.type === "incident") {
        setIncident(message.data);
        setReplayIndex(-1);
        setReplaying(false);
      }
    };
  
    return () => ws.close();
  }, []);
  useEffect(() => {

  const fetchMetrics = async () => {

    try {

      const response = await fetch(
  "https://friday-v2.onrender.com/metrics/latest"
    );

      const data = await response.json();

      setMetrics(data);

    } catch (err) {

      console.log(err);

    }

  };

  fetchMetrics();

  const interval = setInterval(
    fetchMetrics,
    5000
  );

  return () => clearInterval(interval);

}, []);

  const startReplay = () => {
    if (!incident?.timeline?.length) return;

    setReplayIndex(0);
    setReplaying(true);

    let index = 0;

    const replay = setInterval(() => {
      index++;

      if (index >= incident.timeline.length) {
        clearInterval(replay);
        setReplaying(false);
        return;
      }

      setReplayIndex(index);
    }, 900);
  };

  const timeline = incident?.timeline || [];

  return (
    <div className={darkMode ? "app dark" : "app"}>

      {/* HEADER */}

      <header className="topbar">

        <div className="brand">

          <div className="brand-icon">
            F
          </div>

          <div>
            <h1>FRIDAY</h1>
            <p>
              AI Incident Intelligence Platform
            </p>
          </div>

        </div>


        <div className="header-actions">

          <div className="system-status">

            <span
              className={
                connected
                  ? "status-dot online-dot"
                  : "status-dot"
              }
            />

            {connected
              ? "LIVE MONITORING"
              : "OFFLINE"}

          </div>


          <button
            className="theme-button"
            onClick={() => setDarkMode(!darkMode)}
            title="Change theme"
          >
            {darkMode ? "☀" : "☾"}
          </button>

        </div>

      </header>


      {/* OVERVIEW */}

      <section className="overview">

        <div className="metric neumorphic">

          <span className="metric-label">
            MONITORED SERVICES
          </span>

          <strong>04</strong>

          <span className="metric-sub">
            All connected
          </span>

        </div>


        <div className="metric neumorphic">

          <span className="metric-label">
            EVENTS PROCESSED
          </span>

          <strong>{logs.length}</strong>

          <span className="metric-sub">
            Live telemetry
          </span>

        </div>


        <div className="metric neumorphic">

          <span className="metric-label">
            INCIDENT STATUS
          </span>

          <strong
            className={
              incident
                ? "danger-text"
                : "success-text"
            }
          >
            {incident ? "ACTIVE" : "NORMAL"}
          </strong>

          <span className="metric-sub">
            Real-time detection
          </span>

        </div>


        <div className="metric neumorphic">

          <span className="metric-label">
            SEVERITY
          </span>

          <strong
            className={
              incident
                ? "danger-text"
                : "success-text"
            }
          >
            {incident
              ? incident.severity
              : "LOW"}
          </strong>

          <span className="metric-sub">
            Current system state
          </span>

        </div>

      </section>
      <div className="metric neumorphic">

  <span className="metric-label">
    CPU USAGE
  </span>

  <strong>{metrics.cpu}%</strong>

  <span className="metric-sub">
    Live Metric
  </span>

</div>

<div className="metric neumorphic">

  <span className="metric-label">
    MEMORY USAGE
  </span>

  <strong>{metrics.memory}%</strong>

  <span className="metric-sub">
    Live Metric
  </span>

</div>

<div className="metric neumorphic">

  <span className="metric-label">
    DISK USAGE
  </span>

  <strong>{metrics.disk}%</strong>

  <span className="metric-sub">
    Live Metric
  </span>

</div>

      {/* MAIN */}

      <main className="main-grid">

 
        {/* PROCESS FLOW */}

        <section className="panel neumorphic">

          <div className="panel-title">

            <div>
              <span className="eyebrow">
                OBSERVABILITY PIPELINE
              </span>

              <h2>
                FRIDAY Processing Flow
              </h2>
            </div>

            <span className="live-badge">
              ● LIVE
            </span>

          </div>


          <div className="pipeline">

            {[
              ["01", "Telemetry", "Logs & system signals"],
              ["02", "Ingestion", "Collect & normalize"],
              ["03", "Correlation", "Connect related events"],
              ["04", "Detection", "Identify incidents"],
              ["05", "RCA", "Find likely root cause"],
              ["06", "Explanation", "Evidence-based analysis"],
            ].map((step, index) => (

              <div key={step[0]}>

                <div
                  className={
                    index === 4
                      ? "pipeline-step active-step"
                      : "pipeline-step"
                  }
                >

                  <div className="step-number">
                    {step[0]}
                  </div>

                  <div>
                    <strong>{step[1]}</strong>
                    <span>{step[2]}</span>
                  </div>

                </div>

                {index < 5 && (
                  <div className="pipeline-line" />
                )}

              </div>

            ))}

          </div>

        </section>


        {/* RCA */}

        <section className="panel neumorphic">

          {incident ? (

            <>

              <div className="incident-heading">

                <div>
                  <span className="eyebrow danger-eyebrow">
                    ACTIVE INCIDENT
                  </span>

                  <h2>
                    Root Cause Analysis
                  </h2>
                </div>

                <span className="critical-badge">
                  {incident.severity}
                </span>

              </div>


              <div className="root-cause">

                <span>LIKELY ROOT CAUSE</span>

                <h3>
                  {incident.root_cause}
                </h3>


                <div className="confidence-top">

                  <span>Confidence</span>

                  <strong>
                    {incident.confidence}%
                  </strong>

                </div>


                <div className="confidence-bar">

                  <div
                    style={{
                      width:
                        `${incident.confidence}%`,
                    }}
                  />

                </div>

              </div>


              <div className="analysis">

                <h3>
                  FRIDAY Analysis
                </h3>

                <p>
                  {incident.story ||
                    "FRIDAY detected an incident and is analyzing the available evidence."}
                </p>

              </div>


              <div className="evidence">

                <h3>Evidence</h3>

                <ul>

                  {incident.evidence?.map(
                    (item, index) => (

                      <li key={index}>
                        <span>✓</span>
                        {item}
                      </li>

                    )
                  )}

                </ul>

              </div>


              <button
                className="replay-button"
                onClick={startReplay}
                disabled={replaying}
              >
                {replaying
                  ? "REPLAYING INCIDENT..."
                  : "▶  REPLAY INCIDENT"}
              </button>

            </>

          ) : (

            <div className="normal-state">

              <div className="normal-icon">
                ✓
              </div>

              <span className="eyebrow">
                SYSTEM STATUS
              </span>

              <h2>
                All Systems Normal
              </h2>

              <p>
                FRIDAY is continuously monitoring
                your connected services.
              </p>

            </div>

          )}

        </section>

      </main>


      {/* TIMELINE */}

      {incident && (

        <section className="panel neumorphic story-panel">

          <div className="panel-title">

            <div>
              <span className="eyebrow">
                INCIDENT STORY
              </span>

              <h2>
                Failure Propagation Timeline
              </h2>
            </div>

            <span className="story-count">
              {timeline.length} EVENTS
            </span>

          </div>


          <div className="timeline">

            {(replaying
              ? timeline.slice(0, replayIndex + 1)
              : timeline
            ).map((event, index) => (

              <div
                className="timeline-item"
                key={index}
              >

                <div className="timeline-marker">
                  {index + 1}
                </div>

                <div className="timeline-content">

                  <div className="timeline-meta">

                    <span>
                      {event.timestamp}
                    </span>

                    <strong>
                      {event.service}
                    </strong>

                    <em>
                      {event.event_type}
                    </em>

                  </div>

                  <p>
                    {event.message}
                  </p>

                </div>

              </div>

            ))}

          </div>

        </section>

      )}


      {/* LIVE EVENTS */}

      <section className="panel neumorphic events-panel">

        <div className="panel-title">

          <div>
            <span className="eyebrow">
              REAL-TIME TELEMETRY
            </span>

            <h2>
              Live Event Stream
            </h2>
          </div>

          <span className="event-count">
            {logs.length} EVENTS
          </span>

        </div>


        <div className="event-table">

          <div className="event-header">
            <span>TIME</span>
            <span>SERVICE</span>
            <span>LEVEL</span>
            <span>EVENT</span>
          </div>


          {logs.length === 0 ? (

            <div className="empty-events">
              Waiting for telemetry...
            </div>

          ) : (

            logs.map((log, index) => (

              <div
                className="event-row"
                key={index}
              >

                <span className="event-time">
                  {log.timestamp}
                </span>

                <strong>
                  {log.service}
                </strong>

                <span
                  className={
                    log.level === "ERROR"
                      ? "level error-level"
                      : "level info-level"
                  }
                >
                  {log.level}
                </span>

                <span className="event-message">
                  {log.message}
                </span>

              </div>

            ))

          )}

        </div>

      </section>


      <footer>
        FRIDAY • AI Incident Intelligence • Continuous Monitoring
      </footer>

    </div>
  );
}

export default App;