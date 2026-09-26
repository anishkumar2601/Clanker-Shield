import React from "react";
import { BugIcon, ShieldCheckIcon, AlertOctagonIcon, GaugeIcon } from "../icons.jsx";
import { Skeleton, ScoreRing, Sparkbars } from "./common.jsx";

function MetricCard({ icon, tone, label, value, sub, children, loading }) {
  return (
    <div className={`metric-card tone-${tone}`}>
      <div className="metric-card-top">
        <span className={`metric-icon tone-${tone}`}>{icon}</span>
        {children}
      </div>
      {loading ? (
        <Skeleton w={72} h={38} radius={10} style={{ margin: "14px 0 8px" }} />
      ) : (
        <div className="metric-value">{value}</div>
      )}
      <div className="metric-label">{label}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

export default function MetricCards({ metrics, history = [], loading }) {
  if (!loading && !metrics) {
    return (
      <section className="metric-grid">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="metric-card tone-cyan metric-card-empty">
            <span className="metric-icon tone-cyan"><GaugeIcon size={18} /></span>
            <div className="metric-value">—</div>
            <div className="metric-label">Run a scan to see this metric</div>
          </div>
        ))}
      </section>
    );
  }

  const m = metrics || {};
  const historyBars = history.map((record) => Math.max(0, record.findings?.threats_detected ?? 0));
  const hasHistory = history.length > 1;
  const historyOrEmpty = (values, tone) => hasHistory
    ? <Sparkbars values={values} tone={tone} />
    : <span className="metric-no-history">No historical data yet</span>;

  return (
    <section className="metric-grid">
      <MetricCard
        icon={<BugIcon size={18} />} tone="red" loading={loading}
        label="Threats detected" value={m.threats_detected}
        sub={loading ? null : "Across all scanners, this scan"}
      >
        {!loading && historyOrEmpty(historyBars, "red")}
      </MetricCard>

      <MetricCard
        icon={<ShieldCheckIcon size={18} />} tone="green" loading={loading}
        label="Threats neutralized" value={m.threats_neutralized}
        sub={loading ? null : "Absent after static rescan"}
      >
        {!loading && historyOrEmpty(history.map((record) => Math.max(0, record.findings?.threats_neutralized ?? 0)), "green")}
      </MetricCard>

      <MetricCard
        icon={<AlertOctagonIcon size={18} />} tone="amber" loading={loading}
        label="Active vulnerabilities" value={m.active_vulnerabilities}
        sub={loading ? null : `${m.critical_count || 0} critical · ${m.high_count || 0} high`}
      >
        {!loading && historyOrEmpty(history.map((record) => Math.max(0, record.findings?.active_vulnerabilities ?? 0)), "amber")}
      </MetricCard>

      <MetricCard
        icon={<GaugeIcon size={18} />} tone="cyan" loading={loading}
        label="Security risk score" value={loading ? null : `${m.security_risk_score ?? m.ai_security_score}`}
        sub={loading ? null : "Deterministic contextual score · 100 = lowest observed risk"}
      >
        {!loading && (
          <span className="tone-cyan" style={{ color: "var(--cyan)" }}>
            <ScoreRing value={m.security_risk_score ?? m.ai_security_score} size={40} stroke={5} />
          </span>
        )}
      </MetricCard>
    </section>
  );
}
