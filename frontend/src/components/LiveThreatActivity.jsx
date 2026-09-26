import React from "react";
import { AlertTriangleIcon, ShieldCheckIcon } from "../icons.jsx";
import { SeverityBadge, Skeleton, EmptyState, Sparkbars } from "./common.jsx";

export default function LiveThreatActivity({ findings, loading, onSelect, selectedId }) {
  return (
    <section id="threats" className="section-block">
      <div className="section-heading">
        <h2>Live threat activity</h2>
        <p>Real findings from this scan, ranked by risk.</p>
      </div>

      {loading ? (
        <div className="threat-activity-row">
          {[0, 1, 2].map((i) => <Skeleton key={i} w={280} h={132} radius={20} />)}
        </div>
      ) : !findings || findings.length === 0 ? (
        <EmptyState
          icon={<ShieldCheckIcon size={28} />}
          title="No findings in the latest scan"
          detail="ClankerShield didn't detect any issues matching its rules in this repository."
        />
      ) : (
        <div className="threat-activity-row">
          {findings.map((f) => (
            <button
              key={f.id}
              className={`threat-card ${selectedId === f.id ? "threat-card-active" : ""} ${f.resolved ? "threat-card-resolved" : ""}`}
              onClick={() => onSelect(f)}
            >
              <div className="threat-card-top">
                <SeverityBadge severity={f.severity} size="sm" />
                {f.resolved && <ShieldCheckIcon size={14} style={{ color: "var(--green)" }} />}
              </div>
              <div className="threat-card-title">{f.title}</div>
              <div className="threat-card-loc"><code>{f.file}:{f.line}</code></div>
              <div className="threat-card-meta">
                <span>{f.sources?.join(", ") || "builtin"}</span>
                <span>{Math.round((f.confidence || 0) * 100)}% confidence</span>
              </div>
              <div className="threat-card-footer">
                <span className="threat-card-score">Risk {f.risk_score}</span>
                <Sparkbars values={[f.risk_score * 0.4, f.risk_score * 0.7, f.risk_score].map(v => Math.max(2, v))} tone={f.severity === "critical" || f.severity === "high" ? "red" : "amber"} />
              </div>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
