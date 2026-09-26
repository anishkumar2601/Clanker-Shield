import React from "react";
import { AlertOctagonIcon } from "../icons.jsx";
import { Skeleton } from "./common.jsx";

function ThreatGrid({ critical, high, total }) {
  const cells = Array.from({ length: 24 });
  const criticalCells = Math.min(critical, 24);
  const highCells = Math.min(high, 24 - criticalCells);
  return (
    <div className="threat-grid" aria-hidden="true">
      {cells.map((_, i) => {
        let cls = "cell-idle";
        if (i < criticalCells) cls = "cell-critical";
        else if (i < criticalCells + highCells) cls = "cell-high";
        return <span key={i} className={`threat-cell ${cls}`} style={{ animationDelay: `${i * 18}ms` }} />;
      })}
    </div>
  );
}

export default function FloatingThreatCard({ repo, loading }) {
  const m = repo?.metrics;
  return (
    <aside className="floating-threat-card">
      <div className="floating-threat-header">
        <span className="floating-threat-icon"><AlertOctagonIcon size={16} /></span>
        <span>Critical threats</span>
      </div>

      {loading ? (
        <Skeleton w={60} h={40} radius={10} />
      ) : (
        <div className="floating-threat-value">{m?.critical_count ?? 0}</div>
      )}

      <div className="floating-threat-row">
        <span className="floating-threat-label">High priority</span>
        <span className="floating-threat-figure">{loading ? "—" : m?.high_count ?? 0}</span>
      </div>
      <div className="floating-threat-row">
        <span className="floating-threat-label">Current scan</span>
        <span className="floating-threat-figure">{repo ? `#${repo.scan_count}` : "—"}</span>
      </div>

      {!loading && <ThreatGrid critical={m?.critical_count || 0} high={m?.high_count || 0} total={m?.threats_detected || 0} />}
    </aside>
  );
}
