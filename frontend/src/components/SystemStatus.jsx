import React from "react";
import { CheckIcon, AlertTriangleIcon, CpuIcon } from "../icons.jsx";

function StatusItem({ ok, label, okLabel, warnLabel }) {
  return (
    <div className={`status-item ${ok ? "status-ok" : "status-warn"}`}>
      {ok ? <CheckIcon size={13} /> : <AlertTriangleIcon size={13} />}
      <span>{label}</span>
      <span className="status-item-state">{ok ? okLabel : warnLabel}</span>
    </div>
  );
}

export default function SystemStatus({ health, repo }) {
  return (
    <section id="system-status" className="section-block">
      <div className="section-heading">
        <h2>System status</h2>
        <p>What's actually running behind this scan — no capability is claimed unless it's really available.</p>
      </div>
      <div className="status-strip">
        <StatusItem ok={!!health?.semgrep_available} label="Semgrep" okLabel="Installed" warnLabel="Not installed" />
        <StatusItem ok={!!health?.bandit_available} label="Bandit" okLabel="Installed" warnLabel="Not installed" />
        <StatusItem ok={!!health?.osv_enabled} label="OSV advisories" okLabel="Enabled" warnLabel="Opt-in" />
        <div className={`status-item ${health?.ai_configured ? "status-ok" : "status-warn"}`}>
          <CpuIcon size={13} />
          <span>AI provider</span>
          <span className="status-item-state">{health?.ai_configured ? "Configured" : "Local fallback"}</span>
        </div>
        <div className="status-item status-neutral">
          <CheckIcon size={13} />
          <span>Last scan</span>
          <span className="status-item-state">{repo?.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleTimeString() : "—"}</span>
        </div>
        <div className="status-item status-neutral">
          <CheckIcon size={13} />
          <span>Scan count</span>
          <span className="status-item-state">{repo?.scan_count ?? 0}</span>
        </div>
      </div>
    </section>
  );
}
