import React, { useMemo, useState } from "react";
import { SearchIcon, ShieldCheckIcon, SparkleIcon } from "../icons.jsx";
import { SeverityBadge, ResolvedBadge, Button, EmptyState, Skeleton } from "./common.jsx";

const FILTERS = ["all", "critical", "high", "medium", "low"];

function RiskBar({ label, value }) {
  return (
    <div className="risk-bar-row">
      <span className="risk-bar-label">{label}</span>
      <div className="risk-bar-track">
        <div className="risk-bar-fill" style={{ width: `${Math.min(100, (value / 10) * 100)}%` }} />
      </div>
      <span className="risk-bar-value">{value}</span>
    </div>
  );
}

export default function FindingsQueue({ findings, loading, selected, onSelect, onGenerateFix, fixingId, onUpdateStatus }) {
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [showResolved, setShowResolved] = useState(false);

  const visible = useMemo(() => {
    return (findings || [])
      .filter((f) => showResolved || !f.resolved)
      .filter((f) => filter === "all" || f.severity === filter)
      .filter((f) => !query || f.title.toLowerCase().includes(query.toLowerCase()) || f.file.toLowerCase().includes(query.toLowerCase()))
      .sort((a, b) => b.risk_score - a.risk_score);
  }, [findings, filter, query, showResolved]);

  return (
    <section id="vulnerabilities" className="section-block">
      <div className="section-heading">
        <h2>Repository security workspace</h2>
        <p>Every finding, prioritized by risk, with full evidence and a safe-fix path.</p>
      </div>

      <div className="workspace-grid">
        <div className="findings-queue">
          <div className="findings-toolbar">
            <div className="findings-search">
              <SearchIcon size={14} />
              <input placeholder="Search findings…" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <label className="findings-toggle">
              <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
              Show neutralized
            </label>
          </div>

          <div className="findings-filters">
            {FILTERS.map((f) => (
              <button key={f} className={`filter-chip filter-${f} ${filter === f ? "filter-chip-active" : ""}`} onClick={() => setFilter(f)}>
                {f === "all" ? "All" : f[0].toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>

          <div className="findings-list">
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} h={58} radius={12} />)
            ) : visible.length === 0 ? (
              <EmptyState icon={<ShieldCheckIcon size={22} />} title="Nothing matches this filter" />
            ) : (
              visible.map((f) => (
                <button
                  key={f.id}
                  className={`finding-row ${selected?.id === f.id ? "finding-row-active" : ""}`}
                  onClick={() => onSelect(f)}
                >
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="finding-row-title">{f.title}</span>
                  <span className="finding-row-loc"><code>{f.file}</code></span>
                  {f.resolved ? <ResolvedBadge /> : <span className="finding-row-score">{f.risk_score}</span>}
                </button>
              ))
            )}
          </div>
        </div>

        <div className="finding-detail">
          {!selected ? (
            <EmptyState title="Select a finding" detail="Its evidence, risk breakdown, and attack path will appear here." />
          ) : (
            <>
              <div className="finding-detail-header">
                <SeverityBadge severity={selected.severity} />
                {selected.resolved && <ResolvedBadge />}
                <span className="finding-detail-status">{selected.lifecycle_status || "OPEN"}</span>
                <span className="finding-detail-cwe">{selected.cwe}</span>
              </div>
              <h3 className="finding-detail-title">{selected.title}</h3>
              <code className="finding-detail-loc">{selected.file}:{selected.line}</code>

              <pre className="code-evidence"><code>{selected.snippet}</code></pre>

              <p className="finding-detail-text"><strong>Why it matters:</strong> {selected.explanation}</p>
              <p className="finding-detail-text"><strong>Impact:</strong> {selected.impact}</p>

              <div className="risk-breakdown">
                <span className="ai-panel-label">Risk breakdown · {selected.risk_score}/100</span>
                {Object.entries(selected.risk_breakdown || {}).map(([k, v]) => (
                  <RiskBar key={k} label={k.replace(/_/g, " ")} value={v} />
                ))}
              </div>

              {selected.attack_path?.length > 0 && (
                <div className="attack-path">
                  <span className="ai-panel-label">Attack path</span>
                  <div className="attack-path-steps">
                    {selected.attack_path.map((step) => (
                      <div key={step.step} className="attack-path-step">
                        <span className="attack-path-index">{step.step}</span>
                        <div>
                          <div className="attack-path-node">{step.node}</div>
                          <div className="attack-path-desc">{step.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="finding-detail-actions">
                {selected.lifecycle_status === "FALSE_POSITIVE" || selected.lifecycle_status === "ACCEPTED_RISK" ? (
                  <div className="finding-suppressed-note">
                    <strong>{selected.lifecycle_status.replace("_", " ")}</strong>
                    <span>{selected.suppression_reason}</span>
                    <Button variant="secondary" size="sm" onClick={() => onUpdateStatus?.(selected, "REOPENED")}>Reopen finding</Button>
                  </div>
                ) : selected.resolved ? (
                  <span className="finding-resolved-note"><ShieldCheckIcon size={14} /> Finding absent after static rescan; runtime behavior not verified.</span>
                ) : selected.patch_available ? (
                  <Button variant="primary" onClick={() => onGenerateFix(selected)} loading={fixingId === selected.id}>
                    <SparkleIcon size={14} /> Generate safe fix
                  </Button>
                ) : (
                  <span className="finding-resolved-note">No automatic patch pattern available — follow the remediation guidance above.</span>
                )}
                {!selected.resolved && selected.lifecycle_status !== "FALSE_POSITIVE" && selected.lifecycle_status !== "ACCEPTED_RISK" && (
                  <div className="finding-lifecycle-actions">
                    <Button variant="secondary" size="sm" onClick={() => onUpdateStatus?.(selected, "FALSE_POSITIVE")}>False positive</Button>
                    <Button variant="secondary" size="sm" onClick={() => onUpdateStatus?.(selected, "ACCEPTED_RISK")}>Accept risk</Button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
