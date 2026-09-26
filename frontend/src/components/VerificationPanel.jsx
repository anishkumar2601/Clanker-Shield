import React from "react";
import { ShieldCheckIcon, XIcon, AlertTriangleIcon } from "../icons.jsx";
import { Button, EmptyState } from "./common.jsx";

const VERDICT_META = {
  STATICALLY_VERIFIED: { cls: "verdict-verified", Icon: ShieldCheckIcon, label: "Statically verified" },
  FAILED_NEW_FINDINGS: { cls: "verdict-failed", Icon: XIcon, label: "Target fixed, new high-risk findings detected" },
  FAILED: { cls: "verdict-failed", Icon: XIcon, label: "Failed" },
  NOT_VERIFIED: { cls: "verdict-pending", Icon: AlertTriangleIcon, label: "Not verified" },
};

function CountRow({ label, before, after }) {
  const delta = (after ?? 0) - (before ?? 0);
  return (
    <div className="verify-count-row">
      <span>{label}</span>
      <span className="verify-count-values">
        {before} <span className="verify-arrow">→</span> {after}
        <span className={`verify-delta ${delta < 0 ? "delta-good" : delta > 0 ? "delta-bad" : "delta-flat"}`}>
          {delta === 0 ? "no change" : delta < 0 ? `${delta}` : `+${delta}`}
        </span>
      </span>
    </div>
  );
}

export default function VerificationPanel({ verification, onVerify, verifying, canVerify }) {
  return (
    <section id="reports" className="section-block">
      <div className="section-heading">
        <h2>Verification &amp; security diff</h2>
        <p>Each layer reports exactly what passed. Static verification does not imply runtime or regression-test verification.</p>
      </div>

      <div className="verification-panel">
        <div className="verification-actions">
          <Button variant="primary" onClick={onVerify} loading={verifying} disabled={!canVerify}>
            Verify with rescan
          </Button>
          {!canVerify && <span className="verify-hint">Apply a patch first, or rescan to establish a baseline.</span>}
        </div>

        {!verification ? (
          <EmptyState title="No verification run yet" detail="Results will include static rescan, syntax, regression-test, and runtime statuses." />
        ) : (
          <>
            {(() => {
              const meta = VERDICT_META[verification.verdict] || VERDICT_META.NOT_VERIFIED;
              const Icon = meta.Icon;
              return (
                <div className={`verify-verdict ${meta.cls}`}>
                  <Icon size={18} /> {meta.label}
                </div>
              );
            })()}

            <div className="verify-grid">
              <CountRow label="Critical" before={verification.diff.before_severity_counts.critical} after={verification.diff.after_severity_counts.critical} />
              <CountRow label="High" before={verification.diff.before_severity_counts.high} after={verification.diff.after_severity_counts.high} />
              <CountRow label="Medium" before={verification.diff.before_severity_counts.medium} after={verification.diff.after_severity_counts.medium} />
              <CountRow label="Low" before={verification.diff.before_severity_counts.low} after={verification.diff.after_severity_counts.low} />
            </div>

            <div className="verify-summary-row">
              <div><span className="ai-panel-label">Resolved</span><span className="ai-panel-strong">{verification.diff.resolved_count}</span></div>
              <div><span className="ai-panel-label">Remaining</span><span className="ai-panel-strong">{verification.diff.remaining_count}</span></div>
              <div><span className="ai-panel-label">New findings</span><span className="ai-panel-strong">{verification.diff.new_findings_count}</span></div>
              <div><span className="ai-panel-label">Total risk delta</span><span className="ai-panel-strong">{verification.diff.risk_delta}</span></div>
            </div>

            <div className="verify-footnotes">
              <span>Static scan: {verification.static_scan || "NOT_RUN"}</span>
              <span>Syntax: {verification.syntax_verification || (verification.syntax_check.passed ? "PASS" : "FAIL")}</span>
              <span>Existing tests: {verification.existing_tests || "NOT_RUN"}</span>
              <span>Security regression: {verification.security_regression_test || "NOT_RUN"}</span>
              <span>Runtime: {verification.runtime_verification || verification.runtime_tests || "NOT_AVAILABLE"}</span>
            </div>

            {verification.diff.resolved.length > 0 && (
              <div className="verify-resolved-list">
                <span className="ai-panel-label">Resolved this run</span>
                {verification.diff.resolved.map((f) => (
                  <div key={f.id} className="verify-resolved-item">
                    <ShieldCheckIcon size={13} /> {f.title} <code>{f.file}:{f.line}</code>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
