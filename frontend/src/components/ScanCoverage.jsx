import React from "react";
import { AlertTriangleIcon, CheckIcon, XIcon } from "../icons.jsx";

const STATUS = {
  completed: { label: "PASS", cls: "coverage-pass", Icon: CheckIcon },
  not_enabled: { label: "NOT ENABLED", cls: "coverage-neutral", Icon: AlertTriangleIcon },
  not_installed: { label: "NOT INSTALLED", cls: "coverage-neutral", Icon: AlertTriangleIcon },
  not_run: { label: "NOT RUN", cls: "coverage-neutral", Icon: AlertTriangleIcon },
  unavailable: { label: "UNAVAILABLE", cls: "coverage-warn", Icon: AlertTriangleIcon },
  timeout: { label: "TIMEOUT", cls: "coverage-fail", Icon: XIcon },
  failed: { label: "FAILED", cls: "coverage-fail", Icon: XIcon },
};

function CoverageValue({ label, value }) {
  return <div className="coverage-value"><span>{label}</span><strong>{value ?? 0}</strong></div>;
}

export default function ScanCoverage({ coverage }) {
  if (!coverage) return null;
  return (
    <section className="section-block scan-coverage" id="scan-coverage">
      <div className="section-heading">
        <h2>Scan coverage</h2>
        <p>What the latest scan actually inspected, and which analyzers were available.</p>
      </div>
      <div className="coverage-summary">
        <CoverageValue label="Files discovered" value={coverage.files_discovered} />
        <CoverageValue label="Files analyzed" value={coverage.files_analyzed} />
        <CoverageValue label="Files skipped" value={coverage.files_skipped} />
        <CoverageValue label="Binary files" value={coverage.binary_files} />
        <CoverageValue label="Unsupported" value={coverage.unsupported_files} />
        <CoverageValue label="Over size limit" value={coverage.files_exceeding_size_limit} />
      </div>
      <div className="coverage-grid">
        <div className="coverage-card">
          <span className="ai-panel-label">Analyzed languages</span>
          <div className="coverage-language-list">
            {(coverage.languages_analyzed || []).length ? coverage.languages_analyzed.map((language) => <span className="coverage-chip" key={language}>{language}</span>) : <span className="coverage-muted">No supported language files analyzed.</span>}
          </div>
          <span className="coverage-muted">Detected: {(coverage.languages_detected || []).join(", ") || "none"}</span>
        </div>
        <div className="coverage-card">
          <span className="ai-panel-label">Scanner results</span>
          <div className="coverage-scanner-list">
            {(coverage.scanners || []).map((scanner) => {
              const meta = STATUS[scanner.status] || STATUS.failed;
              const Icon = meta.Icon;
              return <div className="coverage-scanner" key={scanner.name}><span className={meta.cls}><Icon size={13} /> {meta.label}</span><strong>{scanner.name}</strong><small>{scanner.detail}</small></div>;
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
