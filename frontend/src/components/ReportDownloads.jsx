import React from "react";
import { api } from "../api.js";

const FORMATS = [
  ["SARIF", "sarif", "GitHub Code Scanning"],
  ["JSON", "json", "Machine-readable evidence"],
  ["CSV", "csv", "Spreadsheet triage"],
  ["Markdown", "markdown", "Issue or handoff notes"],
  ["HTML", "html", "Shareable report"],
];

export default function ReportDownloads({ repo }) {
  if (!repo) return null;
  return (
    <section className="section-block report-downloads">
      <div className="section-heading">
        <h2>Evidence exports</h2>
        <p>Download the latest scan exactly as recorded. Unavailable verification stays unavailable in every format.</p>
      </div>
      <div className="report-download-grid">
        {FORMATS.map(([label, format, detail]) => (
          <a className="report-download" key={format} href={api.reportUrl(repo.id, format)} download>
            <span className="report-download-label">{label}</span>
            <span className="report-download-detail">{detail}</span>
            <span className="report-download-arrow">↓</span>
          </a>
        ))}
      </div>
    </section>
  );
}
