import React from "react";
import { CheckIcon, AlertTriangleIcon, XIcon, NetworkIcon } from "../icons.jsx";
import { Skeleton } from "./common.jsx";

const STATUS_META = {
  completed: { cls: "stage-completed", Icon: CheckIcon, label: "Completed" },
  not_installed: { cls: "stage-warning", Icon: AlertTriangleIcon, label: "Not installed" },
  failed: { cls: "stage-failed", Icon: XIcon, label: "Failed" },
  timeout: { cls: "stage-warning", Icon: AlertTriangleIcon, label: "Timed out" },
  skipped: { cls: "stage-warning", Icon: AlertTriangleIcon, label: "Skipped" },
  running: { cls: "stage-running", Icon: NetworkIcon, label: "Running" },
  pending: { cls: "stage-pending", Icon: NetworkIcon, label: "Pending" },
};

export default function ScanPipeline({ pipeline, loading }) {
  return (
    <section id="network" className="section-block">
      <div className="section-heading">
        <h2>Scan pipeline</h2>
        <p>Local scan telemetry for this repository — not live network traffic.</p>
      </div>

      {loading ? (
        <div className="pipeline-grid">
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} h={84} radius={16} />)}
        </div>
      ) : (
        <div className="pipeline-grid">
          {(pipeline || []).map((stage) => {
            const meta = STATUS_META[stage.status] || STATUS_META.pending;
            const Icon = meta.Icon;
            return (
              <div key={stage.id} className={`pipeline-stage ${meta.cls}`}>
                <div className="pipeline-stage-top">
                  <Icon size={14} />
                  <span>{meta.label}</span>
                </div>
                <div className="pipeline-stage-label">{stage.label}</div>
                <div className="pipeline-stage-detail">{stage.detail}</div>
                <div className="pipeline-stage-foot">
                  {typeof stage.result_count === "number" && <span>{stage.result_count} result{stage.result_count === 1 ? "" : "s"}</span>}
                  {typeof stage.duration_ms === "number" && <span>{stage.duration_ms} ms</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
