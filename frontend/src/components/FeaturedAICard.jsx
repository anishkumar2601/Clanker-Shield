import React from "react";
import { SparkleIcon, CpuIcon, ArrowUpRightIcon } from "../icons.jsx";
import { Button, Skeleton } from "./common.jsx";

export default function FeaturedAICard({ repo, loading, aiConfigured, onViewAnalysis }) {
  const findings = repo?.findings || [];
  const urgent = findings.filter((f) => !f.resolved && (f.severity === "critical" || f.severity === "high"));
  const top = [...urgent].sort((a, b) => b.risk_score - a.risk_score)[0];

  return (
    <section className="featured-ai-card">
      <div className="featured-ai-glow" aria-hidden="true" />
      <div className="featured-ai-top">
        <span className="featured-ai-icon"><SparkleIcon size={20} /></span>
        <div>
          <h2 className="featured-ai-title">AI Security Analysis</h2>
          <span className={`ai-mode-tag ${aiConfigured ? "ai-mode-model" : "ai-mode-local"}`}>
            <CpuIcon size={12} />
            {aiConfigured ? "Model-backed reasoning active" : "Deterministic local analysis active"}
          </span>
        </div>
      </div>

      {loading ? (
        <Skeleton w="70%" h={20} radius={8} style={{ margin: "18px 0" }} />
      ) : urgent.length === 0 ? (
        <p className="featured-ai-body">No urgent findings remain open. The repository's critical and high severity items have all been resolved or none were detected.</p>
      ) : (
        <>
          <div className="featured-ai-count">{urgent.length}</div>
          <p className="featured-ai-body">
            urgent finding{urgent.length === 1 ? "" : "s"} outstanding — most pressing is{" "}
            <strong>{top?.title}</strong> in <code>{top?.file}:{top?.line}</code>. {top?.impact}
          </p>
        </>
      )}

      <Button variant="dark" size="md" onClick={onViewAnalysis} disabled={loading}>
        View analysis <ArrowUpRightIcon size={14} />
      </Button>
    </section>
  );
}
