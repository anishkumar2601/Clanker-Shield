import React from "react";
import { SparkleIcon, ShieldIcon } from "../icons.jsx";
import { SeverityBadge, AiModeTag, Button, EmptyState, Skeleton } from "./common.jsx";

export default function AIAnalysisPanel({ finding, analysis, analyzing, onInvestigate }) {
  return (
    <section id="ai-analysis" className="section-block">
      <div className="section-heading">
        <h2>ClankerShield AI Analysis</h2>
        <p>Explains the selected finding using only the evidence the scanners collected.</p>
      </div>

      <div className="ai-panel">
        {!finding ? (
          <EmptyState
            icon={<SparkleIcon size={26} />}
            title="Select a finding to analyze"
            detail="Pick anything from Live threat activity or the findings queue below."
          />
        ) : (
          <>
            <div className="ai-panel-header">
              <div>
                <div className="ai-panel-title-row">
                  <SeverityBadge severity={finding.severity} />
                  <span className="ai-panel-cwe">{finding.cwe}</span>
                </div>
                <h3 className="ai-panel-title">{finding.title}</h3>
                <code className="ai-panel-loc">{finding.file}:{finding.line}</code>
              </div>
              {!analyzing && (
                <Button variant="primary" size="md" onClick={onInvestigate}>
                  <SparkleIcon size={14} /> Investigate finding
                </Button>
              )}
            </div>

            {analyzing ? (
              <div className="ai-panel-shimmer">
                <Skeleton w="90%" h={14} />
                <Skeleton w="75%" h={14} />
                <Skeleton w="60%" h={14} />
              </div>
            ) : analysis ? (
              <>
                <AiModeTag mode={analysis.mode} />
                <p className="ai-panel-explanation">{analysis.explanation}</p>
                <div className="ai-panel-grid">
                  <div>
                    <span className="ai-panel-label">Risk band</span>
                    <span className="ai-panel-strong">{finding.risk_band} · {finding.risk_score}/100</span>
                  </div>
                  <div>
                    <span className="ai-panel-label">Confidence</span>
                    <span className="ai-panel-strong">{Math.round((analysis.confidence || 0) * 100)}%</span>
                  </div>
                  <div>
                    <span className="ai-panel-label">Attack-path nodes</span>
                    <span className="ai-panel-strong">{analysis.attack_path_node_count}</span>
                  </div>
                  <div>
                    <span className="ai-panel-label">Verdict</span>
                    <span className="ai-panel-strong">{analysis.verdict}</span>
                  </div>
                </div>
                <div className="ai-panel-remediation">
                  <span className="ai-panel-label"><ShieldIcon size={13} /> Recommended remediation</span>
                  <p>{analysis.recommended_remediation}</p>
                </div>
                {analysis.evidence_refs?.length > 0 && (
                  <div className="ai-panel-evidence">
                    <span className="ai-panel-label">Evidence references</span>
                    {analysis.evidence_refs.map((ref, i) => (
                      <code key={i} className="evidence-chip">{ref.file}:{ref.line}</code>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <p className="ai-panel-explanation">{finding.explanation}</p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
