import React from "react";
import { CheckIcon, ShieldCheckIcon, LockIcon, RefreshIcon } from "../icons.jsx";
import { Button, EmptyState } from "./common.jsx";

function DiffView({ diff }) {
  const lines = diff.split("\n");
  return (
    <pre className="diff-view">
      {lines.map((line, i) => {
        let cls = "diff-context";
        if (line.startsWith("+++") || line.startsWith("---")) cls = "diff-file";
        else if (line.startsWith("+")) cls = "diff-add";
        else if (line.startsWith("-")) cls = "diff-remove";
        else if (line.startsWith("@@")) cls = "diff-hunk";
        return <div key={i} className={`diff-line ${cls}`}>{line || " "}</div>;
      })}
    </pre>
  );
}

export default function PatchReview({ patch, onApply, applying, onRollback, rollingBack }) {
  if (!patch) {
    return (
      <div className="patch-review">
        <EmptyState
          icon={<LockIcon size={22} />}
          title="No patch generated yet"
          detail="Select a finding above and choose Generate safe fix to review a patch here."
        />
      </div>
    );
  }

  return (
    <div className="patch-review">
      <div className="patch-review-header">
        <div>
          <h3>Patch review</h3>
          <code className="finding-detail-loc">{patch.file}</code>
        </div>
        <span className={`pill ${patch.status === "applied" ? "pill-green" : patch.status === "rolled_back" ? "pill-amber" : "pill-neutral"}`}>
          {patch.status === "applied" ? "Applied" : patch.status === "rolled_back" ? "Rolled back" : "Draft — awaiting review"}
        </span>
      </div>

      <p className="patch-explanation">{patch.explanation}</p>

      <DiffView diff={patch.diff} />

      <div className="patch-safety-checks">
        {patch.safety_checks.map((c, i) => (
          <span key={i} className="safety-check"><CheckIcon size={12} /> {c}</span>
        ))}
      </div>

      <div className="patch-review-actions">
        {patch.status === "applied" ? (
          <>
            <span className="finding-resolved-note"><ShieldCheckIcon size={14} /> Applied — static verification is not complete until you run Verify.</span>
            <Button variant="secondary" onClick={() => onRollback?.(patch)} loading={rollingBack}>
              <RefreshIcon size={14} /> Roll back
            </Button>
          </>
        ) : patch.status === "rolled_back" ? (
          <span className="finding-resolved-note"><RefreshIcon size={14} /> Original content restored — rescan to confirm the finding is reopened.</span>
        ) : (
          <Button variant="primary" onClick={() => onApply(patch)} loading={applying}>
            <LockIcon size={14} /> Apply patch
          </Button>
        )}
      </div>
    </div>
  );
}
