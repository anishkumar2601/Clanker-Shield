import React, { useState } from "react";
import { SparkleIcon, SendIcon, XIcon } from "../icons.jsx";
import { AiModeTag } from "./common.jsx";

const SUGGESTIONS = [
  "What should I fix first?",
  "Why is this finding dangerous?",
  "Show me the most dangerous attack path.",
  "Find vulnerable systems.",
  "Explain this security signal.",
];

export default function AICommandBar({ onAsk, answer, asking, disabled }) {
  const [value, setValue] = useState("");
  const [expanded, setExpanded] = useState(false);

  const submit = (q) => {
    const question = (q ?? value).trim();
    if (!question || disabled) return;
    setExpanded(true);
    onAsk(question);
    setValue("");
  };

  return (
    <div className={`command-bar-wrap ${expanded ? "command-bar-expanded" : ""}`}>
      {expanded && (
        <div className="command-bar-panel">
          <div className="command-bar-panel-head">
            <span><SparkleIcon size={14} /> ClankerShield AI</span>
            <button onClick={() => setExpanded(false)} aria-label="Collapse"><XIcon size={14} /></button>
          </div>
          {asking ? (
            <div className="command-bar-shimmer" />
          ) : answer ? (
            <>
              <AiModeTag mode={answer.mode} />
              <p className="command-bar-answer">{answer.answer}</p>
              {answer.evidence_refs?.length > 0 && (
                <div className="command-bar-evidence">
                  {answer.evidence_refs.map((r, i) => <code key={i} className="evidence-chip">{r.file}:{r.line}</code>)}
                </div>
              )}
            </>
          ) : null}
        </div>
      )}

      <div className="command-bar">
        <SparkleIcon size={16} className="command-bar-icon" />
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder="Ask ClankerShield AI anything…"
          disabled={disabled}
        />
        <button className="command-bar-send" onClick={() => submit()} disabled={disabled || !value.trim()} aria-label="Ask">
          <SendIcon size={15} />
        </button>
      </div>
      <div className="command-bar-suggestions">
        {SUGGESTIONS.map((s) => (
          <button key={s} onClick={() => submit(s)} disabled={disabled}>{s}</button>
        ))}
      </div>
    </div>
  );
}
