import React from "react";
import { AlertOctagonIcon, AlertTriangleIcon, ShieldCheckIcon, CpuIcon } from "../icons.jsx";

const SEVERITY_META = {
  critical: { label: "Critical", cls: "sev-critical", Icon: AlertOctagonIcon },
  high: { label: "High", cls: "sev-high", Icon: AlertTriangleIcon },
  medium: { label: "Medium", cls: "sev-medium", Icon: AlertTriangleIcon },
  low: { label: "Low", cls: "sev-low", Icon: AlertTriangleIcon },
};

export function SeverityBadge({ severity, size = "md" }) {
  const meta = SEVERITY_META[severity] || SEVERITY_META.low;
  const Icon = meta.Icon;
  return (
    <span className={`badge ${meta.cls} badge-${size}`}>
      <Icon size={size === "sm" ? 12 : 13} />
      {meta.label}
    </span>
  );
}

export function StatusPill({ tone = "neutral", children }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function ResolvedBadge() {
  return (
    <span className="badge sev-resolved">
      <ShieldCheckIcon size={13} /> Neutralized
    </span>
  );
}

export function AiModeTag({ mode }) {
  return (
    <span className={`ai-mode-tag ${mode === "model" ? "ai-mode-model" : "ai-mode-local"}`}>
      <CpuIcon size={12} />
      {mode === "model" ? "Model-backed" : "Deterministic local analysis"}
    </span>
  );
}

export function ScoreRing({ value, size = 64, stroke = 7, tone = "cyan" }) {
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, value));
  const offset = circumference * (1 - clamped / 100);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className={`score-ring ring-${tone}`}>
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--border)" strokeWidth={stroke} />
      <circle
        cx={size / 2} cy={size / 2} r={radius} fill="none"
        stroke="currentColor" strokeWidth={stroke} strokeLinecap="round"
        strokeDasharray={circumference} strokeDashoffset={offset}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        className="score-ring-arc"
      />
    </svg>
  );
}

export function Sparkbars({ values, tone = "cyan" }) {
  const max = Math.max(1, ...values);
  return (
    <div className="sparkbars" aria-hidden="true">
      {values.map((v, i) => (
        <span
          key={i}
          className={`sparkbar tone-${tone}`}
          style={{ height: `${8 + (v / max) * 24}px`, animationDelay: `${i * 40}ms` }}
        />
      ))}
    </div>
  );
}

export function Skeleton({ w = "100%", h = 14, radius = 8, style = {} }) {
  return <div className="skeleton" style={{ width: w, height: h, borderRadius: radius, ...style }} />;
}

export function EmptyState({ icon, title, detail }) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state-icon">{icon}</div>}
      <p className="empty-state-title">{title}</p>
      {detail && <p className="empty-state-detail">{detail}</p>}
    </div>
  );
}

export function Button({ variant = "secondary", size = "md", loading, children, className = "", ...rest }) {
  return (
    <button
      className={`btn btn-${variant} btn-${size} ${loading ? "btn-loading" : ""} ${className}`}
      disabled={loading || rest.disabled}
      {...rest}
    >
      {loading ? <span className="btn-spinner" aria-hidden="true" /> : null}
      <span className="btn-label">{children}</span>
    </button>
  );
}
