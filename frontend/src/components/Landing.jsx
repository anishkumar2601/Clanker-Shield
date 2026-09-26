import React, { useRef } from "react";
import { ShieldIcon, UploadIcon, RefreshIcon, LockIcon, GaugeIcon, SparkleIcon } from "../icons.jsx";
import { Button } from "./common.jsx";

const PROOF_POINTS = [
  { icon: <LockIcon size={16} />, title: "Runs locally", body: "Your repository is analyzed in an isolated workspace. Nothing is sent anywhere unless you configure an AI provider yourself." },
  { icon: <GaugeIcon size={16} />, title: "Deterministic risk", body: "Every score is explainable: severity, exploitability, exposure, and reachability, not a black box." },
  { icon: <SparkleIcon size={16} />, title: "AI that shows its work", body: "Model-backed or local fallback, every claim is grounded in real scan evidence — never invented." },
];

export default function Landing({ onDemo, onUpload, loading, uploading, onSignIn }) {
  const fileInputRef = useRef(null);

  return (
    <div className="landing">
      <div className="landing-glow" aria-hidden="true" />
      <header className="landing-nav">
        <div className="landing-brand">
          <span className="brand-mark brand-mark-dark"><ShieldIcon size={18} /></span>
          <span className="brand-name-dark">ClankerShield</span>
        </div>
        <button className="landing-signin" onClick={() => onSignIn?.("login")}>Sign in / Create account</button>
      </header>

      <main className="landing-hero">
        <span className="landing-eyebrow">AI-powered repository security</span>
        <h1 className="landing-title">AI that sees threats.<br />Before breaches.</h1>
        <p className="landing-sub">
          Find threats, explain risk, generate safe fixes, and prove remediation —
          on a real scan of a real repository, in under a minute.
        </p>

        <div className="landing-actions">
          <Button variant="primary" size="lg" onClick={onDemo} loading={loading}>
            <RefreshIcon size={16} /> Launch demo scan
          </Button>
          <Button variant="ghost-dark" size="lg" onClick={() => fileInputRef.current?.click()} loading={uploading}>
            <UploadIcon size={16} /> Upload a repository ZIP
          </Button>
          <input
            ref={fileInputRef} type="file" accept=".zip" hidden
            onChange={(e) => { const f = e.target.files?.[0]; if (f) onUpload(f); e.target.value = ""; }}
          />
        </div>

        <div className="landing-proof-grid">
          {PROOF_POINTS.map((p) => (
            <div key={p.title} className="landing-proof-card">
              <span className="landing-proof-icon">{p.icon}</span>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
