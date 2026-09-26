import React, { useRef } from "react";
import { UploadIcon, RefreshIcon, FolderIcon } from "./../icons.jsx";
import { Button, Skeleton } from "./common.jsx";

export default function Hero({ repo, loading, onUpload, onNewDemo, uploading }) {
  const fileInputRef = useRef(null);

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (file) onUpload(file);
    e.target.value = "";
  };

  return (
    <section id="overview" className="hero">
      <div className="hero-copy">
        <h1 className="hero-title">Security overview.</h1>
        <p className="hero-sub">
          {loading
            ? "ClankerShield is mapping the repository and correlating findings…"
            : "ClankerShield mapped this repository, detected risk, traced attack paths, and prioritized what to remediate first."}
        </p>

        <div className="hero-facts">
          {loading ? (
            <>
              <Skeleton w={160} h={34} radius={12} />
              <Skeleton w={120} h={34} radius={12} />
              <Skeleton w={140} h={34} radius={12} />
            </>
          ) : repo ? (
            <>
              <div className="hero-fact">
                <FolderIcon size={14} />
                <span>{repo.name}</span>
              </div>
              <div className="hero-fact">
                <span className="hero-fact-label">Source</span>
                <span>{repo.source_type === "demo" ? "Demo repository" : "Uploaded ZIP"}</span>
              </div>
              <div className="hero-fact">
                <span className="hero-fact-label">Files analyzed</span>
                <span>{repo.files_analyzed}</span>
              </div>
              <div className="hero-fact">
                <span className="hero-fact-label">Frameworks</span>
                <span>{repo.frameworks?.length ? repo.frameworks.join(", ") : "None detected"}</span>
              </div>
            </>
          ) : null}
        </div>
      </div>

      <div className="hero-actions">
        <Button variant="primary" size="lg" onClick={onNewDemo} loading={loading && !uploading}>
          <RefreshIcon size={16} /> New demo scan
        </Button>
        <Button variant="secondary" size="lg" onClick={() => fileInputRef.current?.click()} loading={uploading}>
          <UploadIcon size={16} /> Upload ZIP
        </Button>
        <input ref={fileInputRef} type="file" accept=".zip" hidden onChange={handleFile} />
      </div>
    </section>
  );
}
