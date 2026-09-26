import React, { useState } from "react";
import { ShieldIcon, RefreshIcon, MenuIcon, XIcon } from "../icons.jsx";
import { Button } from "./common.jsx";

const LINKS = [
  { id: "overview", label: "Overview" },
  { id: "threats", label: "Threats" },
  { id: "network", label: "Network" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "ai-analysis", label: "AI Analysis" },
  { id: "reports", label: "Reports" },
  { id: "system-status", label: "System status" },
];

export default function TopNav({ repoName, authUser, onLogout, onRescan, rescanning }) {
  const [open, setOpen] = useState(false);

  const scrollTo = (id) => {
    setOpen(false);
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <header className="topnav">
      <div className="topnav-inner">
        <div className="topnav-brand">
          <span className="brand-mark"><ShieldIcon size={18} /></span>
          <span className="brand-name">ClankerShield</span>
        </div>

        <nav className="topnav-links" aria-label="Dashboard sections">
          {LINKS.map((l) => (
            <button key={l.id} className="topnav-link" onClick={() => scrollTo(l.id)}>
              {l.label}
            </button>
          ))}
        </nav>

        <div className="topnav-actions">
          <Button variant="secondary" size="sm" onClick={onRescan} loading={rescanning}>
            <RefreshIcon size={14} /> Rescan
          </Button>
          {authUser && <span className="topnav-account" title={authUser.email}>{authUser.email}</span>}
          {authUser ? (
            <button className="topnav-profile" title={authUser.email} onClick={onLogout} aria-label="Sign out">
              {authUser.email.slice(0, 1).toUpperCase()}
            </button>
          ) : (
            <div className="topnav-profile" title={repoName || "Repository"}>
              {(repoName || "C").slice(0, 1).toUpperCase()}
            </div>
          )}
          <button className="topnav-burger" onClick={() => setOpen((v) => !v)} aria-label="Open menu">
            {open ? <XIcon size={20} /> : <MenuIcon size={20} />}
          </button>
        </div>
      </div>

      {open && (
        <div className="topnav-mobile">
          {LINKS.map((l) => (
            <button key={l.id} className="topnav-mobile-link" onClick={() => scrollTo(l.id)}>
              {l.label}
            </button>
          ))}
          <button className="topnav-mobile-link" onClick={() => { setOpen(false); onRescan(); }}>
            <RefreshIcon size={14} /> Rescan repository
          </button>
          {authUser && <button className="topnav-mobile-link" onClick={() => { setOpen(false); onLogout?.(); }}>Sign out {authUser.email}</button>}
        </div>
      )}
    </header>
  );
}
