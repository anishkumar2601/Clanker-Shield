import React from "react";
import TopNav from "./TopNav.jsx";
import Hero from "./Hero.jsx";
import MetricCards from "./MetricCards.jsx";
import FeaturedAICard from "./FeaturedAICard.jsx";
import FloatingThreatCard from "./FloatingThreatCard.jsx";
import LiveThreatActivity from "./LiveThreatActivity.jsx";
import AIAnalysisPanel from "./AIAnalysisPanel.jsx";
import ScanPipeline from "./ScanPipeline.jsx";
import ScanCoverage from "./ScanCoverage.jsx";
import FindingsQueue from "./FindingsQueue.jsx";
import PatchReview from "./PatchReview.jsx";
import VerificationPanel from "./VerificationPanel.jsx";
import SecurityGraph from "./SecurityGraph.jsx";
import RepositoryInventory from "./RepositoryInventory.jsx";
import SystemStatus from "./SystemStatus.jsx";
import SecurityCopilot from "./SecurityCopilot.jsx";
import ReportDownloads from "./ReportDownloads.jsx";
import { NetworkIcon } from "../icons.jsx";

export default function Dashboard(props) {
  const {
    repo, loading, uploading, rescanning, health, structure,
    selectedFinding, analysis, analyzing,
    patch, fixingId, applyingPatch, rollingBackPatch,
    verification, verifying,
    commandAnswer, asking, authUser, onLogout,
    onNewDemo, onUpload, onRescan, onSelectFinding, onInvestigate, onUpdateFindingStatus,
    onGenerateFix, onApplyPatch, onRollbackPatch, onVerify, onAsk,
  } = props;

  const findings = repo?.findings || [];
  const sortedFindings = [...findings].filter(f => !f.resolved).sort((a, b) => b.risk_score - a.risk_score);

  return (
    <div className="dashboard">
      <TopNav repoName={repo?.name} authUser={authUser} onLogout={onLogout} onRescan={onRescan} rescanning={rescanning} />

      <div className="dashboard-container">
        <Hero repo={repo} loading={loading} onUpload={onUpload} onNewDemo={onNewDemo} uploading={uploading} />

        <div className="overview-row">
          <div className="overview-main">
            <MetricCards metrics={repo?.metrics} history={repo?.scan_history} loading={loading} />
            <FeaturedAICard
              repo={repo} loading={loading} aiConfigured={!!health?.ai_configured}
              onViewAnalysis={() => document.getElementById("ai-analysis")?.scrollIntoView({ behavior: "smooth" })}
            />
          </div>
          <FloatingThreatCard repo={repo} loading={loading} />
        </div>

        <LiveThreatActivity
          findings={sortedFindings.slice(0, 8)}
          loading={loading}
          onSelect={onSelectFinding}
          selectedId={selectedFinding?.id}
        />

        <AIAnalysisPanel
          finding={selectedFinding}
          analysis={analysis}
          analyzing={analyzing}
          onInvestigate={onInvestigate}
        />

        <ScanPipeline pipeline={repo?.pipeline} loading={loading} />

        <ScanCoverage coverage={repo?.coverage} />

        <ReportDownloads repo={repo} />

        <FindingsQueue
          findings={findings}
          loading={loading}
          selected={selectedFinding}
          onSelect={onSelectFinding}
          onUpdateStatus={onUpdateFindingStatus}
          onGenerateFix={onGenerateFix}
          fixingId={fixingId}
        />

        <div className="section-block">
          <div className="section-heading">
            <h2>Patch review &amp; safe application</h2>
            <p>Hash-protected — a patch only applies if the file hasn't changed since it was generated.</p>
          </div>
          <PatchReview patch={patch} onApply={onApplyPatch} applying={applyingPatch} onRollback={onRollbackPatch} rollingBack={rollingBackPatch} />
        </div>

        <VerificationPanel
          verification={verification}
          onVerify={onVerify}
          verifying={verifying}
          canVerify={!!repo}
        />

        <div className="section-block">
          <div className="section-heading">
            <h2>Security graph</h2>
            <p>Routes, findings, and system components, connected by real evidence.</p>
          </div>
          <SecurityGraph graph={repo?.graph} onSelectFinding={(node) => {
            const f = findings.find((x) => x.id === node.id.replace("finding::", ""));
            if (f) onSelectFinding(f);
          }} />
        </div>

        <div className="section-block">
          <div className="section-heading">
            <h2>Repository inventory</h2>
            <p>What ClankerShield actually found while mapping this repository.</p>
          </div>
          <RepositoryInventory inventory={repo?.inventory} structure={structure} />
        </div>

        <SystemStatus health={health} repo={repo} />

        <SecurityCopilot repo={repo} findings={findings} onSelectFinding={onSelectFinding} />
      </div>
    </div>
  );
}
