import React, { useCallback, useEffect, useState } from "react";
import Landing from "./components/Landing.jsx";
import Dashboard from "./components/Dashboard.jsx";
import Auth from "./components/Auth.jsx";
import { api } from "./api.js";
import { useToast } from "./hooks/useToast.jsx";

export default function App() {
  const toast = useToast();

  const [view, setView] = useState("landing");
  const [health, setHealth] = useState(null);
  const [authUser, setAuthUser] = useState(null);
  const [authView, setAuthView] = useState("login");
  const [showAuth, setShowAuth] = useState(false);

  const [repo, setRepo] = useState(null);
  const [structure, setStructure] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [rescanning, setRescanning] = useState(false);

  const [selectedFinding, setSelectedFinding] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);

  const [patch, setPatch] = useState(null);
  const [fixingId, setFixingId] = useState(null);
  const [applyingPatch, setApplyingPatch] = useState(false);
  const [rollingBackPatch, setRollingBackPatch] = useState(false);

  const [verification, setVerification] = useState(null);
  const [verifying, setVerifying] = useState(false);

  const [commandAnswer, setCommandAnswer] = useState(null);
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    api.health().then(async (result) => {
      setHealth(result);
      if (result.auth_required) {
        try {
          const session = await api.me();
          setAuthUser(session.authenticated ? session.user : null);
        } catch {
          setAuthUser(null);
        }
      }
    }).catch(() => setHealth(null));
  }, []);

  const handleAuthenticated = useCallback((user) => {
    setAuthUser(user);
    setAuthView("login");
    setShowAuth(false);
    setView("landing");
    toast.success(`Signed in as ${user.email}.`);
  }, [toast]);

  const handleApiError = (err) => {
    if (err?.status === 401 && health?.auth_required) {
      setAuthUser(null);
      setAuthView("expired");
      setView("landing");
      return;
    }
    toast.error(err?.message || "The request failed.");
  };

  const handleLogout = useCallback(async () => {
    try { await api.logout(); } catch { /* the local session is cleared below */ }
    setAuthUser(null);
    setShowAuth(false);
    setView("landing");
    setRepo(null);
    setStructure(null);
    resetSelection();
  }, []);

  const refreshStructure = useCallback(async (repoId) => {
    try {
      const s = await api.getStructure(repoId);
      setStructure(s);
    } catch {
      // Non-critical - the rest of the dashboard still works without the tree.
    }
  }, []);

  const resetSelection = () => {
    setSelectedFinding(null);
    setAnalysis(null);
    setPatch(null);
  };

  const handleDemo = useCallback(async () => {
    setLoading(true);
    resetSelection();
    setVerification(null);
    try {
      const data = await api.createDemo();
      setRepo(data);
      setView("dashboard");
      refreshStructure(data.id);
      api.health().then(setHealth).catch(() => {});
      toast.success(`Demo scan complete — ${data.metrics.threats_detected} finding(s) detected.`);
    } catch (err) {
      handleApiError(err);
    } finally {
      setLoading(false);
    }
  }, [refreshStructure, toast]);

  const handleUpload = useCallback(async (file) => {
    setUploading(true);
    setLoading(true);
    resetSelection();
    setVerification(null);
    try {
      const data = await api.uploadZip(file);
      setRepo(data);
      setView("dashboard");
      refreshStructure(data.id);
      const skipped = data.upload_notice?.skipped_members?.length || 0;
      toast.success(
        `Scan complete — ${data.metrics.threats_detected} finding(s) across ${data.files_analyzed} files.` +
        (skipped ? ` ${skipped} unsafe archive member(s) were skipped.` : "")
      );
    } catch (err) {
      handleApiError(err);
    } finally {
      setUploading(false);
      setLoading(false);
    }
  }, [refreshStructure, toast]);

  const handleRescan = useCallback(async () => {
    if (!repo) return;
    setRescanning(true);
    try {
      const data = await api.rescan(repo.id);
      setRepo(data);
      refreshStructure(repo.id);
      if (selectedFinding && !data.findings.some((f) => f.id === selectedFinding.id)) {
        resetSelection();
      }
      toast.success("Rescan complete.");
    } catch (err) {
      handleApiError(err);
    } finally {
      setRescanning(false);
    }
  }, [repo, selectedFinding, refreshStructure, toast]);

  const handleSelectFinding = useCallback((finding) => {
    setSelectedFinding(finding);
    setAnalysis(null);
    if (!patch || patch.finding_id !== finding.id) setPatch(null);
  }, [patch]);

  const handleInvestigate = useCallback(async () => {
    if (!repo || !selectedFinding) return;
    setAnalyzing(true);
    try {
      const result = await api.analyzeFinding(repo.id, selectedFinding.id);
      setAnalysis(result);
    } catch (err) {
      handleApiError(err);
    } finally {
      setAnalyzing(false);
    }
  }, [repo, selectedFinding, toast]);

  const handleFindingStatus = useCallback(async (finding, status) => {
    if (!repo || !finding) return;
    const reason = status === "FALSE_POSITIVE" || status === "ACCEPTED_RISK"
      ? window.prompt(`Reason for ${status === "FALSE_POSITIVE" ? "false positive" : "accepted risk"}:`, "")
      : "Reopened by reviewer";
    if ((status === "FALSE_POSITIVE" || status === "ACCEPTED_RISK") && (!reason || reason.trim().length < 8)) {
      toast.error("A reason of at least 8 characters is required.");
      return;
    }
    try {
      const updated = await api.updateFindingStatus(repo.id, finding.id, status, reason || "");
      setRepo((current) => current ? { ...current, findings: current.findings.map((item) => item.id === updated.id ? updated : item) } : current);
      setSelectedFinding(updated);
      toast.success(`Finding marked ${updated.lifecycle_status.replace("_", " ").toLowerCase()}.`);
    } catch (err) {
      handleApiError(err);
    }
  }, [repo, toast]);

  const handleGenerateFix = useCallback(async (finding) => {
    if (!repo) return;
    setFixingId(finding.id);
    try {
      const generated = await api.generateFix(repo.id, finding.id);
      setPatch(generated);
      toast.success("Patch generated — review the diff below.");
      document.querySelector(".patch-review")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (err) {
      handleApiError(err);
    } finally {
      setFixingId(null);
    }
  }, [repo, toast]);

  const handleApplyPatch = useCallback(async (p) => {
    if (!repo) return;
    setApplyingPatch(true);
    try {
      const result = await api.applyPatch(repo.id, p.id);
      setPatch(result.patch);
      toast.success(`Applied — ${result.finding_title || "patch"} is ready to verify.`);
    } catch (err) {
      handleApiError(err);
    } finally {
      setApplyingPatch(false);
    }
  }, [repo, toast]);

  const handleRollbackPatch = useCallback(async (p) => {
    if (!repo) return;
    setRollingBackPatch(true);
    try {
      const result = await api.rollbackPatch(repo.id, p.id);
      setPatch(result.patch);
      toast.success("Patch rolled back safely. Rescan to update findings.");
    } catch (err) {
      handleApiError(err);
    } finally {
      setRollingBackPatch(false);
    }
  }, [repo, toast]);

  const handleVerify = useCallback(async () => {
    if (!repo) return;
    setVerifying(true);
    try {
      const result = await api.verify(repo.id);
      setVerification(result);
      setRepo(result.repository);
      refreshStructure(repo.id);
      toast[result.verdict === "STATICALLY_VERIFIED" ? "success" : result.verdict.startsWith("FAILED") ? "error" : "info"](
        `Verification: ${result.verdict.replace("_", " ").toLowerCase()}.`
      );
    } catch (err) {
      handleApiError(err);
    } finally {
      setVerifying(false);
    }
  }, [repo, refreshStructure, toast]);

  const handleAsk = useCallback(async (question) => {
    if (!repo) return;
    setAsking(true);
    try {
      const result = await api.askQuestion(repo.id, question);
      setCommandAnswer(result);
    } catch (err) {
      handleApiError(err);
    } finally {
      setAsking(false);
    }
  }, [repo, toast]);

  if ((health?.auth_required || showAuth) && !authUser) {
    return <Auth initialMode={authView} onAuthenticated={handleAuthenticated} />;
  }

  if (view === "landing") {
    return <Landing onDemo={handleDemo} onUpload={handleUpload} loading={loading} uploading={uploading} onSignIn={(mode) => { setAuthView(mode); setShowAuth(true); }} />;
  }

  return (
    <Dashboard
      repo={repo} loading={loading} uploading={uploading} rescanning={rescanning}
      health={health} structure={structure}
      selectedFinding={selectedFinding} analysis={analysis} analyzing={analyzing}
      patch={patch} fixingId={fixingId} applyingPatch={applyingPatch}
      rollingBackPatch={rollingBackPatch}
      verification={verification} verifying={verifying}
      commandAnswer={commandAnswer} asking={asking}
      authUser={authUser} onLogout={handleLogout}
      onNewDemo={handleDemo} onUpload={handleUpload} onRescan={handleRescan}
      onSelectFinding={handleSelectFinding} onInvestigate={handleInvestigate}
      onUpdateFindingStatus={handleFindingStatus}
      onGenerateFix={handleGenerateFix} onApplyPatch={handleApplyPatch} onRollbackPatch={handleRollbackPatch}
      onVerify={handleVerify} onAsk={handleAsk}
    />
  );
}
