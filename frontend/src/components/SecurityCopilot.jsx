import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { RefreshIcon, SendIcon, SparkleIcon, XIcon } from "../icons.jsx";
import { AiModeTag } from "./common.jsx";

const SUGGESTIONS = [
  "What should I fix first?",
  "Why is this finding dangerous?",
  "Show the most dangerous attack path.",
  "Show me the relevant code evidence.",
];

function MessageContent({ content }) {
  const pieces = String(content || "").split("```");
  return (
    <div className="copilot-markdown">
      {pieces.map((piece, index) => {
        if (index % 2 === 1) {
          const lines = piece.replace(/^\w+\n/, "");
          return <pre className="copilot-code" key={index}><code>{lines}</code></pre>;
        }
        return (
          <p className="copilot-text" key={index}>
            {piece.split("\n").map((line, lineIndex) => (
              <React.Fragment key={lineIndex}>
                {line}
                {lineIndex < piece.split("\n").length - 1 && <br />}
              </React.Fragment>
            ))}
          </p>
        );
      })}
    </div>
  );
}

function EvidenceChips({ message, findings, onSelectFinding }) {
  const refs = message.evidence_refs || [];
  if (!refs.length) return null;
  return (
    <div className="copilot-evidence">
      <span className="copilot-label">Evidence</span>
      {refs.map((ref, index) => {
        const finding = findings.find((item) => item.file === ref.file && item.line === ref.line);
        return (
          <button
            className="copilot-evidence-chip"
            key={`${ref.file}-${ref.line}-${index}`}
            onClick={() => finding && onSelectFinding(finding)}
            disabled={!finding}
          >
            {ref.file}:{ref.line}
          </button>
        );
      })}
    </div>
  );
}

export default function SecurityCopilot({ repo, findings = [], onSelectFinding }) {
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState("");
  const [editingId, setEditingId] = useState(null);
  const [editValue, setEditValue] = useState("");
  const abortRef = useRef(null);

  const activeConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === activeId),
    [conversations, activeId]
  );

  const loadConversation = async (conversationId) => {
    if (!conversationId) return;
    setLoading(true);
    setError("");
    try {
      const data = await api.getConversation(repo.id, conversationId);
      setMessages(data.conversation.messages || []);
      setActiveId(conversationId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let alive = true;
    if (!repo?.id) return undefined;
    (async () => {
      setLoading(true);
      setError("");
      try {
        const data = await api.listConversations(repo.id);
        if (!alive) return;
        let list = data.conversations || [];
        if (!list.length) {
          const created = await api.createConversation(repo.id);
          list = [created.conversation];
        }
        if (!alive) return;
        setConversations(list);
        const selected = list.find((item) => item.id === activeId) || list[0];
        setActiveId(selected.id);
        const detail = await api.getConversation(repo.id, selected.id);
        if (alive) setMessages(detail.conversation.messages || []);
      } catch (err) {
        if (alive) setError(err.message);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [repo?.id]);

  const newConversation = async () => {
    if (!repo?.id) return;
    abortRef.current?.abort();
    setStreaming(false);
    try {
      const data = await api.createConversation(repo.id);
      setConversations((current) => [data.conversation, ...current]);
      setActiveId(data.conversation.id);
      setMessages([]);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  };

  const submit = async (suggestion) => {
    const question = (suggestion ?? input).trim();
    if (!question || !repo?.id || !activeId || streaming) return;
    setInput("");
    setError("");
    const userMessage = { id: `local-user-${Date.now()}`, role: "user", content: question };
    const assistantId = `local-assistant-${Date.now()}`;
    const assistantMessage = { id: assistantId, role: "assistant", content: "", mode: "local" };
    setMessages((current) => [...current, userMessage, assistantMessage]);
    setStreaming(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      await api.streamConversationMessage(repo.id, activeId, question, {
        onMeta: (meta) => {
          setMessages((current) => current.map((item) => item.id === assistantId ? { ...item, ...meta } : item));
        },
        onDelta: (delta) => {
          setMessages((current) => current.map((item) => item.id === assistantId ? { ...item, content: item.content + (delta.text || "") } : item));
        },
        onDone: (data) => {
          setMessages((current) => current.map((item) => item.id === assistantId ? data.message : item));
          setConversations((current) => current.map((item) => item.id === activeId ? { ...item, ...data.conversation } : item));
        },
        onError: (data) => setError(data.detail || "The copilot could not finish this answer."),
      }, controller.signal);
      const refreshed = await api.listConversations(repo.id);
      setConversations(refreshed.conversations || []);
    } catch (err) {
      if (err.name !== "AbortError") setError(err.message);
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const regenerate = async () => {
    if (!repo?.id || !activeId || streaming) return;
    setError("");
    const assistantId = `local-regenerated-${Date.now()}`;
    setMessages((current) => [...current, { id: assistantId, role: "assistant", content: "", mode: "local" }]);
    setStreaming(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      await api.regenerateConversation(repo.id, activeId, {
        onMeta: (meta) => setMessages((current) => current.map((item) => item.id === assistantId ? { ...item, ...meta } : item)),
        onDelta: (delta) => setMessages((current) => current.map((item) => item.id === assistantId ? { ...item, content: item.content + (delta.text || "") } : item)),
        onDone: (data) => setMessages((current) => current.map((item) => item.id === assistantId ? data.message : item)),
        onError: (data) => setError(data.detail || "The copilot could not regenerate this answer."),
      }, controller.signal);
    } catch (err) {
      if (err.name !== "AbortError") setError(err.message);
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const saveEdit = async (messageId) => {
    if (!editValue.trim()) return;
    try {
      await api.editMessage(repo.id, activeId, messageId, editValue);
      setEditingId(null);
      await loadConversation(activeId);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="security-copilot section-block" id="security-copilot">
      <div className="section-heading copilot-section-heading">
        <div>
          <h2><SparkleIcon size={20} /> Security Copilot</h2>
          <p>Persistent, evidence-linked conversations scoped to <strong>{repo?.name || "this repository"}</strong>.</p>
        </div>
        <div className="copilot-trust-badge"><span className="status-dot status-dot-green" /> Read-only context tools</div>
      </div>

      <div className="copilot-shell">
        <aside className="copilot-threads">
          <div className="copilot-threads-head">
            <span>Investigations</span>
            <button className="copilot-new-button" onClick={newConversation}>New</button>
          </div>
          <div className="copilot-thread-list">
            {conversations.map((conversation) => (
              <button
                key={conversation.id}
                className={`copilot-thread ${activeId === conversation.id ? "copilot-thread-active" : ""}`}
                onClick={() => loadConversation(conversation.id)}
              >
                <span className="copilot-thread-title">{conversation.title}</span>
                <span className="copilot-thread-meta">{conversation.messages?.length || 0} messages</span>
              </button>
            ))}
          </div>
          <div className="copilot-scope-card">
            <span className="copilot-label">Current scope</span>
            <strong>{repo?.files_analyzed || 0} files</strong>
            <span>{findings.filter((finding) => !finding.resolved).length} active findings · no arbitrary shell access</span>
          </div>
        </aside>

        <div className="copilot-chat">
          <div className="copilot-chat-head">
            <div>
              <span className="copilot-chat-kicker">{activeConversation?.title || "Security investigation"}</span>
              <span className="copilot-chat-sub">Grounded in the latest scan evidence</span>
            </div>
            <button className="copilot-icon-button" onClick={() => activeId && loadConversation(activeId)} disabled={loading} aria-label="Refresh conversation">
              <RefreshIcon size={15} />
            </button>
          </div>

          <div className="copilot-messages" aria-live="polite">
            {loading ? (
              <div className="copilot-empty"><div className="copilot-orb"><SparkleIcon size={24} /></div><strong>Loading investigation memory…</strong></div>
            ) : messages.length === 0 ? (
              <div className="copilot-empty"><div className="copilot-orb"><SparkleIcon size={24} /></div><strong>Ask about this repository</strong><span>I’ll cite scanner-backed files and lines, and I’ll say when the evidence is insufficient.</span></div>
            ) : messages.map((message) => (
              <div className={`copilot-message-row copilot-message-${message.role}`} key={message.id}>
                <div className="copilot-avatar">{message.role === "user" ? "YOU" : <SparkleIcon size={14} />}</div>
                <div className="copilot-message-card">
                  <div className="copilot-message-meta">
                    <span>{message.role === "user" ? "You" : "ClankerShield AI"}</span>
                    {message.mode && message.role === "assistant" && <AiModeTag mode={message.mode} />}
                  </div>
                  {editingId === message.id ? (
                    <div className="copilot-edit-box">
                      <textarea value={editValue} onChange={(event) => setEditValue(event.target.value)} rows={3} />
                      <div><button className="copilot-small-button" onClick={() => saveEdit(message.id)}>Save</button><button className="copilot-small-button muted" onClick={() => setEditingId(null)}>Cancel</button></div>
                    </div>
                  ) : <MessageContent content={message.content} />}

                  {message.role === "assistant" && (
                    <>
                      <EvidenceChips message={message} findings={findings} onSelectFinding={onSelectFinding} />
                      {message.tool_calls?.length > 0 && (
                        <details className="copilot-tools"><summary>Context used · {message.tool_calls.length} read-only tool calls</summary><pre>{JSON.stringify(message.tool_calls, null, 2)}</pre></details>
                      )}
                      {!streaming && message.content && <button className="copilot-message-action" onClick={regenerate}><RefreshIcon size={12} /> Regenerate</button>}
                    </>
                  )}
                  {message.role === "user" && !message.id.startsWith("local-") && !streaming && (
                    <button className="copilot-message-action" onClick={() => { setEditingId(message.id); setEditValue(message.content); }}><span>Edit</span></button>
                  )}
                </div>
              </div>
            ))}
          </div>

          {error && <div className="copilot-error"><XIcon size={14} /> {error}</div>}
          <div className="copilot-composer-wrap">
            <form className="copilot-composer" onSubmit={(event) => { event.preventDefault(); submit(); }}>
              <SparkleIcon size={16} className="copilot-composer-icon" />
              <textarea value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); submit(); } }} placeholder="Ask about risk, evidence, attack paths, or remediation…" rows={1} disabled={streaming || !activeId} />
              {streaming ? <button type="button" className="copilot-stop" onClick={() => abortRef.current?.abort()}>Stop</button> : <button type="submit" className="copilot-send" disabled={!input.trim() || !activeId}><SendIcon size={15} /></button>}
            </form>
            <div className="copilot-suggestions">{SUGGESTIONS.map((suggestion) => <button key={suggestion} onClick={() => submit(suggestion)} disabled={streaming || !activeId}>{suggestion}</button>)}</div>
            <span className="copilot-composer-hint">Enter to send · Shift + Enter for a new line · repository content is treated as untrusted data</span>
          </div>
        </div>
      </div>
    </section>
  );
}
