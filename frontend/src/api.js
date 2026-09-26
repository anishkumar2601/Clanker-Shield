const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000/api";

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      headers: options.body instanceof FormData ? undefined : { "Content-Type": "application/json" },
      credentials: "include",
      ...options,
    });
  } catch (networkErr) {
    throw new ApiError(
      "Can't reach the ClankerShield API. Is the backend running at " + API_BASE + "?",
      0
    );
  }

  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { detail: text };
    }
  }

  if (!res.ok) {
    throw new ApiError((data && data.detail) || `Request failed (${res.status})`, res.status);
  }
  return data;
}

async function streamRequest(path, options = {}, handlers = {}) {
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      ...options,
    });
  } catch (networkErr) {
    throw new ApiError(
      "Can't reach the ClankerShield API. Is the backend running at " + API_BASE + "?",
      0
    );
  }

  if (!res.ok) {
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
    throw new ApiError((data && data.detail) || `Request failed (${res.status})`, res.status);
  }

  if (!res.body) throw new ApiError("The browser did not expose a streaming response body.", 0);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  const handleFrame = (frame) => {
    const lines = frame.split(/\r?\n/);
    const event = lines.find((line) => line.startsWith("event:"))?.slice(6).trim() || "message";
    const raw = lines.find((line) => line.startsWith("data:"))?.slice(5).trim();
    if (!raw) return;
    let data;
    try { data = JSON.parse(raw); } catch { data = { text: raw }; }
    if (event === "meta") handlers.onMeta?.(data);
    else if (event === "delta") handlers.onDelta?.(data);
    else if (event === "done") handlers.onDone?.(data);
    else if (event === "error") {
      handlers.onError?.(data);
      throw new ApiError(data.detail || "The copilot stream failed.", 500);
    }
  };

  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const frames = buffer.split(/\r?\n\r?\n/);
    buffer = frames.pop() || "";
    for (const frame of frames) handleFrame(frame);
    if (done) break;
  }
  if (buffer.trim()) handleFrame(buffer);
}

export const api = {
  health: () => request("/health"),

  me: () => request("/auth/me"),

  signup: (email, password, passwordConfirmation) =>
    request("/auth/signup", { method: "POST", body: JSON.stringify({ email, password, password_confirmation: passwordConfirmation }) }),

  login: (email, password) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),

  verifyEmail: (token) =>
    request("/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) }),

  forgotPassword: (email) =>
    request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) }),

  resetPassword: (token, password, passwordConfirmation) =>
    request("/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password, password_confirmation: passwordConfirmation }) }),

  logout: () => request("/auth/logout", { method: "POST" }),

  createDemo: () => request("/repositories/demo", { method: "POST" }),

  uploadZip: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/repositories/upload", { method: "POST", body: form });
  },

  getRepository: (repoId) => request(`/repositories/${repoId}`),

  rescan: (repoId) => request(`/repositories/${repoId}/scan`, { method: "POST" }),

  getFinding: (repoId, findingId) => request(`/repositories/${repoId}/findings/${findingId}`),

  analyzeFinding: (repoId, findingId) =>
    request(`/repositories/${repoId}/findings/${findingId}/analyze`, { method: "POST" }),

  updateFindingStatus: (repoId, findingId, status, reason) =>
    request(`/repositories/${repoId}/findings/${findingId}/status`, {
      method: "POST",
      body: JSON.stringify({ status, reason }),
    }),

  askQuestion: (repoId, question) =>
    request(`/repositories/${repoId}/questions`, {
      method: "POST",
      body: JSON.stringify({ question }),
    }),

  generateFix: (repoId, findingId) =>
    request(`/repositories/${repoId}/findings/${findingId}/fix`, { method: "POST" }),

  applyPatch: (repoId, patchId) =>
    request(`/repositories/${repoId}/patches/apply`, {
      method: "POST",
      body: JSON.stringify({ patch_id: patchId }),
    }),

  rollbackPatch: (repoId, patchId) =>
    request(`/repositories/${repoId}/patches/${patchId}/rollback`, { method: "POST" }),

  verify: (repoId) => request(`/repositories/${repoId}/verify`, { method: "POST" }),

  getStructure: (repoId) => request(`/repositories/${repoId}/structure`),

  getInventory: (repoId) => request(`/repositories/${repoId}/inventory`),

  getGraph: (repoId) => request(`/repositories/${repoId}/graph`),

  reportUrl: (repoId, format) => `${API_BASE}/repositories/${repoId}/reports/${format}`,

  listConversations: (repoId) => request(`/repositories/${repoId}/conversations`),

  createConversation: (repoId, title = "Security investigation") =>
    request(`/repositories/${repoId}/conversations`, {
      method: "POST",
      body: JSON.stringify({ title }),
    }),

  getConversation: (repoId, conversationId) =>
    request(`/repositories/${repoId}/conversations/${conversationId}`),

  deleteConversation: (repoId, conversationId) =>
    request(`/repositories/${repoId}/conversations/${conversationId}`, { method: "DELETE" }),

  editMessage: (repoId, conversationId, messageId, content) =>
    request(`/repositories/${repoId}/conversations/${conversationId}/messages/${messageId}`, {
      method: "PATCH",
      body: JSON.stringify({ content }),
    }),

  streamConversationMessage: (repoId, conversationId, content, handlers = {}, signal) =>
    streamRequest(`/repositories/${repoId}/conversations/${conversationId}/messages`, {
      method: "POST",
      body: JSON.stringify({ content }),
      signal,
    }, handlers),

  regenerateConversation: (repoId, conversationId, handlers = {}, signal) =>
    streamRequest(`/repositories/${repoId}/conversations/${conversationId}/regenerate`, {
      method: "POST",
      signal,
    }, handlers),
};

export { ApiError };
