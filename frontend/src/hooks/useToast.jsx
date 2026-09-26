import React, { createContext, useCallback, useContext, useRef, useState } from "react";
import { CheckIcon, AlertTriangleIcon, XIcon, SparkleIcon } from "../icons.jsx";

const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const idRef = useRef(0);

  const dismiss = useCallback((id) => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((message, kind = "info", timeout = 4200) => {
    const id = ++idRef.current;
    setToasts((list) => [...list, { id, message, kind }]);
    if (timeout) setTimeout(() => dismiss(id), timeout);
    return id;
  }, [dismiss]);

  const toast = {
    success: (m) => push(m, "success"),
    error: (m) => push(m, "error"),
    info: (m) => push(m, "info"),
    ai: (m) => push(m, "ai"),
  };

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`}>
            <span className="toast-icon">
              {t.kind === "success" && <CheckIcon size={16} />}
              {t.kind === "error" && <AlertTriangleIcon size={16} />}
              {t.kind === "ai" && <SparkleIcon size={16} />}
              {t.kind === "info" && <SparkleIcon size={16} />}
            </span>
            <span className="toast-message">{t.message}</span>
            <button className="toast-dismiss" onClick={() => dismiss(t.id)} aria-label="Dismiss">
              <XIcon size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
