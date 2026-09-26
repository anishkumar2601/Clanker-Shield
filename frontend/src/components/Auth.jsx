import React, { useEffect, useMemo, useState } from "react";
import { ShieldIcon } from "../icons.jsx";
import { api } from "../api.js";
import { Button } from "./common.jsx";

const PASSWORD_HINT = "Use at least 10 characters.";

export default function Auth({ initialMode = "login", onAuthenticated }) {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [token, setToken] = useState(new URLSearchParams(window.location.search).get("token") || "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [developmentToken, setDevelopmentToken] = useState("");

  useEffect(() => {
    if (initialMode) setMode(initialMode);
  }, [initialMode]);

  const title = useMemo(() => ({
    login: "Welcome back",
    signup: "Create your account",
    forgot: "Recover your account",
    reset: "Set a new password",
    verify: "Confirm your email",
    expired: "Your session expired",
    error: "Authentication needs attention",
  }[mode] || "Welcome to ClankerShield"), [mode]);

  const switchMode = (next) => {
    setMode(next);
    setError("");
    setMessage("");
    setDevelopmentToken("");
  };

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setMessage("");
    setBusy(true);
    try {
      if (mode === "login") {
        const result = await api.login(email, password);
        onAuthenticated(result.user);
      } else if (mode === "signup") {
        const result = await api.signup(email, password, confirmation);
        setDevelopmentToken(result.development_verification_token || "");
        setMessage(result.message);
        setMode("verify");
      } else if (mode === "verify") {
        const result = await api.verifyEmail(token);
        onAuthenticated(result.user);
      } else if (mode === "forgot") {
        const result = await api.forgotPassword(email);
        setMessage(result.message);
        if (result.development_reset_token) {
          setDevelopmentToken(result.development_reset_token);
          setToken(result.development_reset_token);
        }
      } else if (mode === "reset") {
        const result = await api.resetPassword(token, password, confirmation);
        onAuthenticated(result.user);
      }
    } catch (err) {
      setError(err.message || "Authentication failed. Please try again.");
    } finally {
      setBusy(false);
    }
  };

  const isPasswordForm = mode === "login" || mode === "signup" || mode === "reset";
  const isForm = ["login", "signup", "verify", "forgot", "reset"].includes(mode);

  return (
    <main className="auth-shell">
      <div className="auth-glow" />
      <section className="auth-card" aria-labelledby="auth-title">
        <div className="auth-brand"><span className="brand-mark"><ShieldIcon size={18} /></span><span>ClankerShield</span></div>
        <p className="auth-eyebrow">AI SECURITY PLATFORM</p>
        <h1 id="auth-title">{title}</h1>
        <p className="auth-subtitle">Evidence-backed protection for every repository you own.</p>

        {error && <div className="auth-alert auth-alert-error" role="alert">{error}</div>}
        {message && <div className="auth-alert auth-alert-info" role="status">{message}</div>}

        {isForm && (
          <form className="auth-form" onSubmit={submit}>
            {(mode === "login" || mode === "signup" || mode === "forgot") && (
              <label>Email<input type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
            )}
            {isPasswordForm && (
              <label>Password<input type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} minLength={10} required />{mode !== "login" && <small>{PASSWORD_HINT}</small>}</label>
            )}
            {(mode === "signup" || mode === "reset") && (
              <label>Confirm password<input type="password" autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} minLength={10} required /></label>
            )}
            {mode === "verify" && (
              <label>Verification token<input value={token} onChange={(e) => setToken(e.target.value)} placeholder="Paste the token from your email" required /></label>
            )}
            {mode === "reset" && (
              <label>Reset token<input value={token} onChange={(e) => setToken(e.target.value)} placeholder="Paste the reset token" required /></label>
            )}
            <Button type="submit" size="lg" loading={busy}>{mode === "login" ? "Sign in" : mode === "signup" ? "Create account" : mode === "verify" ? "Verify email" : mode === "forgot" ? "Send reset link" : "Update password"}</Button>
          </form>
        )}

        {developmentToken && <div className="auth-dev-token"><strong>Development token</strong><code>{developmentToken}</code><small>Email delivery is not configured in this local deployment.</small></div>}

        {mode === "error" && <Button onClick={() => switchMode("login")}>Return to sign in</Button>}
        {mode === "expired" && <Button onClick={() => switchMode("login")}>Sign in again</Button>}

        <div className="auth-links">
          {mode === "login" && <><button onClick={() => switchMode("forgot")}>Forgot password?</button><span>New to ClankerShield? <button onClick={() => switchMode("signup")}>Create an account</button></span></>}
          {mode === "signup" && <span>Already registered? <button onClick={() => switchMode("login")}>Sign in</button></span>}
          {mode === "forgot" && <span>Remembered your password? <button onClick={() => switchMode("login")}>Sign in</button></span>}
          {mode === "verify" && <span>Already verified? <button onClick={() => switchMode("login")}>Sign in</button></span>}
          {mode === "reset" && <span>Need a new link? <button onClick={() => switchMode("forgot")}>Recover account</button></span>}
        </div>
        <p className="auth-security-note">Sessions use HttpOnly cookies. Passwords and privileged keys never enter the browser.</p>
      </section>
    </main>
  );
}
