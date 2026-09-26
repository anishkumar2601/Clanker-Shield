"""
ClankerShield API.

Repository and scan state stays in memory for this single-process MVP;
repository-scoped copilot conversations use the small JSON store in
conversation_store.py. Every scan runs against an isolated temporary
workspace directory on disk; nothing here executes repository code.
"""
from __future__ import annotations

import os
import json
import shutil
import tempfile
import time
from contextvars import ContextVar
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel

from . import ai_analyst, auth_service, dependency_advisories, external_scanners, graph as graph_mod, inventory as inventory_mod, iac_analysis
from . import conversation_store, patches as patches_mod, reporting, security_analysis, security_tools, verification, zip_safety
from .demo_repo import materialize_demo_repository
from .models import Finding, PipelineStage, Repository, compute_metrics, new_id, now_iso

app = FastAPI(title="ClankerShield API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.environ.get("CLANKER_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()],
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
    allow_credentials=True,
)

REPOS: dict[str, Repository] = {}
CURRENT_USER: ContextVar[dict | None] = ContextVar("clanker_current_user", default=None)


@app.middleware("http")
async def authentication_boundary(request: Request, call_next):
    """Authenticate API requests before repository data can be reached.

    The default remains development-compatible (auth is opt-in) so existing
    single-user demo flows do not break. Production/multi-user deployments
    must set CLANKER_AUTH_REQUIRED=true.
    """
    token = request.cookies.get(auth_service.SESSION_COOKIE)
    authorization = request.headers.get("Authorization", "")
    if not token and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    user = auth_service.user_from_session(token)
    context_token = CURRENT_USER.set(user)
    try:
        protected_repository_path = request.url.path.startswith("/api/repositories")
        if auth_service.auth_required() and protected_repository_path and not user:
            return JSONResponse(status_code=401, content={"detail": "Authentication is required for repository access."})
        return await call_next(request)
    finally:
        CURRENT_USER.reset(context_token)


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class QuestionRequest(BaseModel):
    question: str


class ConversationCreateRequest(BaseModel):
    title: str = "Security investigation"


class ChatMessageRequest(BaseModel):
    content: str


class MessageEditRequest(BaseModel):
    content: str


class FindingStatusRequest(BaseModel):
    status: Literal["CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "IN_PROGRESS", "REOPENED"]
    reason: str = ""


class ApplyPatchRequest(BaseModel):
    patch_id: str


class SignupRequest(BaseModel):
    email: str
    password: str
    password_confirmation: str


class LoginRequest(BaseModel):
    email: str
    password: str


class VerifyEmailRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    password: str
    password_confirmation: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _current_user() -> dict:
    return CURRENT_USER.get() or {"id": "dev-local", "email": "local@clankershield.invalid", "role": "admin", "email_verified": True}


def _get_repo(repo_id: str) -> Repository:
    repo = REPOS.get(repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found. It may have expired - start a new scan.")
    user = _current_user()
    if auth_service.auth_required() and repo.owner_id != user.get("id"):
        # Do not reveal whether another user's repository exists.
        raise HTTPException(status_code=404, detail="Repository not found.")
    return repo


def _get_finding(repo: Repository, finding_id: str) -> Finding:
    finding = repo.findings.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found in this repository's latest scan.")
    return finding


def _stage(stage_id: str, label: str) -> PipelineStage:
    return PipelineStage(id=stage_id, label=label)


def _run_stage(stage: PipelineStage, fn):
    stage.status = "running"
    stage.started_at = now_iso()
    t0 = time.monotonic()
    try:
        result = fn()
        stage.status = "completed"
        return result
    except Exception as exc:  # a single stage failing must not take down the whole scan
        stage.status = "failed"
        stage.error = f"{type(exc).__name__}: stage failed; inspect server logs for details."
        return None
    finally:
        stage.finished_at = now_iso()
        stage.duration_ms = round((time.monotonic() - t0) * 1000)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _chunks(text: str, size: int = 72):
    for index in range(0, len(text), size):
        yield text[index:index + size]


def _stream_chat(repo: Repository, conversation_id: str, question: str, messages: list[dict] | None = None):
    """Stream a grounded copilot answer as server-sent events."""
    conversation = conversation_store.get_conversation(repo.id, conversation_id)
    if not conversation:
        yield _sse("error", {"detail": "Conversation not found."})
        return

    try:
        context = security_tools.build_context(repo, question, messages or conversation.get("messages", []))
        answer = ai_analyst.answer_chat(question, context)
    except Exception:
        yield _sse("error", {"detail": "The copilot could not build a grounded answer from this repository."})
        return
    yield _sse("meta", {
        "conversation_id": conversation_id,
        "mode": answer.get("mode", "local"),
        "tool_calls": answer.get("tool_calls", []),
        "referenced_finding_ids": answer.get("referenced_finding_ids", []),
    })
    for chunk in _chunks(answer.get("answer", "")):
        yield _sse("delta", {"text": chunk})

    assistant = conversation_store.append_message(
        repo.id,
        conversation_id,
        "assistant",
        answer.get("answer", "No grounded answer was produced."),
        mode=answer.get("mode", "local"),
        evidence_refs=answer.get("evidence_refs", []),
        referenced_finding_ids=answer.get("referenced_finding_ids", []),
        tool_calls=answer.get("tool_calls", []),
        follow_up_questions=answer.get("follow_up_questions", []),
    )
    yield _sse("done", {"conversation_id": conversation_id, "message": assistant})


def run_full_scan(repo: Repository) -> None:
    root = repo.workspace_path
    pipeline: list[PipelineStage] = []

    # 1. Inventory
    inv_stage = _stage("inventory", "Repository inventory")
    inv = _run_stage(inv_stage, lambda: inventory_mod.build_inventory(root))
    inv_stage.result_count = inv["total_files"] if inv else 0
    inv_stage.detail = f"{inv['total_files']} files, {len(inv['frameworks'])} framework(s) detected" if inv else "Inventory failed."
    pipeline.append(inv_stage)
    inv = inv or {}
    repo.inventory = inv
    repo.files_analyzed = inv.get("files_analyzed", inv.get("total_files", 0))
    repo.frameworks = inv.get("frameworks", [])

    all_files = inventory_mod.list_relative_files(root)

    # 2. Dependency analysis
    dep_stage = _stage("dependency_analysis", "Dependency analysis")
    dep_findings: list[Finding] = []
    osv_result: dict = {"status": "not_enabled", "findings": [], "detail": "OSV advisory lookup is disabled."}

    def _dep():
        nonlocal osv_result
        found = []
        for rel in inv.get("dependency_files", []):
            full = os.path.join(root, rel)
            if not os.path.isfile(full):
                continue
            with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            found.extend(security_analysis.scan_dependency_file(rel, text))
        osv_result = dependency_advisories.scan_osv(root, inv.get("dependency_files", []))
        return found + osv_result.get("findings", [])

    dep_findings = _run_stage(dep_stage, _dep) or []
    dep_stage.result_count = len(dep_findings)
    dep_stage.detail = f"{len(dep_findings)} dependency finding(s); {osv_result.get('detail', '')}"
    pipeline.append(dep_stage)

    # 3. Semgrep (optional)
    semgrep_stage = _stage("semgrep", "Semgrep")
    semgrep_result = _run_stage(semgrep_stage, lambda: external_scanners.run_semgrep(root)) or \
        {"status": "failed", "findings": [], "detail": "Semgrep stage raised an unexpected error."}
    semgrep_stage.status = semgrep_result["status"] if semgrep_result["status"] != "completed" else "completed"
    semgrep_stage.available = semgrep_result["status"] != "not_installed"
    semgrep_stage.result_count = len(semgrep_result["findings"])
    semgrep_stage.detail = semgrep_result["detail"]
    pipeline.append(semgrep_stage)

    # 4. Bandit (optional)
    bandit_stage = _stage("bandit", "Bandit")
    bandit_result = _run_stage(bandit_stage, lambda: external_scanners.run_bandit(root)) or \
        {"status": "failed", "findings": [], "detail": "Bandit stage raised an unexpected error."}
    bandit_stage.status = bandit_result["status"] if bandit_result["status"] != "completed" else "completed"
    bandit_stage.available = bandit_result["status"] != "not_installed"
    bandit_stage.result_count = len(bandit_result["findings"])
    bandit_stage.detail = bandit_result["detail"]
    pipeline.append(bandit_stage)

    # 5. Built-in static analysis
    static_stage = _stage("static_analysis", "Static analysis")
    static_findings = _run_stage(static_stage, lambda: [
        f for f in security_analysis.run_builtin_scanner(root, all_files) if f.type != "outdated_dependency"
    ]) or []
    static_stage.result_count = len(static_findings)
    static_stage.detail = f"{len(static_findings)} finding(s) from {len(security_analysis.BUILTIN_RULES)} transparent rules plus Python AST data-flow checks."
    pipeline.append(static_stage)

    # 6. IaC/container analysis. This is text-only and never executes a
    # Dockerfile, workflow, Terraform module, or Kubernetes manifest.
    iac_stage = _stage("iac_analysis", "IaC and container analysis")
    iac_findings = _run_stage(iac_stage, lambda: iac_analysis.scan_iac_files(root, all_files)) or []
    iac_stage.result_count = len(iac_findings)
    iac_stage.detail = f"{len(iac_findings)} evidence-backed Docker, Kubernetes, Terraform, Compose, and CI finding(s)."
    pipeline.append(iac_stage)

    # 7. Secrets
    secrets_stage = _stage("secrets", "Secret detection")
    secret_findings = _run_stage(secrets_stage, lambda: security_analysis.run_secret_scanner(root, all_files)) or []
    secrets_stage.result_count = len(secret_findings)
    secrets_stage.detail = f"{len(secret_findings)} secret-shaped value(s) found and redacted."
    pipeline.append(secrets_stage)

    # 8. Correlation
    correlation_stage = _stage("correlation", "Finding correlation")
    raw_all = dep_findings + semgrep_result["findings"] + bandit_result["findings"] + static_findings + iac_findings + secret_findings
    merged = _run_stage(correlation_stage, lambda: security_analysis.correlate_findings(raw_all)) or raw_all
    correlation_stage.result_count = len(merged)
    correlation_stage.detail = f"{len(raw_all)} raw finding(s) correlated into {len(merged)}."
    pipeline.append(correlation_stage)

    # 8. Evidence + 9. Risk
    risk_stage = _stage("risk", "Risk scoring")

    def _score_all():
        for f in merged:
            security_analysis.score_finding(f, inv)
            f.patch_available = patches_mod.can_generate_patch(f.to_dict())
        return merged

    _run_stage(risk_stage, _score_all)
    risk_stage.result_count = len(merged)
    risk_stage.detail = "Deterministic risk scores assigned to every finding."
    pipeline.append(risk_stage)

    # 10. AI reasoning (availability only - per-finding analysis happens on demand)
    ai_stage = _stage("ai_reasoning", "AI reasoning")
    repo.ai_configured = ai_analyst.ai_configured()
    ai_stage.status = "completed"
    ai_stage.available = True
    ai_stage.detail = "Model-backed reasoning configured." if repo.ai_configured else "Using deterministic local analysis (no AI provider configured)."
    ai_stage.finished_at = now_iso()
    ai_stage.started_at = ai_stage.finished_at
    ai_stage.duration_ms = 0
    pipeline.append(ai_stage)

    # 11. Attack paths + graph
    graph_stage = _stage("attack_paths", "Attack-path analysis")

    def _paths():
        for f in merged:
            f.attack_path = graph_mod.build_attack_path(f.to_dict(), inv)
        return graph_mod.build_security_graph([f.to_dict() for f in merged], inv)

    repo.graph = _run_stage(graph_stage, _paths) or {"nodes": [], "edges": []}
    graph_stage.result_count = len(repo.graph.get("nodes", []))
    graph_stage.detail = f"{len(repo.graph.get('nodes', []))} node(s), {len(repo.graph.get('edges', []))} edge(s)."
    pipeline.append(graph_stage)

    # Identity across scans: a finding is "the same" if the same rule fires on
    # the same file. This lets a rescan tell "still broken" apart from
    # "fixed" without relying on line numbers, which shift after a patch.
    def key(f: Finding):
        return (f.file, f.type, f.rule_ids[0] if f.rule_ids else None)

    previous_by_key = {key(f): f for f in repo.findings.values()}
    current_keys = {key(f) for f in merged}
    for f in merged:
        f.resolved = False
        previous = previous_by_key.get(key(f))
        if previous and previous.lifecycle_status in {"FALSE_POSITIVE", "ACCEPTED_RISK", "IN_PROGRESS", "CONFIRMED"}:
            f.lifecycle_status = previous.lifecycle_status
            f.suppression_reason = previous.suppression_reason
            f.suppressed_at = previous.suppressed_at

    # Findings resolved in an earlier scan stay in the record (as "neutralized")
    # even once they've dropped out of the live scanner output.
    carried_resolved = [f for f in repo.findings.values() if f.resolved and key(f) not in current_keys]
    carried_suppressed = [f for f in repo.findings.values() if f.lifecycle_status in {"FALSE_POSITIVE", "ACCEPTED_RISK"} and key(f) not in current_keys]

    # Anything active before that the scanner no longer finds just got fixed.
    newly_resolved = []
    for k, old_finding in previous_by_key.items():
        if not old_finding.resolved and k not in current_keys:
            old_finding.resolved = True
            old_finding.verification_status = "FIXED"
            old_finding.lifecycle_status = "FIXED"
            newly_resolved.append(old_finding)

    if repo.scan_count == 0:
        repo.baseline_findings = {f.id: f for f in merged}

    repo.findings = {f.id: f for f in merged}
    for f in carried_resolved + newly_resolved + carried_suppressed:
        repo.findings[f.id] = f

    repo.pipeline = [s.to_dict() for s in pipeline]
    repo.scan_count += 1
    repo.last_scanned_at = now_iso()
    repo.coverage = {
        "files_discovered": inv.get("files_discovered", inv.get("total_files", 0)),
        "files_analyzed": inv.get("files_analyzed", 0),
        "files_skipped": inv.get("files_skipped", 0),
        "binary_files": len(inv.get("binary_files", [])),
        "unsupported_files": len(inv.get("unsupported_files", [])),
        "files_exceeding_size_limit": len(inv.get("oversized_files", [])),
        "languages_detected": inv.get("languages_detected", sorted(inv.get("languages", {}))),
        "languages_analyzed": sorted(inv.get("languages_analyzed", {})),
        "scanners": [
            {"name": "Built-in pattern rules", "status": "completed", "detail": f"{len(static_findings)} finding(s)."},
            {"name": "Python AST data flow", "status": "completed", "detail": "Conservative source-to-sink analysis."},
            {"name": "IaC and container analysis", "status": iac_stage.status, "detail": iac_stage.detail},
            {"name": "Dependency analysis", "status": dep_stage.status, "detail": dep_stage.detail},
            {"name": "OSV advisory lookup", "status": osv_result.get("status", "failed"), "detail": osv_result.get("detail", "")},
            {"name": "Semgrep", "status": semgrep_result.get("status", "failed"), "detail": semgrep_stage.detail},
            {"name": "Bandit", "status": bandit_result.get("status", "failed"), "detail": bandit_stage.detail},
            {"name": "Runtime verification", "status": "not_run", "detail": "Repository code is never executed on the host."},
        ],
        "dependency_files_found": len(inv.get("dependency_files", [])),
        "dependency_files_analyzed": len(inv.get("dependency_files", [])) if dep_stage.status == "completed" else 0,
    }
    scan_record = {
        "scan_id": new_id("scan"),
        "scan_number": repo.scan_count,
        "timestamp": repo.last_scanned_at,
        "findings": compute_metrics(list(repo.findings.values())),
        "risk_score": compute_metrics(list(repo.findings.values())).get("security_risk_score"),
        "duration_ms": sum(stage.duration_ms or 0 for stage in pipeline),
        "coverage": repo.coverage,
    }
    repo.scan_history = (repo.scan_history + [scan_record])[-100:]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "time": now_iso(),
        "auth_required": auth_service.auth_required(),
        "semgrep_available": external_scanners.semgrep_available(),
        "bandit_available": external_scanners.bandit_available(),
        "osv_enabled": dependency_advisories.osv_enabled(),
        "ai_configured": ai_analyst.ai_configured(),
    }


def _set_session_cookie(response: Response, user: dict) -> None:
    response.set_cookie(
        auth_service.SESSION_COOKIE,
        auth_service.issue_session(user["id"]),
        httponly=True,
        secure=os.environ.get("CLANKER_SECURE_COOKIES", "false").lower() in {"1", "true", "yes", "on"},
        samesite="lax",
        max_age=auth_service.SESSION_TTL_SECONDS,
        path="/",
    )


@app.post("/api/auth/signup")
def signup(body: SignupRequest):
    try:
        user, verification_token = auth_service.create_user(body.email, body.password, body.password_confirmation)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = {"status": "verification_required", "user": user, "message": "Account created. Verify your email before signing in."}
    if auth_service.development_tokens_enabled():
        result["development_verification_token"] = verification_token
    return result


@app.post("/api/auth/verify-email")
def verify_email(body: VerifyEmailRequest, response: Response):
    user = auth_service.verify_email(body.token.strip())
    if not user:
        raise HTTPException(status_code=400, detail="That verification link is invalid or has already been used.")
    _set_session_cookie(response, user)
    return {"status": "verified", "user": user}


@app.post("/api/auth/login")
def login(body: LoginRequest, response: Response):
    user = auth_service.authenticate(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email, password, or unverified account.")
    _set_session_cookie(response, user)
    return {"status": "authenticated", "user": user}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(auth_service.SESSION_COOKIE, path="/")
    return {"status": "signed_out"}


@app.get("/api/auth/me")
def me():
    user = CURRENT_USER.get()
    return {"authenticated": bool(user), "user": user}


@app.post("/api/auth/forgot-password")
def forgot_password(body: ForgotPasswordRequest):
    # Always return the same public response to reduce account enumeration.
    token = auth_service.request_password_reset(body.email)
    result = {"status": "accepted", "message": "If an account matches, password reset instructions will be sent."}
    if token and auth_service.development_tokens_enabled():
        result["development_reset_token"] = token
    return result


@app.post("/api/auth/reset-password")
def reset_password(body: ResetPasswordRequest, response: Response):
    try:
        user = auth_service.reset_password(body.token.strip(), body.password, body.password_confirmation)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not user:
        raise HTTPException(status_code=400, detail="That reset link is invalid or expired.")
    _set_session_cookie(response, user)
    return {"status": "password_updated", "user": user}


@app.post("/api/repositories/demo")
def create_demo_repository():
    workspace = tempfile.mkdtemp(prefix="clanker_demo_")
    materialize_demo_repository(workspace)
    repo = Repository(id=new_id("repo"), name="Clanker Demo Service", source_type="demo", workspace_path=workspace, owner_id=_current_user()["id"])
    REPOS[repo.id] = repo
    run_full_scan(repo)
    return repo.summary_dict()


@app.post("/api/repositories/upload")
async def upload_repository(file: UploadFile = File(...)):
    content = await file.read()
    workspace = tempfile.mkdtemp(prefix="clanker_upload_")
    try:
        result = zip_safety.safe_extract_zip(content, workspace)
    except zip_safety.ZipSafetyError as exc:
        shutil.rmtree(workspace, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc))

    name = os.path.splitext(file.filename or "Uploaded repository")[0]
    repo = Repository(id=new_id("repo"), name=name or "Uploaded repository", source_type="upload", workspace_path=workspace, owner_id=_current_user()["id"])
    REPOS[repo.id] = repo
    run_full_scan(repo)
    response = repo.summary_dict()
    response["upload_notice"] = {
        "files_extracted": result.files_extracted,
        "skipped_members": result.skipped_members[:20],
        "nested_archives_kept_as_files": (result.nested_archives or [])[:20],
    }
    return response


@app.get("/api/repositories/{repo_id}")
def get_repository(repo_id: str):
    return _get_repo(repo_id).summary_dict()


@app.post("/api/repositories/{repo_id}/scan")
def rescan_repository(repo_id: str):
    repo = _get_repo(repo_id)
    run_full_scan(repo)
    return repo.summary_dict()


@app.get("/api/repositories/{repo_id}/findings/{finding_id}")
def get_finding(repo_id: str, finding_id: str):
    repo = _get_repo(repo_id)
    return _get_finding(repo, finding_id).to_dict()


@app.post("/api/repositories/{repo_id}/findings/{finding_id}/analyze")
def analyze_finding(repo_id: str, finding_id: str):
    repo = _get_repo(repo_id)
    finding = _get_finding(repo, finding_id)
    return ai_analyst.analyze_finding(finding.to_dict(), repo.inventory)


@app.post("/api/repositories/{repo_id}/findings/{finding_id}/status")
def update_finding_status(repo_id: str, finding_id: str, body: FindingStatusRequest):
    repo = _get_repo(repo_id)
    finding = _get_finding(repo, finding_id)
    status = body.status
    reason = (body.reason or "").strip()
    if status in {"FALSE_POSITIVE", "ACCEPTED_RISK"} and len(reason) < 8:
        raise HTTPException(status_code=400, detail="A reason of at least 8 characters is required when suppressing a finding.")
    finding.lifecycle_status = "OPEN" if status == "REOPENED" else status
    finding.suppression_reason = "" if status == "REOPENED" else reason
    finding.suppressed_at = None if status == "REOPENED" else (now_iso() if status in {"FALSE_POSITIVE", "ACCEPTED_RISK"} else finding.suppressed_at)
    finding.verification_status = "DETECTED" if status == "REOPENED" else finding.verification_status
    repo.audit_events.append({"event": "finding_status_changed", "finding_id": finding.id, "status": status, "timestamp": now_iso()})
    return finding.to_dict()


@app.post("/api/repositories/{repo_id}/questions")
def ask_question(repo_id: str, body: QuestionRequest):
    repo = _get_repo(repo_id)
    if not body.question or not body.question.strip():
        raise HTTPException(status_code=400, detail="Ask a question about the scan first.")
    findings = [f.to_dict() for f in repo.findings.values()]
    return ai_analyst.answer_question(body.question.strip(), findings, repo.inventory)


@app.get("/api/repositories/{repo_id}/conversations")
def list_conversations(repo_id: str):
    _get_repo(repo_id)
    return {"conversations": conversation_store.list_conversations(repo_id)}


@app.post("/api/repositories/{repo_id}/conversations")
def create_conversation(repo_id: str, body: ConversationCreateRequest | None = None):
    _get_repo(repo_id)
    title = ((body.title if body else None) or "Security investigation").strip()
    if len(title) > 120:
        raise HTTPException(status_code=400, detail="Conversation title must be 120 characters or fewer.")
    return {"conversation": conversation_store.create_conversation(repo_id, title)}


@app.get("/api/repositories/{repo_id}/conversations/{conversation_id}")
def get_conversation(repo_id: str, conversation_id: str):
    _get_repo(repo_id)
    conversation = conversation_store.get_conversation(repo_id, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return {"conversation": conversation}


@app.delete("/api/repositories/{repo_id}/conversations/{conversation_id}")
def delete_conversation(repo_id: str, conversation_id: str):
    _get_repo(repo_id)
    if not conversation_store.remove_conversation(repo_id, conversation_id):
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return {"status": "deleted", "conversation_id": conversation_id}


@app.patch("/api/repositories/{repo_id}/conversations/{conversation_id}/messages/{message_id}")
def edit_conversation_message(repo_id: str, conversation_id: str, message_id: str, body: MessageEditRequest):
    _get_repo(repo_id)
    content = (body.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message content cannot be empty.")
    try:
        message = conversation_store.update_message(repo_id, conversation_id, message_id, content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not message:
        raise HTTPException(status_code=404, detail="Editable user message not found.")
    return {"message": message}


@app.post("/api/repositories/{repo_id}/conversations/{conversation_id}/messages")
def send_conversation_message(repo_id: str, conversation_id: str, body: ChatMessageRequest):
    repo = _get_repo(repo_id)
    conversation = conversation_store.get_conversation(repo_id, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    content = (body.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message content cannot be empty.")
    if len(content) > 2000:
        raise HTTPException(status_code=400, detail="Message content must be 2,000 characters or fewer.")
    try:
        conversation_store.append_message(repo_id, conversation_id, "user", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return StreamingResponse(
        _stream_chat(repo, conversation_id, content),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/repositories/{repo_id}/conversations/{conversation_id}/regenerate")
def regenerate_conversation_message(repo_id: str, conversation_id: str):
    repo = _get_repo(repo_id)
    conversation = conversation_store.get_conversation(repo_id, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    latest_user = next((item for item in reversed(conversation.get("messages", [])) if item.get("role") == "user"), None)
    if not latest_user:
        raise HTTPException(status_code=400, detail="Send a user message before regenerating an answer.")
    return StreamingResponse(
        _stream_chat(repo, conversation_id, latest_user["content"], conversation.get("messages", [])),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/repositories/{repo_id}/findings/{finding_id}/fix")
def generate_fix(repo_id: str, finding_id: str):
    repo = _get_repo(repo_id)
    finding = _get_finding(repo, finding_id)
    try:
        patch = patches_mod.generate_patch(repo.workspace_path, repo.id, finding.to_dict())
    except patches_mod.PatchError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    repo.patches[patch.id] = patch
    return patch.public_dict()


@app.post("/api/repositories/{repo_id}/patches/apply")
def apply_patch(repo_id: str, body: ApplyPatchRequest):
    repo = _get_repo(repo_id)
    patch = repo.patches.get(body.patch_id)
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found. Generate a fix again.")
    if patch.status != "draft":
        raise HTTPException(status_code=409, detail=f"This patch is already {patch.status}.")
    try:
        patches_mod.apply_patch(repo.workspace_path, patch)
    except patches_mod.PatchError as exc:
        patch.status = "stale"
        raise HTTPException(status_code=409, detail=str(exc))
    patch.status = "applied"
    repo.audit_events.append({"event": "patch_applied", "patch_id": patch.id, "timestamp": now_iso()})
    finding = repo.findings.get(patch.finding_id)
    return {"patch": patch.public_dict(), "finding_id": patch.finding_id, "finding_title": finding.title if finding else None}


@app.post("/api/repositories/{repo_id}/patches/{patch_id}/rollback")
def rollback_patch(repo_id: str, patch_id: str):
    repo = _get_repo(repo_id)
    patch = repo.patches.get(patch_id)
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found.")
    try:
        patches_mod.rollback_patch(repo.workspace_path, patch)
    except patches_mod.PatchError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    repo.audit_events.append({"event": "patch_rolled_back", "patch_id": patch.id, "timestamp": now_iso()})
    return {"patch": patch.public_dict(), "status": "rolled_back"}


@app.post("/api/repositories/{repo_id}/verify")
def verify_repository(repo_id: str):
    repo = _get_repo(repo_id)
    before_findings_all = [f.to_dict() for f in repo.findings.values()]
    before_active = [f for f in before_findings_all if not f["resolved"] and f.get("lifecycle_status") not in {"FALSE_POSITIVE", "ACCEPTED_RISK"}]
    target_patch = next((p for p in repo.patches.values() if p.status == "applied"), None)

    all_files = inventory_mod.list_relative_files(repo.workspace_path)
    syntax_result = verification.check_python_syntax(repo.workspace_path, all_files)

    run_full_scan(repo)  # rescan in place - this is the window compared below
    after_active = [f.to_dict() for f in repo.findings.values() if not f.resolved and f.lifecycle_status not in {"FALSE_POSITIVE", "ACCEPTED_RISK"}]

    diff_summary = verification.compare_scans(before_active, after_active)

    verdict = "NOT_VERIFIED"
    if target_patch:
        finding = None
        for f in before_findings_all:
            if f["id"] == target_patch.finding_id:
                finding = f
                break
        if finding:
            target_key = (finding["file"], finding["type"], (finding.get("rule_ids") or [None])[0])
            verdict = verification.determine_verdict(target_key, before_active, after_active, syntax_result, diff_summary)

    static_scan = "PASS" if target_patch and diff_summary.get("resolved_count", 0) > 0 else "NOT_RUN"
    if target_patch and diff_summary.get("resolved_count", 0) > 0 and diff_summary.get("new_critical_high_count", 0) > 0:
        static_scan = "FAIL"
    syntax_status = "PASS" if syntax_result["passed"] else "FAIL"
    if target_patch:
        target_patch.verification_status = verdict

    record = {
        "verified_at": now_iso(),
        "verdict": verdict,
        "static_scan": static_scan,
        "syntax_verification": syntax_status,
        "existing_tests": "NOT_RUN",
        "security_regression_test": "NOT_RUN",
        "runtime_verification": "NOT_AVAILABLE",
        "new_critical_high_findings": diff_summary.get("new_critical_high_count", 0),
        "syntax_check": syntax_result,
        "diff": diff_summary,
        "runtime_tests": "NOT_AVAILABLE",
        "patch_id": target_patch.id if target_patch else None,
    }
    repo.verification_history.append(record)
    return {**record, "repository": repo.summary_dict()}


@app.get("/api/repositories/{repo_id}/structure")
def get_structure(repo_id: str):
    repo = _get_repo(repo_id)
    files = inventory_mod.list_relative_files(repo.workspace_path)
    tree: dict = {}
    for rel in sorted(files):
        parts = rel.split(os.sep)
        cursor = tree
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor.setdefault("__files__", []).append(parts[-1])
    return {"root": repo.name, "tree": tree, "total_files": len(files)}


@app.get("/api/repositories/{repo_id}/inventory")
def get_inventory(repo_id: str):
    return _get_repo(repo_id).inventory


@app.get("/api/repositories/{repo_id}/graph")
def get_graph(repo_id: str):
    return _get_repo(repo_id).graph


@app.get("/api/repositories/{repo_id}/reports/{report_format}")
def get_report(repo_id: str, report_format: str):
    """Export the latest evidence without claiming unavailable verification."""
    repo = _get_repo(repo_id)
    formatters = {
        "json": (reporting.to_json, "application/json", "json"),
        "sarif": (reporting.to_sarif, "application/sarif+json", "sarif"),
        "csv": (reporting.to_csv, "text/csv; charset=utf-8", "csv"),
        "markdown": (reporting.to_markdown, "text/markdown; charset=utf-8", "md"),
        "md": (reporting.to_markdown, "text/markdown; charset=utf-8", "md"),
        "html": (reporting.to_html, "text/html; charset=utf-8", "html"),
    }
    formatter = formatters.get(report_format.lower())
    if not formatter:
        raise HTTPException(status_code=404, detail="Supported report formats: json, sarif, csv, markdown, html.")
    render, media_type, extension = formatter
    return Response(
        content=render(repo),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="clankershield-{repo.id}.{extension}"'},
    )
