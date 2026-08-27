from __future__ import annotations

import os
import re
from pathlib import Path

import hashlib
import hmac
import secrets
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from . import db
from .delivery import parse_delivery
from .validator import validate_text

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Проверка e-mail", version="0.1.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-this-session-secret"),
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


class TextPayload(BaseModel):
    text: str


def _hash_password(password: str) -> bytes:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return b"pbkdf2_sha256$200000$" + salt.hex().encode() + b"$" + digest.hex().encode()


def _verify_password(password: str, stored: bytes | str) -> bool:
    if isinstance(stored, str):
        stored = stored.encode()
    try:
        algo, rounds_s, salt_hex, digest_hex = stored.split(b"$", 3)
        if algo != b"pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = bytes.fromhex(salt_hex.decode())
        expected = bytes.fromhex(digest_hex.decode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _ensure_admin() -> None:
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "ChangeMe-8083")
    with db.connect() as conn:
        row = conn.execute("SELECT id FROM admin_user WHERE id=1").fetchone()
        if not row:
            password_hash = _hash_password(password)
            conn.execute(
                "INSERT INTO admin_user(id, username, password_hash) VALUES(1, ?, ?)",
                (username, password_hash),
            )


@app.on_event("startup")
def startup() -> None:
    db.init_db()
    _ensure_admin()


def _is_admin(request: Request) -> bool:
    return request.session.get("admin") is True


def _require_admin(request: Request):
    if not _is_admin(request):
        raise HTTPException(status_code=401, detail="Требуется вход администратора")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"max_addresses": db.get_setting("max_addresses", "100")},
    )


@app.post("/api/check")
async def api_check(payload: TextPayload):
    if len(payload.text) > 200_000:
        raise HTTPException(status_code=413, detail="Слишком большой объем текста")
    return await validate_text(payload.text)


@app.post("/api/delivery")
def api_delivery(payload: TextPayload):
    if len(payload.text) > 200_000:
        raise HTTPException(status_code=413, detail="Слишком большой объем текста")
    return parse_delivery(payload.text)


@app.get("/health")
def health():
    return {"status": "ok", "service": "email-checker"}


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if _is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    return templates.TemplateResponse(request=request, name="admin_login.html", context={"error": None})


@app.post("/admin/login", response_class=HTMLResponse)
def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    with db.connect() as conn:
        row = conn.execute("SELECT username, password_hash FROM admin_user WHERE id=1").fetchone()
    if row and username == row["username"] and _verify_password(password, row["password_hash"]):
        request.session["admin"] = True
        return RedirectResponse("/admin", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="admin_login.html",
        context={"error": "Неверный логин или пароль"},
        status_code=401,
    )


@app.post("/admin/logout")
def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "settings": db.get_settings(),
            "domains": db.list_standard_domains(),
            "cache": db.list_cache(),
            "smtp_statuses": db.list_smtp_statuses(),
        },
    )


@app.post("/admin/settings")
def admin_settings(
    request: Request,
    cache_positive_hours: int = Form(...),
    cache_negative_hours: int = Form(...),
    cache_temporary_minutes: int = Form(...),
    smtp_timeout_seconds: float = Form(...),
    dns_timeout_seconds: float = Form(...),
    max_addresses: int = Form(...),
    ipv6_enabled: str | None = Form(None),
):
    _require_admin(request)
    max_addresses = min(max(max_addresses, 1), 100)
    db.set_settings({
        "cache_positive_hours": str(max(1, cache_positive_hours)),
        "cache_negative_hours": str(max(1, cache_negative_hours)),
        "cache_temporary_minutes": str(max(1, cache_temporary_minutes)),
        "smtp_timeout_seconds": str(min(max(smtp_timeout_seconds, 1), 15)),
        "dns_timeout_seconds": str(min(max(dns_timeout_seconds, 1), 15)),
        "max_addresses": str(max_addresses),
        "ipv6_enabled": "1" if ipv6_enabled == "1" else "0",
    })
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/domains/add")
def admin_domain_add(request: Request, domain: str = Form(...)):
    _require_admin(request)
    domain = domain.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+", domain) or "." not in domain:
        raise HTTPException(status_code=400, detail="Некорректный домен")
    db.add_standard_domain(domain)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/domains/delete")
def admin_domain_delete(request: Request, domain: str = Form(...)):
    _require_admin(request)
    db.delete_standard_domain(domain)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/cache/clear")
def admin_cache_clear(request: Request):
    _require_admin(request)
    db.clear_cache()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/smtp/save")
def admin_smtp_save(
    request: Request,
    code: str = Form(...),
    title: str = Form(...),
    explanation: str = Form(...),
):
    _require_admin(request)
    if not re.fullmatch(r"[245]\.\d{1,3}\.\d{1,3}", code.strip()):
        raise HTTPException(status_code=400, detail="Некорректный enhanced status code")
    db.upsert_smtp_status(code, title, explanation)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/smtp/delete")
def admin_smtp_delete(request: Request, code: str = Form(...)):
    _require_admin(request)
    db.delete_smtp_status(code)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/password")
def admin_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
):
    _require_admin(request)
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Новый пароль должен быть не короче 8 символов")
    with db.connect() as conn:
        row = conn.execute("SELECT password_hash FROM admin_user WHERE id=1").fetchone()
        if not row or not _verify_password(current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Неверный текущий пароль")
        new_hash = _hash_password(new_password)
        conn.execute("UPDATE admin_user SET password_hash=? WHERE id=1", (new_hash,))
    return RedirectResponse("/admin", status_code=303)
