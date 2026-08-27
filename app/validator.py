from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

import dns.asyncresolver
import dns.exception
import dns.resolver
import idna

from . import db

INVISIBLE = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"}
LOCAL_ASCII_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-")
DOMAIN_ASCII_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")

EMAIL_CANDIDATE_RE = re.compile(r"[^\s<>\"()\[\],;:]+@[^\s<>\"'()\[\],;:]+", re.UNICODE)

CYR_TO_LAT = str.maketrans({
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
    "у": "y", "У": "Y", "і": "i", "І": "I", "к": "k", "К": "K",
    "м": "m", "М": "M", "т": "t", "Т": "T", "в": "b", "В": "B",
    "л": "l", "Л": "L",
})


@dataclass
class Candidate:
    line: int
    source: str
    email: str


def script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    if "CYRILLIC" in name:
        return "cyrillic"
    if "LATIN" in name:
        return "latin"
    return "other"


def clean_invisible(text: str) -> str:
    return "".join(ch for ch in text if ch not in INVISIBLE)


def extract_candidates(text: str, max_addresses: int = 100) -> tuple[list[Candidate], bool]:
    candidates: list[Candidate] = []
    overflow = False
    for line_no, original in enumerate(text.splitlines() or [text], start=1):
        line = clean_invisible(original)
        for match in EMAIL_CANDIDATE_RE.finditer(line):
            token = match.group(0)
            token = token.rstrip(".,;:!?»)]}>'")
            token = token.lstrip("«([{<'")
            # A copied mailto: link may carry URI parameters after the domain.
            if "@" in token:
                left, right = token.split("@", 1)
                right = re.split(r"[?#]", right, maxsplit=1)[0]
                token = f"{left}@{right}"
            token = re.sub(r"^(?:mailto:|smtp:)", "", token, flags=re.I)
            if "@" not in token:
                continue
            # For Outlook-style semicolon lists, keep only this recipient's source fragment.
            seg_start = line.rfind(";", 0, match.start()) + 1
            seg_end = line.find(";", match.end())
            if seg_end < 0:
                seg_end = len(line)
            source_fragment = original[seg_start:seg_end].strip() or original
            candidates.append(Candidate(line=line_no, source=source_fragment, email=token))
            if len(candidates) >= max_addresses:
                # Keep exactly max_addresses and signal that more were present.
                if EMAIL_CANDIDATE_RE.search(line[match.end():]) or any(EMAIL_CANDIDATE_RE.search(x) for x in text.splitlines()[line_no:]):
                    overflow = True
                return candidates[:max_addresses], overflow
    return candidates, overflow


def _minority_script_highlights(value: str, base_offset: int = 0) -> list[dict]:
    positions = {"latin": [], "cyrillic": [], "other": []}
    for i, ch in enumerate(value):
        sc = script_of(ch)
        if sc:
            positions.setdefault(sc, []).append(i)
    latin = positions["latin"]
    cyr = positions["cyrillic"]
    if latin and cyr:
        bad = cyr if len(cyr) <= len(latin) else latin
        return [{"start": base_offset + i, "end": base_offset + i + 1, "kind": "syntax"} for i in bad]
    return []


def _validate_local(local: str, domain_is_cyrillic_rf: bool) -> tuple[list[dict], str | None]:
    highlights: list[dict] = []
    scripts = {script_of(ch) for ch in local if script_of(ch)}
    scripts.discard(None)
    if "latin" in scripts and "cyrillic" in scripts:
        highlights.extend(_minority_script_highlights(local))
        return highlights, "Проверьте имя"
    if "cyrillic" in scripts and not domain_is_cyrillic_rf:
        for i, ch in enumerate(local):
            if script_of(ch) == "cyrillic":
                highlights.append({"start": i, "end": i + 1, "kind": "syntax"})
        return highlights, "Проверьте имя"

    if not local or len(local.encode("utf-8")) > 64:
        return [{"start": 0, "end": max(1, len(local)), "kind": "syntax"}], "Проверьте имя"
    if local.startswith(".") or local.endswith(".") or ".." in local:
        for i, ch in enumerate(local):
            if ch == "." and (i == 0 or i == len(local)-1 or (i+1 < len(local) and local[i+1] == ".")):
                highlights.append({"start": i, "end": i + 1, "kind": "syntax"})
        return highlights or [{"start": 0, "end": len(local), "kind": "syntax"}], "Проверьте имя"

    for i, ch in enumerate(local):
        sc = script_of(ch)
        if sc == "cyrillic" and domain_is_cyrillic_rf:
            continue
        if ch not in LOCAL_ASCII_ALLOWED and sc != "cyrillic":
            highlights.append({"start": i, "end": i + 1, "kind": "syntax"})
    if highlights:
        return highlights, "Проверьте имя"
    return [], None


def _domain_is_unicode_rf(domain: str) -> bool:
    return domain.lower().endswith(".рф") and any(script_of(ch) == "cyrillic" for ch in domain)


def _validate_domain_syntax(domain: str, offset: int) -> tuple[str | None, list[dict], str | None, bool]:
    """Return ascii_domain, highlights, message, is_unicode_rf."""
    if not domain:
        return None, [{"start": offset, "end": offset + 1, "kind": "syntax"}], "Проверьте домен", False

    scripts = {script_of(ch) for ch in domain if script_of(ch)}
    scripts.discard(None)
    if "latin" in scripts and "cyrillic" in scripts:
        return None, _minority_script_highlights(domain, offset), "Проверьте домен", False

    is_rf = _domain_is_unicode_rf(domain)
    if "cyrillic" in scripts and not is_rf:
        hs = [
            {"start": offset + i, "end": offset + i + 1, "kind": "syntax"}
            for i, ch in enumerate(domain) if script_of(ch) == "cyrillic"
        ]
        return None, hs, "Проверьте домен", False

    if any(ch.isspace() for ch in domain):
        hs = [{"start": offset+i, "end": offset+i+1, "kind": "syntax"} for i, ch in enumerate(domain) if ch.isspace()]
        return None, hs, "Проверьте домен", is_rf

    try:
        if is_rf:
            ascii_domain = idna.encode(domain.lower()).decode("ascii")
        else:
            ascii_domain = domain.lower()
            # Also accept explicit punycode forms if they are valid IDNA.
            if ascii_domain.startswith("xn--") or ".xn--" in ascii_domain:
                decoded = idna.decode(ascii_domain)
                if decoded.lower().endswith(".рф"):
                    is_rf = True
    except idna.IDNAError:
        return None, [{"start": offset, "end": offset + len(domain), "kind": "syntax"}], "Проверьте домен", is_rf

    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return None, [{"start": offset, "end": offset + len(domain), "kind": "syntax"}], "Проверьте домен", is_rf

    for idx, label in enumerate(ascii_domain.split(".")):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or not set(label) <= DOMAIN_ASCII_ALLOWED:
            return None, [{"start": offset, "end": offset + len(domain), "kind": "syntax"}], "Проверьте домен", is_rf
    return ascii_domain, [], None, is_rf


def normalize_email(email: str) -> tuple[str, str, str] | None:
    email = unicodedata.normalize("NFC", clean_invisible(email)).strip()
    if email.count("@") != 1:
        return None
    local, domain = email.split("@", 1)
    domain = domain.lower()
    return f"{local}@{domain}", local, domain


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j-1] + (ca != cb)))
        prev = cur
    return prev[-1]


def suggest_domain(domain: str, standard_domains: Iterable[str]) -> str | None:
    # Conservative: only known domains, only a close and unique match.
    variants = {domain.lower(), domain.translate(CYR_TO_LAT).lower()}
    if "п" in domain.lower():
        variants.add(domain.lower().replace("п", "in"))
    scored = []
    for target in standard_domains:
        target = target.lower()
        score = min(levenshtein(v, target) for v in variants)
        if score <= 2:
            scored.append((score, target))
    scored.sort()
    if not scored:
        return None
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return None
    return scored[0][1]


async def _resolve(resolver: dns.asyncresolver.Resolver, name: str, rrtype: str) -> list[str]:
    try:
        ans = await resolver.resolve(name, rrtype, lifetime=float(db.get_setting("dns_timeout_seconds", "3")))
        return [str(r).rstrip(".") for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


async def _smtp_banner(ip: str, host: str, timeout: float) -> tuple[bool, str | None]:
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def worker():
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            address = (ip, 25, 0, 0) if family == socket.AF_INET6 else (ip, 25)
            s.connect(address)
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            try:
                s.sendall(b"QUIT\r\n")
            except OSError:
                pass
            return banner.startswith("220"), banner[:300]
        except OSError:
            return False, None
        finally:
            s.close()

    return await asyncio.to_thread(worker)


async def _check_domain_uncached(ascii_domain: str) -> dict:
    settings = db.get_settings()
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = float(settings.get("dns_timeout_seconds", "3"))
    resolver.timeout = float(settings.get("dns_timeout_seconds", "3"))

    result = {
        "domain": ascii_domain,
        "cached": False,
        "mx": [],
        "ipv4": [],
        "ipv6": [],
        "smtp_ok": False,
        "smtp_protocol": None,
        "smtp_banner": None,
        "state": "unknown",
    }
    now = datetime.now(timezone.utc)

    try:
        mx_answer = await resolver.resolve(ascii_domain, "MX", lifetime=resolver.lifetime)
        mx_records = sorted((int(r.preference), str(r.exchange).rstrip(".")) for r in mx_answer)
        if any(host == "" for _, host in mx_records):
            result["state"] = "invalid"
            expires = now + timedelta(hours=float(settings.get("cache_negative_hours", "24")))
            db.put_cache(ascii_domain, "invalid", result, expires.isoformat())
            return result
        result["mx"] = [host for _, host in mx_records]
    except dns.resolver.NXDOMAIN:
        result["state"] = "invalid"
        expires = now + timedelta(hours=float(settings.get("cache_negative_hours", "24")))
        db.put_cache(ascii_domain, "invalid", result, expires.isoformat())
        return result
    except dns.resolver.NoAnswer:
        # RFC SMTP implicit MX fallback to the domain itself.
        result["mx"] = [ascii_domain]
        result["implicit_mx"] = True
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        result["state"] = "temporary"
        expires = now + timedelta(minutes=float(settings.get("cache_temporary_minutes", "30")))
        db.put_cache(ascii_domain, "temporary", result, expires.isoformat())
        return result

    ipv6_enabled = settings.get("ipv6_enabled", "1") == "1"
    hosts = result["mx"][:5]
    queries = []
    meta = []
    for host in hosts:
        queries.append(_resolve(resolver, host, "A")); meta.append("A")
        if ipv6_enabled:
            queries.append(_resolve(resolver, host, "AAAA")); meta.append("AAAA")
    resolved_sets = await asyncio.gather(*queries) if queries else []
    for rrtype, values in zip(meta, resolved_sets):
        target = result["ipv6"] if rrtype == "AAAA" else result["ipv4"]
        for value in values:
            if value not in target:
                target.append(value)

    if not result["ipv4"] and not result["ipv6"]:
        result["state"] = "invalid"
        expires = now + timedelta(hours=float(settings.get("cache_negative_hours", "24")))
        db.put_cache(ascii_domain, "invalid", result, expires.isoformat())
        return result

    timeout = float(settings.get("smtp_timeout_seconds", "4"))
    # Try a small dual-stack sample in parallel, so one unreachable family does not stall the check.
    addresses = ([(ip, "IPv6") for ip in result["ipv6"][:2]] +
                 [(ip, "IPv4") for ip in result["ipv4"][:2]])

    async def attempt(ip: str, protocol: str):
        ok, banner = await _smtp_banner(ip, result["mx"][0], timeout)
        return protocol, ok, banner

    attempts = [asyncio.create_task(attempt(ip, protocol)) for ip, protocol in addresses]
    try:
        for task in asyncio.as_completed(attempts):
            protocol, ok, banner = await task
            if ok:
                result["smtp_ok"] = True
                result["smtp_protocol"] = protocol
                result["smtp_banner"] = banner
                break
    finally:
        for task in attempts:
            if not task.done():
                task.cancel()

    if result["smtp_ok"]:
        result["state"] = "valid"
        expires = now + timedelta(hours=float(settings.get("cache_positive_hours", "168")))
        db.put_cache(ascii_domain, "valid", result, expires.isoformat())
    else:
        # DNS/MX exists, but connection can fail for reasons outside the target domain.
        result["state"] = "temporary"
        expires = now + timedelta(minutes=float(settings.get("cache_temporary_minutes", "30")))
        db.put_cache(ascii_domain, "temporary", result, expires.isoformat())
    return result


_DOMAIN_INFLIGHT: dict[str, asyncio.Task] = {}


async def check_domain(ascii_domain: str) -> dict:
    cached = db.get_cache(ascii_domain)
    if cached:
        return cached
    existing = _DOMAIN_INFLIGHT.get(ascii_domain)
    if existing:
        return await existing
    task = asyncio.create_task(_check_domain_uncached(ascii_domain))
    _DOMAIN_INFLIGHT[ascii_domain] = task
    try:
        return await task
    finally:
        if _DOMAIN_INFLIGHT.get(ascii_domain) is task:
            _DOMAIN_INFLIGHT.pop(ascii_domain, None)


async def validate_one(candidate: Candidate, standard_domains: list[str]) -> dict:
    normalized = normalize_email(candidate.email)
    base = {
        "line": candidate.line,
        "source": candidate.source,
        "original": candidate.email,
        "cleaned": candidate.email,
        "status": "warning",
        "symbol": "!",
        "result": "Проверьте адрес",
        "highlights": [],
        "suggestion": None,
        "domain_check": None,
    }
    if not normalized:
        base["highlights"] = [{"start": 0, "end": max(1, len(candidate.email)), "kind": "syntax"}]
        return base

    cleaned, local, domain = normalized
    base["cleaned"] = cleaned
    at_offset = len(local) + 1

    # Domain syntax first, because local Unicode policy depends on whether this is a Cyrillic .рф domain.
    ascii_domain, dh, dmsg, is_cyr_rf = _validate_domain_syntax(domain, at_offset)
    lh, lmsg = _validate_local(local, is_cyr_rf)
    if lh or lmsg:
        base["highlights"].extend(lh)
        base["result"] = lmsg or "Проверьте имя"
    if dh or dmsg:
        base["highlights"].extend(dh)
        if not lmsg:
            base["result"] = dmsg or "Проверьте домен"

    if base["highlights"]:
        if dmsg:
            suggested = suggest_domain(domain, standard_domains)
            if suggested and suggested != domain.lower():
                base["suggestion"] = f"{local}@{suggested}"
        return base

    assert ascii_domain is not None
    domain_result = await check_domain(ascii_domain)
    base["domain_check"] = domain_result
    if domain_result["state"] == "valid":
        base.update(status="ok", symbol="✓", result="Адрес корректен")
        return base
    if domain_result["state"] == "invalid":
        base.update(status="warning", symbol="!", result="Проверьте домен")
        base["highlights"] = [{"start": at_offset, "end": len(cleaned), "kind": "domain"}]
        suggested = suggest_domain(domain, standard_domains)
        if suggested and suggested != domain.lower():
            base["suggestion"] = f"{local}@{suggested}"
        return base

    base.update(status="unknown", symbol="?", result="Не удалось проверить")
    return base


async def validate_text(text: str) -> dict:
    max_addresses = int(db.get_setting("max_addresses", "100"))
    candidates, overflow = extract_candidates(text, max_addresses=max_addresses)
    standard_domains = db.list_standard_domains()

    # Deduplicate technical checks by cleaned email, while keeping every input occurrence in output.
    tasks: dict[str, asyncio.Task] = {}
    results: list[dict] = []
    seen_keys: list[str] = []
    network_slots = asyncio.Semaphore(10)

    async def limited_validate(candidate: Candidate):
        async with network_slots:
            return await validate_one(candidate, standard_domains)
    for c in candidates:
        norm = normalize_email(c.email)
        key = norm[0] if norm else c.email
        seen_keys.append(key)
        if key not in tasks:
            tasks[key] = asyncio.create_task(limited_validate(c))

    resolved = {key: await task for key, task in tasks.items()}
    occurrence = {}
    for c, key in zip(candidates, seen_keys):
        occurrence[key] = occurrence.get(key, 0) + 1
        item = dict(resolved[key])
        # Preserve each source line even when technical result came from first occurrence.
        item["line"] = c.line
        item["source"] = c.source
        item["original"] = c.email
        results.append(item)

    duplicate_count = sum(count - 1 for count in occurrence.values() if count > 1)
    return {
        "count": len(results),
        "unique_count": len(tasks),
        "duplicate_count": duplicate_count,
        "overflow": overflow,
        "results": results,
    }
