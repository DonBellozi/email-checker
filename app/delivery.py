from __future__ import annotations

import re

from . import db

ACTION_TITLES = {
    "delivered": ("ok", "✓", "Письмо доставлено", "Доставка завершена успешно."),
    "delayed": ("warning", "!", "Доставка задерживается", "Почтовый сервер продолжит попытки доставки. Повторно отправлять письмо сейчас не требуется."),
    "failed": ("error", "!", "Письмо не доставлено", "Доставка завершилась ошибкой."),
    "relayed": ("ok", "✓", "Письмо передано другому серверу", "Сообщение принято промежуточным почтовым сервером для дальнейшей доставки."),
    "expanded": ("ok", "✓", "Адрес раскрыт в несколько получателей", "Почтовая система преобразовала исходный адрес в один или несколько конечных адресов."),
}

LOCAL_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-")
DOMAIN_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")

KEYWORD_RULES = [
    (re.compile(r"\bspf\b.*(?:fail|failed|softfail|reject)|(?:fail|failed).*\bspf\b", re.I), "Не пройдена проверка SPF", "Сервер получателя не подтвердил право отправляющего сервера отправлять почту от имени домена."),
    (re.compile(r"\bdkim\b.*(?:fail|failed|invalid)|(?:fail|failed|invalid).*\bdkim\b", re.I), "Не пройдена проверка DKIM", "Сервер получателя не смог подтвердить DKIM-подпись сообщения."),
    (re.compile(r"\bdmarc\b.*(?:fail|failed|reject)|(?:fail|failed|reject).*\bdmarc\b", re.I), "Не пройдена проверка DMARC", "Политика DMARC домена не разрешила принять сообщение."),
    (re.compile(r"blacklist|blocklist|blocked using|listed in", re.I), "Отправитель заблокирован", "Сервер или IP-адрес отправителя находится в списке блокировки или отклонен политикой получателя."),
    (re.compile(r"relay access denied|relaying denied|relay denied", re.I), "Пересылка запрещена", "Почтовый сервер не разрешает пересылку сообщения для указанного направления."),
    (re.compile(r"message size|too large|size exceeds|exceeded.*size", re.I), "Сообщение слишком большое", "Размер письма превышает ограничение почтовой системы."),
    (re.compile(r"mailbox (?:is )?full|quota exceeded|over quota", re.I), "Почтовый ящик переполнен", "На стороне получателя недостаточно свободного места."),
    (re.compile(r"bad destination mailbox address syntax|ill-?formatted e-?mail address|invalid (?:recipient|mailbox).*syntax", re.I), "Некорректный адрес получателя", "Адрес получателя записан с синтаксической ошибкой. Удалите лишние кавычки, префикс mailto: и другие посторонние символы."),
    (re.compile(r"domain not found|host or domain name not found|no such domain|domain.*does not exist", re.I), "Домен получателя не найден", "Почтовый домен получателя не существует или не разрешается через DNS. Проверьте часть адреса после @."),
    (re.compile(r"user unknown|unknown user|user not found|recipient.*not found|no such user|invalid mailbox|mailbox.*(?:not found|unavailable)", re.I), "Получатель не найден", "Проверьте адрес электронной почты получателя."),
    (re.compile(r"conversation with.*timed out|timed out.*(?:server greeting|connection)|connection timed out", re.I), "Сервер получателя не ответил", "Не удалось установить SMTP-соединение с сервером получателя. Это может быть временной сетевой проблемой."),
    (re.compile(r"greylist|try again later", re.I), "Доставка временно отложена", "Сервер получателя просит повторить попытку позже. Почтовая система обычно сделает это автоматически."),
]


def _first(pattern: str, text: str, flags=re.I | re.M) -> str | None:
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def _parse_recipient_blocks(text: str) -> list[dict]:
    starts = list(re.finditer(r"^Final-Recipient:\s*[^;]+;\s*(.+)$", text, re.I | re.M))
    if not starts:
        return []
    out = []
    for i, m in enumerate(starts):
        end = starts[i+1].start() if i+1 < len(starts) else len(text)
        block = text[m.start():end]
        out.append({
            "recipient": m.group(1).strip(),
            "action": (_first(r"^Action:\s*([^\s]+)", block) or "").lower() or None,
            "status": _first(r"^Status:\s*([245]\.\d{1,3}\.\d{1,3})", block),
            "diagnostic": _first(r"^Diagnostic-Code:\s*(.+)$", block),
        })
    return out


def _plain_recipient(text: str) -> str | None:
    """Extract a recipient from common human-readable Postfix/Exim bounce text."""
    recipient = _first(
        r"following address\(es\) failed:\s*\n\s*([^\r\n]+@[^\r\n]+)",
        text,
    )
    if not recipient:
        recipient = _first(
            r'^\s*(<?[^\r\n]+@[^\r\n]+>?)\s*:\s*(?:host\s|message size\s|conversation with\s)',
            text,
        )
    if not recipient:
        recipient = _first(
            r'^\s*(<?(?:"[^"]+"|[^\s<>:]+)@[^\s<>:]+>?)\s*$',
            text,
        )
    if not recipient:
        return None
    recipient = recipient.strip().strip("<>").strip()
    return recipient if "@" in recipient else None


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} Б"
    units = ((1024 ** 3, "ГБ"), (1024 ** 2, "МБ"), (1024, "КБ"))
    for divisor, unit in units:
        if value >= divisor:
            amount = value / divisor
            formatted = f"{amount:.2f}".rstrip("0").rstrip(".").replace(".", ",")
            bytes_text = f"{value:,}".replace(",", " ")
            return f"{formatted} {unit} ({bytes_text} байт)"
    return f"{value} Б"


def _size_details(text: str) -> dict:
    match = re.search(
        r"message size\s+(\d+)\s+exceeds\s+(?:the\s+)?size limit\s+(\d+)",
        text,
        re.I,
    )
    if not match:
        return {}
    actual, limit = (int(match.group(1)), int(match.group(2)))
    return {
        "message_size_bytes": actual,
        "message_size": _format_bytes(actual),
        "size_limit_bytes": limit,
        "size_limit": _format_bytes(limit),
        "size_excess_bytes": max(actual - limit, 0),
        "size_excess": _format_bytes(max(actual - limit, 0)),
    }


def _recipient_syntax_details(recipient: str | None) -> dict:
    if not recipient:
        return {}

    highlights: list[dict] = []
    notes: list[str] = []

    def add(start: int, end: int) -> None:
        if start < end and not any(h["start"] == start and h["end"] == end for h in highlights):
            highlights.append({"start": start, "end": end, "kind": "syntax"})

    lowered = recipient.lower()
    search_from = 0
    while True:
        position = lowered.find("mailto:", search_from)
        if position < 0:
            break
        add(position, position + len("mailto:"))
        search_from = position + len("mailto:")
    if "mailto:" in lowered:
        notes.append("Удалите префикс mailto:")

    if recipient.count("@") != 1:
        add(0, len(recipient))
        notes.append("Адрес должен содержать один символ @")
    else:
        local, domain = recipient.split("@", 1)
        if not local:
            add(0, max(1, len(recipient)))
            notes.append("Не указано имя почтового ящика")
        for index, char in enumerate(local):
            if char not in LOCAL_ALLOWED:
                add(index, index + 1)
        domain_offset = len(local) + 1
        if (
            not domain
            or "." not in domain
            or domain.startswith(".")
            or domain.endswith(".")
            or ".." in domain
        ):
            add(domain_offset, len(recipient))
        else:
            for index, char in enumerate(domain):
                if char not in DOMAIN_ALLOWED:
                    add(domain_offset + index, domain_offset + index + 1)

    if '"' in recipient:
        notes.append("Удалите лишние кавычки")
    if highlights and not notes:
        notes.append("Удалите недопустимые символы и проверьте написание адреса")
    if not highlights:
        return {}

    highlights.sort(key=lambda item: (item["start"], item["end"]))
    return {
        "recipient_check": "Проверьте адрес получателя",
        "recipient_check_note": ". ".join(notes) + ".",
        "recipient_highlights": highlights,
    }


def _explain(action: str | None, enhanced: str | None, smtp_code: str | None, diagnostic: str, full_text: str) -> dict:
    status = "unknown"
    symbol = "?"
    title = "Не удалось определить статус"
    explanation = "Проверьте исходный текст сообщения доставки."

    if action in ACTION_TITLES:
        status, symbol, title, explanation = ACTION_TITLES[action]

    combined = f"{diagnostic}\n{full_text}"
    for rx, kt, ke in KEYWORD_RULES:
        if rx.search(combined):
            title, explanation = kt, ke
            if status == "unknown":
                status, symbol = "warning", "!"
            break

    if enhanced:
        mapped = db.get_smtp_status(enhanced)
        if mapped:
            title = mapped["title"]
            explanation = mapped["explanation"]
        if enhanced.startswith("2"):
            status, symbol = "ok", "✓"
            if not mapped and title == "Не удалось определить статус":
                title, explanation = "Доставка выполнена", "Почтовая система сообщает об успешном результате."
        elif enhanced.startswith("4"):
            status, symbol = "warning", "!"
            if not mapped and title == "Не удалось определить статус":
                title, explanation = "Временная ошибка", "Почтовая система сообщает о временной проблеме и может повторить попытку позже."
        elif enhanced.startswith("5"):
            status, symbol = "error", "!"
            if not mapped and title == "Не удалось определить статус":
                title, explanation = "Письмо не доставлено", "Почтовая система сообщает о постоянной ошибке. Проверьте подробности сообщения."

    # Explicit DSN action is the authoritative delivery state; keep its state even if text refines the title.
    if action in ACTION_TITLES:
        status, symbol = ACTION_TITLES[action][0], ACTION_TITLES[action][1]
        if action == "delayed" and enhanced and not enhanced.startswith("4"):
            explanation = ACTION_TITLES[action][3]

    if action not in ACTION_TITLES and not enhanced and smtp_code:
        if smtp_code.startswith("2"):
            status, symbol = "ok", "✓"
            if title == "Не удалось определить статус":
                title, explanation = "Команда выполнена", "Почтовый сервер подтвердил успешное выполнение операции."
        elif smtp_code.startswith("4"):
            status, symbol = "warning", "!"
            if title == "Не удалось определить статус":
                title, explanation = "Временная ошибка", "Сервер сообщает о временной проблеме. Повторная попытка может пройти успешно."
        elif smtp_code.startswith("5"):
            status, symbol = "error", "!"
            if title == "Не удалось определить статус":
                title, explanation = "Постоянная ошибка доставки", "Без устранения причины повторная отправка, скорее всего, не поможет."

    return {
        "status": status,
        "symbol": symbol,
        "title": title,
        "explanation": explanation,
    }


def parse_delivery(text: str) -> dict:
    text = text.strip()
    if not text:
        return {"items": [], "message": "Вставьте код или сообщение почтовой системы."}

    blocks = _parse_recipient_blocks(text)
    items = []

    if blocks:
        for b in blocks:
            smtp = None
            enhanced = b["status"]
            diag = b["diagnostic"] or ""
            m = re.search(r"(?<![\d.])([245]\d{2})(?![\d.])", diag)
            if m:
                smtp = m.group(1)
            if not enhanced:
                m = re.search(r"\b([245]\.\d{1,3}\.\d{1,3})\b", diag)
                if m:
                    enhanced = m.group(1)
            info = _explain(b["action"], enhanced, smtp, diag, text)
            size_info = _size_details(diag or text)
            recipient_info = _recipient_syntax_details(b["recipient"])
            items.append({**b, "smtp_code": smtp, "enhanced_code": enhanced, **size_info, **recipient_info, **info})
    else:
        action = (_first(r"^Action:\s*([^\s]+)", text) or "").lower() or None
        if not action:
            if re.search(r"Delivery Status Notification\s*\(Success\)|successfully delivered", text, re.I):
                action = "delivered"
            elif re.search(r"Undelivered Mail Returned to Sender|delivery (?:has )?failed|failure notice|could not be delivered|cannot be delivered|permanent error", text, re.I):
                action = "failed"
            elif re.search(r"Delayed Mail|still being retried|THIS IS A WARNING ONLY|delivery temporarily suspended", text, re.I):
                action = "delayed"
        enhanced = _first(r"^Status:\s*([245]\.\d{1,3}\.\d{1,3})", text)
        smtp = None
        m = re.search(r"(?<![\d.])([245]\d{2})(?:[ -]+([245]\.\d{1,3}\.\d{1,3}))?(?![\d.])", text)
        if m:
            smtp = m.group(1)
            enhanced = enhanced or m.group(2)
        if not enhanced:
            m = re.search(r"\b([245]\.\d{1,3}\.\d{1,3})\b", text)
            enhanced = m.group(1) if m else None
        recipient = _first(r"(?:Final-Recipient:\s*[^;]+;|Original-Recipient:\s*[^;]+;)\s*(\S+)", text) or _plain_recipient(text)
        diagnostic = _first(r"^Diagnostic-Code:\s*(.+)$", text) or text[:500]
        info = _explain(action, enhanced, smtp, diagnostic, text)
        size_info = _size_details(text)
        recipient_info = _recipient_syntax_details(recipient)
        items.append({
            "recipient": recipient,
            "action": action,
            "status_code": enhanced,
            "diagnostic": diagnostic,
            "smtp_code": smtp,
            "enhanced_code": enhanced,
            **size_info,
            **recipient_info,
            **info,
        })

    return {"items": items, "message": None}
