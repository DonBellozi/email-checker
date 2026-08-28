import asyncio
import os
import tempfile

fd, path = tempfile.mkstemp(prefix="email-checker-", suffix=".db")
os.close(fd)
os.unlink(path)
os.environ["DB_PATH"] = path

from app import db
from app.delivery import parse_delivery
from app.validator import extract_candidates, validate_text


def main():
    db.init_db()

    text = "Иванов <ivanov@mail.ru>; Петров <petrov@maiл.ru>; smtp:test@yandex.ru"
    candidates, overflow = extract_candidates(text, 100)
    assert not overflow
    assert [x.email for x in candidates] == ["ivanov@mail.ru", "petrov@maiл.ru", "test@yandex.ru"]

    result = asyncio.run(validate_text("petrov@maiл.ru\nusеr@gmail.com\nвася@gmail.com"))
    assert result["results"][0]["result"] == "Проверьте домен"
    assert result["results"][1]["result"] == "Проверьте имя"
    assert result["results"][2]["result"] == "Проверьте имя"

    quoted_mailto = asyncio.run(validate_text('"mailto:stroyholding0414"@mail.ru'))
    assert quoted_mailto["count"] == 1
    quoted_row = quoted_mailto["results"][0]
    assert quoted_row["cleaned"] == '"mailto:stroyholding0414"@mail.ru'
    assert quoted_row["result"] == "Проверьте имя"
    marked = [
        quoted_row["cleaned"][part["start"]:part["end"]]
        for part in quoted_row["highlights"]
    ]
    assert "mailto:" in marked
    assert marked.count('"') == 2

    plain_mailto = asyncio.run(validate_text("mailto:user@mail.ru"))
    assert plain_mailto["count"] == 1
    assert plain_mailto["results"][0]["result"] == "Проверьте имя"
    assert any(
        plain_mailto["results"][0]["cleaned"][part["start"]:part["end"]] == "mailto:"
        for part in plain_mailto["results"][0]["highlights"]
    )

    embedded_at = asyncio.run(validate_text('"mailto:stroy@holding0414"@mail.ru'))
    assert embedded_at["count"] == 1
    embedded_row = embedded_at["results"][0]
    assert embedded_row["cleaned"] == '"mailto:stroy@holding0414"@mail.ru'
    assert embedded_row["result"] == "Проверьте имя"
    assert embedded_row["domain"] == "mail.ru"
    embedded_marks = [
        embedded_row["cleaned"][part["start"]:part["end"]]
        for part in embedded_row["highlights"]
    ]
    assert "mailto:" in embedded_marks
    assert "@" in embedded_marks

    dsn = parse_delivery("550 5.1.1 User unknown")
    assert dsn["items"][0]["title"] == "Получатель не найден"

    mailru = parse_delivery(
        "<yana-dnr87@mail.ru>: host mxs.mail.ru[94.100.180.31] said: "
        "550 Message was not accepted -- invalid mailbox. "
        "Local mailbox yana-dnr87@mail.ru is unavailable: user not found "
        "(in reply to end of DATA command)"
    )
    assert mailru["items"][0]["smtp_code"] == "550"
    assert mailru["items"][0]["status"] == "error"
    assert mailru["items"][0]["title"] == "Получатель не найден"

    delivery_cases = [
        (
            "This message was created automatically by mail delivery software.\n"
            "A message that you sent could not be delivered. This is a permanent error. "
            "The following address(es) failed:\n\nneftvodokanal@ufamts.ru\n"
            "mailbox is full: retry timeout exceeded",
            "neftvodokanal@ufamts.ru", "Почтовый ящик переполнен", "error",
        ),
        (
            "armavir@mo.krasnodar.ru: message size 27612894 exceeds size limit "
            "26214400 of server mail-fr.krasnodar.ru[46.226.227.7]",
            "armavir@mo.krasnodar.ru", "Сообщение слишком большое", "warning",
        ),
        (
            "Undelivered Mail Returned to Sender\n\n"
            "ryazan@ryazangov.ru: conversation with ryazangov.ru[185.71.67.179] "
            "timed out while receiving the initial server greeting",
            "ryazan@ryazangov.ru", "Сервер получателя не ответил", "error",
        ),
        (
            '<"mailto:stroyholding0414"@mail.ru>: host mxs.mail.ru[217.69.139.150] said: '
            "550 5.1.3 Bad destination mailbox address syntax: invalid mailbox. "
            'Local mailbox <"mailto is unavailable: Ill-formatted e-mail address',
            '"mailto:stroyholding0414"@mail.ru', "Некорректный адрес получателя", "error",
        ),
        (
            "into@xn--geenfin-rgg.xn--izoup-owe.com: host 10.0.10.176[10.0.10.176] "
            "said: 450 4.1.2 Recipient address rejected: Domain not found",
            "into@xn--geenfin-rgg.xn--izoup-owe.com", "Домен получателя не найден", "warning",
        ),
    ]
    for raw, recipient, title, status in delivery_cases:
        parsed = parse_delivery(raw)["items"][0]
        assert parsed["recipient"] == recipient
        assert parsed["title"] == title
        assert parsed["status"] == status

    delayed = parse_delivery("Action: delayed\nStatus: 4.4.1\nDiagnostic-Code: smtp; 451 4.4.1 try again later")
    assert delayed["items"][0]["title"] == "Доставка задерживается"

    print("smoke: OK")


if __name__ == "__main__":
    main()
