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

    delayed = parse_delivery("Action: delayed\nStatus: 4.4.1\nDiagnostic-Code: smtp; 451 4.4.1 try again later")
    assert delayed["items"][0]["title"] == "Доставка задерживается"

    print("smoke: OK")


if __name__ == "__main__":
    main()
