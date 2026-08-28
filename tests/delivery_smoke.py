import os
import tempfile


fd, path = tempfile.mkstemp(prefix="email-checker-delivery-", suffix=".db")
os.close(fd)
os.unlink(path)
os.environ["DB_PATH"] = path

from app import db
from app.delivery import parse_delivery


def check(raw, recipient, title, status):
    item = parse_delivery(raw)["items"][0]
    assert item["recipient"] == recipient, item
    assert item["title"] == title, item
    assert item["status"] == status, item
    return item


def main():
    db.init_db()
    check(
        "This message was created automatically by mail delivery software.\n"
        "A message that you sent could not be delivered to one or more of its recipients. "
        "This is a permanent error. The following address(es) failed:\n\n"
        "neftvodokanal@ufamts.ru\nmailbox is full: retry timeout exceeded",
        "neftvodokanal@ufamts.ru", "Почтовый ящик переполнен", "error",
    )
    armavir = check(
        "Undelivered Mail Returned to Sender\n"
        "armavir@mo.krasnodar.ru: message size 27612894 exceeds size limit "
        "26214400 of server mail-fr.krasnodar.ru[46.226.227.7]",
        "armavir@mo.krasnodar.ru", "Сообщение слишком большое", "error",
    )
    assert armavir["message_size_bytes"] == 27612894
    assert armavir["size_limit_bytes"] == 26214400
    assert armavir["size_excess_bytes"] == 1398494
    assert armavir["size_limit"].startswith("25 МБ")

    proshkola = check(
        "Undelivered Mail Returned to Sender\n"
        "info@proshkola.ru: message size 110309852 exceeds size limit 73400320 "
        "of server emx.mail.ru[217.69.139.180]",
        "info@proshkola.ru", "Сообщение слишком большое", "error",
    )
    assert proshkola["message_size_bytes"] == 110309852
    assert proshkola["size_limit_bytes"] == 73400320
    assert proshkola["size_limit"].startswith("70 МБ")
    check(
        'This is a permanent error. The following address(es) failed:\n\n":vodokanal"@ryazan.gov.ru\n'
        '550 Message was not accepted -- invalid mailbox. Local mailbox '
        '":vodokanal"@ryazan.gov.ru is unavailable: user not found',
        '":vodokanal"@ryazan.gov.ru', "Получатель не найден", "error",
    )
    check(
        "Undelivered Mail Returned to Sender\n"
        "ryazan@ryazangov.ru: conversation with ryazangov.ru[185.71.67.179] timed out "
        "while receiving the initial server greeting",
        "ryazan@ryazangov.ru", "Сервер получателя не ответил", "error",
    )
    malformed = check(
        '<"mailto:stroyholding0414"@mail.ru>: host mxs.mail.ru[217.69.139.150] said: '
        "550 5.1.3 Bad destination mailbox address syntax: invalid mailbox. Local "
        'mailbox <"mailto is unavailable: Ill-formatted e-mail address',
        '"mailto:stroyholding0414"@mail.ru', "Некорректный адрес получателя", "error",
    )
    assert malformed["recipient_check"] == "Проверьте адрес получателя"
    marked = [
        malformed["recipient"][part["start"]:part["end"]]
        for part in malformed["recipient_highlights"]
    ]
    assert "mailto:" in marked
    assert marked.count('"') == 2
    assert "Удалите префикс mailto:" in malformed["recipient_check_note"]
    check(
        "into@xn--geenfin-rgg.xn--izoup-owe.com: host 10.0.10.176[10.0.10.176] said: "
        "450 4.1.2 Recipient address rejected: Domain not found",
        "into@xn--geenfin-rgg.xn--izoup-owe.com", "Домен получателя не найден", "warning",
    )
    print("delivery smoke: OK")


if __name__ == "__main__":
    try:
        main()
    finally:
        if os.path.exists(path):
            os.unlink(path)
