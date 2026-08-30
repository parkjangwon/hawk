import smtplib
import urllib.request


def send():
    # ruleid: korea.py.plaintext-transport
    requests.get("http://example.com/api")
    # ruleid: korea.py.plaintext-transport
    urllib.request.urlopen("http://internal/service")
    # ruleid: korea.py.plaintext-transport
    smtplib.SMTP("smtp.example.com")
    # ok: korea.py.plaintext-transport
    requests.get("https://example.com/api")
    # ok: korea.py.plaintext-transport
    smtplib.SMTP_SSL("smtp.example.com")
