import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Brevo SMTP
SMTP_HOST = "smtp-relay.brevo.com"
SMTP_PORT = 587
SMTP_LOGIN = os.getenv("BREVO_LOGIN", "ad5b79001@smtp-brevo.com")
SMTP_PASSWORD = os.getenv("BREVO_PASSWORD", "xsmtpsib-e05a1a40432e6f72ac31a2d6e59ad890adf2afb1761af1b42cb05ce7314e1060-MnCXbYes56ZqRQYq")
FROM_EMAIL = "ad5b79001@smtp-brevo.com"

# OTP saqlash (xotirada)
otp_store = {}

def generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(to_email: str) -> bool:
    otp = generate_otp()
    otp_store[to_email] = otp
    print(f"[EMAIL] OTP: {otp} → {to_email}")

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "FSR SafeScan — Tasdiqlash kodi"
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email

        html = f"""
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0f172a;color:#f1f5f9;padding:32px;border-radius:16px">
            <div style="text-align:center;margin-bottom:24px">
                <div style="font-size:48px">🛡️</div>
                <h2 style="color:#38bdf8;letter-spacing:2px;text-transform:uppercase">FSR SafeScan</h2>
            </div>
            <p style="color:#94a3b8;margin-bottom:16px">Ro'yxatdan o'tish uchun tasdiqlash kodingiz:</p>
            <div style="background:#1e293b;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;border:1px solid rgba(255,255,255,0.1)">
                <div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#38bdf8">{otp}</div>
            </div>
            <p style="color:#64748b;font-size:13px">Bu kod 10 daqiqa amal qiladi. Agar siz ro'yxatdan o'tmagan bo'lsangiz, bu xabarni e'tiborsiz qoldiring.</p>
        </div>
        """

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_LOGIN, SMTP_PASSWORD)
            server.sendmail(FROM_EMAIL, to_email, msg.as_string())

        print(f"[EMAIL] Yuborildi: {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL] Xatolik: {e}")
        return False

def verify_otp(email: str, otp: str) -> bool:
    stored = otp_store.get(email)
    if stored and stored == otp:
        del otp_store[email]
        return True
    return False