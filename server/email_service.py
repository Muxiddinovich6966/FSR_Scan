# import smtplib
# import random
# import string
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
#
# # GMAIL = "norpolatovfarruxbek0@gmail.com"
# # APP_PASSWORD = "aubh hpqb gdvp naiy"
# import os
# GMAIL = os.getenv("GMAIL", "norpolatovfarruxbek0@gmail.com")
# APP_PASSWORD = os.getenv("GMAIL_PASSWORD", "aubh hpqb gdvp naiy")
# # OTP saqlash (xotirada)
# otp_store = {}
#
# def generate_otp() -> str:
#     return ''.join(random.choices(string.digits, k=6))
#
# def send_otp_email(to_email: str) -> bool:
#     otp = generate_otp()
#     otp_store[to_email] = otp
#     print(f"[EMAIL] OTP: {otp} → {to_email}")
#
#     try:
#         msg = MIMEMultipart("alternative")
#         msg["Subject"] = "FSR SafeScan — Tasdiqlash kodi"
#         msg["From"] = GMAIL
#         msg["To"] = to_email
#
#         html = f"""
#         <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0f172a;color:#f1f5f9;padding:32px;border-radius:16px">
#             <div style="text-align:center;margin-bottom:24px">
#                 <div style="font-size:48px">🛡️</div>
#                 <h2 style="color:#38bdf8;letter-spacing:2px;text-transform:uppercase">FSR SafeScan</h2>
#             </div>
#             <p style="color:#94a3b8;margin-bottom:16px">Ro'yxatdan o'tish uchun tasdiqlash kodingiz:</p>
#             <div style="background:#1e293b;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;border:1px solid rgba(255,255,255,0.1)">
#                 <div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#38bdf8">{otp}</div>
#             </div>
#             <p style="color:#64748b;font-size:13px">Bu kod 10 daqiqa amal qiladi. Agar siz ro'yxatdan o'tmagan bo'lsangiz, bu xabarni e'tiborsiz qoldiring.</p>
#         </div>
#         """
#
#         msg.attach(MIMEText(html, "html"))
#
#         with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
#             server.login(GMAIL, APP_PASSWORD.replace(" ", ""))
#             server.sendmail(GMAIL, to_email, msg.as_string())
#
#         print(f"[EMAIL] Yuborildi: {to_email}")
#         return True
#     except Exception as e:
#         print(f"[EMAIL] Xatolik: {e}")
#         return False
#
# def verify_otp(email: str, otp: str) -> bool:
#     stored = otp_store.get(email)
#     if stored and stored == otp:
#         del otp_store[email]
#         return True
#     return False


import random
import string
import os
import httpx

# Brevo API
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "xsmtpsib-e05a1a40432e6f72ac31a2d6e59ad890adf2afb1761af1b42cb05ce7314e1060-GzpkSH0Jz2BFtgKg")
FROM_EMAIL = "norpolatovfarruxbek0@gmail.com"
FROM_NAME = "FSR SafeScan"

# OTP saqlash
otp_store = {}

def generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(to_email: str) -> bool:
    otp = generate_otp()
    otp_store[to_email] = otp
    print(f"[EMAIL] OTP: {otp} → {to_email}")

    try:
        response = httpx.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": BREVO_API_KEY,
                "Content-Type": "application/json"
            },
            json={
                "sender": {"name": FROM_NAME, "email": FROM_EMAIL},
                "to": [{"email": to_email}],
                "subject": "FSR SafeScan — Tasdiqlash kodi",
                "htmlContent": f"""
                <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0f172a;color:#f1f5f9;padding:32px;border-radius:16px">
                    <div style="text-align:center;margin-bottom:24px">
                        <div style="font-size:48px">🛡️</div>
                        <h2 style="color:#38bdf8;letter-spacing:2px">FSR SafeScan</h2>
                    </div>
                    <p style="color:#94a3b8;margin-bottom:16px">Ro'yxatdan o'tish uchun tasdiqlash kodingiz:</p>
                    <div style="background:#1e293b;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px">
                        <div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#38bdf8">{otp}</div>
                    </div>
                    <p style="color:#64748b;font-size:13px">Bu kod 10 daqiqa amal qiladi.</p>
                </div>
                """
            },
            timeout=10
        )
        if response.status_code == 201:
            print(f"[EMAIL] Yuborildi: {to_email}")
            return True
        else:
            print(f"[EMAIL] Xatolik: {response.status_code} {response.text}")
            return False
    except Exception as e:
        print(f"[EMAIL] Xatolik: {e}")
        return False

def verify_otp(email: str, otp: str) -> bool:
    stored = otp_store.get(email)
    if stored and stored == otp:
        del otp_store[email]
        return True
    return False