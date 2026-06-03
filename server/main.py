# from typing import List,Optional
# import asyncio
# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.staticfiles import StaticFiles
# from fastapi.responses import FileResponse
# from pydantic import BaseModel
# from datetime import datetime
# from scanner import check_url_virustotal, analyze_url, analyze_url_content, get_link_preview, analyze_sms, analyze_file
# import json
# import os
# app = FastAPI(title="FSR SafeScan API")
#
# # Setup CORS
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
#
# # Request Models
# class UrlScanRequest(BaseModel):
#     url: str
#
# class SmsScanRequest(BaseModel):
#     text: str
#
# class FileScanRequest(BaseModel):
#     fileName: str
#     fileSize: int
#     fileType: str
#
# # Response Models
# class ScanResult(BaseModel):
#     safe: bool
#     score: int
#     threats: List[str]
#     actionDescription: Optional[str] = None
#
# class ScanResponse(BaseModel):
#     type: str
#     data: str
#     timestamp: str
#     result: ScanResult
#
# # --- MOCK DATABASE (Threat Intelligence) ---
# BLACKLIST_DOMAINS = [
#     'secure-login-update.com',
#     'verify-account-now.net',
#     'free-iphone-giveaway.xyz',
#     'paypal-support-center.info',
#     'instagram-verify-badge.top'
# ]
#
# SUSPICIOUS_TLDS = ['.xyz', '.top', '.info', '.club', '.work', '.gq', '.cf', '.tk', '.ml', '.ga', '.buzz', '.cn', '.ru']
#
# SUSPICIOUS_KEYWORDS = [
#     'login', 'secure', 'account', 'update', 'verify', 'free', 'bonus', 'gift', 'bank', 'wallet', 'crypto',
#     'signin', 'confirm', 'banking', 'paypal', 'apple', 'netflix', 'amazon', 'support', 'service', 'auth',
#     'malware', 'virus', 'infected', 'phishing', 'spyware', 'trojan', 'ransomware'
# ]
#
# FREE_HOSTING_DOMAINS = [
#     'appspot.com', 'herokuapp.com', 'netlify.app', 'vercel.app', 'github.io', 'gitlab.io',
#     '000webhostapp.com', 'ngrok.io', 'serveo.net'
# ]
#
# # --- HEURISTIC ENGINE ---
# def analyze_url(input_url: str) -> ScanResult:
#     score = 100
#     threats = []
#     action_desc = ""
#
#     if not input_url.startswith('http'):
#         input_url = 'http://' + input_url
#
#     try:
#         parsed_url = urllib.parse.urlparse(input_url)
#         domain = parsed_url.hostname or ""
#     except Exception:
#         return ScanResult(safe=False, score=0, threats=['Invalid URL format'])
#
#     # 1. Database Check
#     if any(bad_domain in domain for bad_domain in BLACKLIST_DOMAINS):
#         action_desc = "Bu xavfli domen (sayt) qora ro'yxatga kiritilgan! U sizning ma'lumotlaringizni o'g'irlash yoki virus tarqatish maqsadida yaratilganligi isbotlangan."
#         return ScanResult(safe=False, score=0, threats=['Domain found in global phishing blacklist'], actionDescription=action_desc)
#
#     # 2. IP Address Check
#     ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
#     if ip_pattern.match(domain):
#         score -= 40
#         threats.append('URL uses IP address instead of domain name')
#
#     # 3. Suspicious TLD Check
#     if '.' in domain:
#         tld = domain[domain.rfind('.'):]
#         if tld in SUSPICIOUS_TLDS:
#             score -= 30
#             threats.append(f'Suspicious Top-Level Domain detected ({tld})')
#
#     # 4. Keyword Analysis
#     lower_url = input_url.lower()
#     found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
#     if found_keywords:
#         score -= 20 * len(found_keywords)
#         threats.append(f'Suspicious keywords found: {", ".join(found_keywords)}')
#         if any(k in lower_url for k in ['bank', 'paypal', 'crypto', 'wallet', 'banking', 'payment']):
#             action_desc = "Bu havola sizning bank karta raqamlaringiz, elektron hamyoningiz yoki moliya ma'lumotlaringizni o'g'irlashga qaratilgan Phishing (Fiting) hujumi bo'lishi ehtimoli yuqori."
#         elif any(k in lower_url for k in ['login', 'signin', 'account', 'verify', 'instagram', 'apple', 'netflix']):
#             action_desc = "Bu havola ijtimoiy tarmoqlar yoki shaxsiy akkauntingiz parollarini o'g'irlash uchun mo'ljallangan qalbaki sayt bo'lishi mumkin."
#         elif any(k in lower_url for k in ['free', 'bonus', 'gift']):
#             action_desc = "Bu havola sizni yolg'on yutuqlar bilan aldamoqchi bo'lgan firibgarlik (Scam) sayti bo'lishi mumkin."
#         elif any(k in lower_url for k in ['malware', 'virus', 'infected']):
#             action_desc = "Bu havola telefoningizga virus (Malware) tushirish yoki shaxsiy fayllaringizni buzish uchun mo'ljallangan."
#
#     # 4.1 Free Hosting Check
#     if any(domain.endswith(d) for d in FREE_HOSTING_DOMAINS):
#         score -= 15
#         threats.append(f'Hosted on free/cloud platform ({domain}) - potential for abuse')
#         if found_keywords:
#             score -= 30
#             threats.append('Suspicious combination: Free hosting + Sensitive keywords')
#
#     # 5. URL Length & Complexity
#     if len(input_url) > 75:
#         score -= 15
#         threats.append('URL is suspiciously long')
#
#     if input_url.count('-') > 2:
#         score -= 15
#         threats.append('Excessive use of hyphens in URL')
#
#     if input_url.count('@') > 0:
#         score -= 60
#         threats.append('URL contains "@" symbol (potential redirect attack)')
#
#     # 6. Subdomain Depth
#     subdomains = domain.split('.')
#     if len(subdomains) > 3:
#         score -= 20
#         threats.append('Multiple subdomains detected (potential masking)')
#
#     # 7. Protocol Check
#     if parsed_url.scheme == 'http':
#         score -= 15
#         threats.append('Unsecure connection (HTTP instead of HTTPS)')
#
#     if not action_desc and score < 70:
#         action_desc = "Bu havola shubhali tuzilishga ega bo'lib, xavfsiz emas deb topildi. Unga ishonchli shaxsiy ma'lumotlaringizni kiritmang!"
#
#     score = max(0, score)
#     return ScanResult(safe=(score >= 70), score=score, threats=threats, actionDescription=action_desc if not (score >= 70) else None)
#
#
# def analyze_text(text: str) -> ScanResult:
#     score = 100
#     threats = []
#     action_desc = ""
#     lower_text = text.lower()
#
#     # Urgent language check
#     urgent_patterns = ['urgent', 'immediately', 'verify now', 'action required', 'suspended', 'blocked']
#     found_urgent = [p for p in urgent_patterns if p in lower_text]
#     if found_urgent:
#         score -= 20 * len(found_urgent)
#         threats.append(f'Urgent/Panic language detected: {", ".join(found_urgent)}')
#
#     # Financial keywords
#     financial_patterns = ['bank', 'card', 'payment', 'transfer', 'wired']
#     found_financial = [p for p in financial_patterns if p in lower_text]
#     if found_financial:
#         score -= 15
#         threats.append(f'Financial request detected: {", ".join(found_financial)}')
#
#     # Phone numbers
#     if re.search(r'\+?\d{8,}', text):
#         score -= 10
#         threats.append('Contains phone number (potential vishing)')
#
#     if found_urgent and found_financial:
#         action_desc = "Bu xabar qo'rquv va shoshqaloqlikdan foydalanib, pulingizni undirishni maqsad qilgan ijtimoiy muhandislik (Social Engineering) hujumidir."
#     elif found_financial:
#         action_desc = "Bu xabar sizning bank yoki to'lov tizimlaridagi ma'lumotlaringizni aldov yo'li bilan olishga qaratilgan bo'lishi mumkin."
#     elif found_urgent:
#         action_desc = "Bu xabar sizni sarosimaga tushirib, tezkor harakat qilishga majburlaydigan firibgarlik usuli (Scam)."
#     elif re.search(r'\+?\d{8,}', text):
#         action_desc = "Bu xabardagi raqamga qo'ng'iroq qilish orqali shaxsiy ma'lumotlaringiz yoki pulingiz o'g'irlanishi mumkin (Vishing)."
#
#     if not action_desc and score <= 60:
#         action_desc = "Ushbu SMS/matn firibgarlar tomonidan yuborilgan bo'lishi mumkin."
#
#     score = max(0, score)
#     return ScanResult(safe=(score > 60), score=score, threats=threats, actionDescription=action_desc if not (score > 60) else None)
#
#
# def analyze_file(file_name: str, file_size: int, file_type: str) -> ScanResult:
#     score = 100
#     threats = []
#     action_desc = ""
#
#     # Dangerous extensions
#     dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.apk']
#     ext = ""
#     if '.' in file_name:
#         ext = file_name[file_name.rfind('.'):].lower()
#
#     if ext in dangerous_extensions:
#         if ext in ['.exe', '.bat', '.cmd']:
#             action_desc = "Bu kompyuter uchun yozilgan xavfli dastur bo'lib, tizimni buzish yoki boshqaruvni qo'lga olish (Trojan/Virus) vazifasini bajarishi mumkin."
#         elif ext == '.apk':
#             action_desc = "Bu Android telefoningizdagi kontaktlar, SMSlar, parollar va bank dasturlari ustidan nazoratni o'g'irlovchi troyan virusi (Spyware) bo'lishi mumkin."
#         elif ext in ['.vbs', '.scr']:
#             action_desc = "Bu zararli skript bo'lib, kompyuteringizda yashirincha ishga tushib fayllaringizni shifrlab qo'yishi mumkin (Ransomware)."
#
#         return ScanResult(safe=False, score=0, threats=[f'High-risk file extension detected: {ext}'], actionDescription=action_desc)
#
#     # Double extension check
#     if len(file_name.split('.')) > 2:
#         score -= 40
#         threats.append('Double file extension detected (potential masquerading)')
#
#     # Suspiciously small script files
#     if file_size < 1024 and ext in ['.js', '.jar']:
#         score -= 30
#         threats.append('Suspiciously small script file')
#
#     if len(file_name.split('.')) > 2:
#          action_desc = "Bu fayl o'zini rasm yoki hujjat qilib ko'rsatib, aslida zararli virus bo'lishi mumkin (Masquerading)."
#
#     if not action_desc and score <= 60:
#          action_desc = "Ushbu fayl tarkibida shubhali kodlar yoki mantiq bo'lishi mumkin, uni ochish xavfli!"
#
#     score = max(0, score)
#     return ScanResult(safe=(score > 60), score=score, threats=threats, actionDescription=action_desc if not (score > 60) else None)
#
# # --- API ROUTES ---
# @app.post("/api/scan")
# async def scan_url(req: UrlScanRequest):
#     if not req.url:
#         raise HTTPException(status_code=400, detail="URL is required")
#
#     print(f"\n[URL SKAN] {req.url}")
#     source = "heuristic"
#
#     # Hammasini parallel ishlatamiz
#     vt_result, content_result, preview = await asyncio.gather(
#         check_url_virustotal(req.url),
#         analyze_url_content(req.url),
#         get_link_preview(req.url)
#     )
#
#     # Asosiy natija
#     if vt_result:
#         result = dict(vt_result)
#         source = "virustotal"
#     else:
#         result = dict(analyze_url(req.url))
#         source = "heuristic"
#
#     # Content analysis
#     content_warnings = []
#     content_purpose = []
#     content_danger = 0
#
#     if content_result:
#         content_warnings = content_result.get("warnings", [])
#         content_purpose = content_result.get("purpose", [])
#         content_danger = content_result.get("danger_score", 0)
#
#         if content_danger > 0:
#             result["score"] = max(0, result["score"] - content_danger // 2)
#         if content_danger >= 50:
#             result["safe"] = False
#
#         result["threats"] = list(result.get("threats", [])) + content_warnings
#
#     result["contentAnalysis"] = {
#         "purpose": content_purpose,
#         "warnings": content_warnings,
#         "pageTitle": content_result.get("page_title", "") if content_result else "",
#         "dangerScore": content_danger,
#         "method": content_result.get("method", "") if content_result else ""
#     }
#
#     # Preview ma'lumoti
#     result["preview"] = preview
#
#     print(f"[Result] {'SAFE' if result['safe'] else 'DANGER'} ({result['score']}%)")
#     print(f"[Preview] {preview.get('site_name','')} — {preview.get('title','')[:50]}")
#
#     return {
#         "type": "url",
#         "data": req.url,
#         "source": source,
#         "timestamp": datetime.utcnow().isoformat() + "Z",
#         "result": result
#     }
#
#
# @app.post("/api/scan/sms")
# async def scan_sms(req: SmsScanRequest):
#     if not req.text:
#         raise HTTPException(status_code=400, detail="Text content is required")
#
#     print("Scanning SMS Text...")
#     result = await analyze_sms(req.text)
#     print(f"Result: {'SAFE' if result['safe'] else 'DANGER'} ({result['score']}%)")
#
#     return {
#         "type": "sms",
#         "data": req.text,
#         "source": "heuristic",
#         "timestamp": datetime.utcnow().isoformat() + "Z",
#         "result": result
#     }
#
# @app.post("/api/scan/file")
# async def scan_file(req: FileScanRequest):
#     if not req.fileName:
#         raise HTTPException(status_code=400, detail="File information is required")
#
#     print(f"[FAYL SKAN] {req.fileName}")
#     result = dict(analyze_file(req.fileName, req.fileSize or 0, req.fileType or ""))
#     print(f"Result: {'SAFE' if result['safe'] else 'DANGER'} ({result['score']}%)")
#
#     return {
#         "type": "file",
#         "data": req.fileName,
#         "source": "heuristic",
#         "timestamp": datetime.utcnow().isoformat() + "Z",
#         "result": result
#     }
# CLIENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client")
# if os.path.exists(CLIENT_DIR):
#     app.mount("/app", StaticFiles(directory=CLIENT_DIR, html=True), name="client")
#
# @app.get("/")
# def root():
#     index_path = os.path.join(CLIENT_DIR, "index.html")
#     if os.path.exists(index_path):
#         return FileResponse(index_path)
#     return {"message": "FSR SafeScan API ishlayapti!", "docs": "/docs"}
#
#
# if __name__ == "__main__":
#     import uvicorn
#     print("="*50)
#     print("Saytni ochish uchun ustiga bosing: http://127.0.0.1:3000")
#     print("="*50)
#     uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)


from fastapi import FastAPI, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import asyncio
import json
import os
from email_service import send_otp_email, verify_otp

from database import init_db, get_db
from auth import register_user, login_user, verify_token
from scanner import (
    check_url_virustotal, analyze_url, analyze_url_content,
    get_link_preview, analyze_sms, analyze_file
)
def translate_threats(threats: list) -> list:
    translations = {
        "malicious": "zararli",
        "phishing": "fishing (aldov)",
        "suspicious": "shubhali",
        "spam": "spam",
        "malware": "zararli dastur",
        "trojan": "troyan virus",
        "ransomware": "to'lov virusi",
        "adware": "reklama virusi",
    }
    result = []
    for threat in threats:
        translated = threat
        for eng, uzb in translations.items():
            translated = translated.replace(eng, uzb)
        result.append(translated)
    return result
app = FastAPI(title="FSR SafeScan API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()
    print("FSR SafeScan API v3 ishga tushdi!")

# Static files
CLIENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),"client")
ADMIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),"admin")

if os.path.exists(CLIENT_DIR):
    app.mount("/app", StaticFiles(directory=CLIENT_DIR, html=True), name="client")
if os.path.exists(ADMIN_DIR):
    app.mount("/admin-panel", StaticFiles(directory=ADMIN_DIR, html=True), name="admin")

@app.get("/")
def root():
    index_path = os.path.join(CLIENT_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "FSR SafeScan API ishlayapti!", "docs": "/docs"}

# ============================================================
#  REQUEST MODELLARI
# ============================================================
class UrlRequest(BaseModel):
    url: str

class SmsRequest(BaseModel):
    text: str

class FileRequest(BaseModel):
    fileName: str
    fileSize: int = 0
    fileType: str = ""

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# ============================================================
#  TOKEN TEKSHIRISH
# ============================================================
def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.replace("Bearer ", "")
    return verify_token(token)

def require_auth(authorization: Optional[str] = Header(None)) -> dict:
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Avtorizatsiya talab qilinadi")
    return user

def require_admin(authorization: Optional[str] = Header(None)) -> dict:
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Avtorizatsiya talab qilinadi")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin huquqi talab qilinadi")
    return user

# ============================================================
#  YORDAMCHI — skanlarni saqlash
# ============================================================
def save_scan(scan_type: str, data: str, source: str, result: dict, user_id: int = None):
    try:
        conn = get_db()
        vt = result.get("vtStats", {}) or {}
        conn.execute('''
            INSERT INTO scans (user_id, type, data, source, is_safe, score, threats,
                vt_malicious, vt_suspicious, vt_harmless, vt_undetected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, scan_type, data[:500], source,
            1 if result.get("safe") else 0,
            result.get("score", 0),
            json.dumps(result.get("threats", []), ensure_ascii=False),
            vt.get("malicious", 0), vt.get("suspicious", 0),
            vt.get("harmless", 0), vt.get("undetected", 0)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Saqlashda xatolik: {e}")

# ============================================================
#  AUTH ENDPOINTLAR
# ============================================================
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.0.0", "timestamp": datetime.now().isoformat()}


# # Ro'yxat uchun yangi model
class RegisterRequestOTP(BaseModel):
    username: str
    email: str
    password: str
    otp: str = ""  # Bo'sh bo'lsa — OTP yuboriladi
class OtpRequest(BaseModel):
    email: str

@app.post("/api/auth/send-otp")
def send_otp(req: OtpRequest):
    success = send_otp_email(req.email)
    if not success:
        raise HTTPException(status_code=500, detail="Email yuborishda xatolik!")
    return {"message": "Tasdiqlash kodi emailingizga yuborildi!"}
class OtpRequest(BaseModel):
    email: str

@app.post("/api/auth/send-otp")
def send_otp(req: OtpRequest):
    success = send_otp_email(req.email)
    if not success:
        raise HTTPException(status_code=500, detail="Email yuborishda xatolik!")
    return {"message": "Tasdiqlash kodi emailingizga yuborildi!"}

@app.post("/api/auth/register")
def register(req: RegisterRequestOTP):
    """OTP tasdiqlash va ro'yxat"""
    if not req.otp:
        raise HTTPException(status_code=400, detail="Tasdiqlash kodi kiritilmagan")

    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Parol kamida 6 ta belgi bo'lishi kerak")

    # OTP tekshiruv
    if not verify_otp(req.email, req.otp):
        raise HTTPException(status_code=400, detail="Tasdiqlash kodi noto'g'ri yoki muddati o'tgan")

    result = register_user(req.username, req.email, req.password)
    if not result["success"]:
        raise HTTPException(status_code=400, detail="Bu foydalanuvchi nomi yoki email allaqachon mavjud")

    return {"message": "Muvaffaqiyatli ro'yxatdan o'tdingiz!"}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    result = login_user(req.username, req.password)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["error"])
    return result

@app.get("/api/auth/me")
def me(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Token noto'g'ri")
    return user

# ============================================================
#  SKAN ENDPOINTLAR
# ============================================================
@app.post("/api/scan")
async def scan_url(req: UrlRequest, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["user_id"] if user else None

    print(f"\n[URL SKAN] {req.url}")
    source = "heuristic"

    vt_result, content_result, preview = await asyncio.gather(
        check_url_virustotal(req.url),
        analyze_url_content(req.url),
        get_link_preview(req.url)
    )

    if vt_result:
        result = dict(vt_result)
        source = "virustotal"
    else:
        result = dict(analyze_url(req.url))

    # Content analysis
    content_warnings = []
    content_purpose = []
    content_danger = 0

    if content_result:
        content_warnings = content_result.get("warnings", [])
        content_purpose = content_result.get("purpose", [])
        content_danger = content_result.get("danger_score", 0)
        if content_danger > 0:
            result["score"] = max(0, result["score"] - content_danger // 2)
        if content_danger >= 50:
            result["safe"] = False
        result["threats"] = list(result.get("threats", [])) + content_warnings

    result["contentAnalysis"] = {
        "purpose": content_purpose,
        "warnings": content_warnings,
        "pageTitle": content_result.get("page_title", "") if content_result else "",
        "dangerScore": content_danger,
    }
    result["preview"] = preview
    result["threats"] = translate_threats(result.get("threats", []))

    save_scan("url", req.url, source, result, user_id)
    print(f"[Result] {'SAFE' if result['safe'] else 'DANGER'} ({result['score']}%)")


    return {
        "type": "url", "data": req.url, "source": source,
        "timestamp": datetime.now().isoformat(), "result": result
    }

@app.post("/api/scan/sms")
async def scan_sms(req: SmsRequest, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["user_id"] if user else None

    print("[SMS SKAN]")
    result = await analyze_sms(req.text)
    save_scan("sms", req.text, "heuristic", result, user_id)
    print(f"[Result] {'SAFE' if result['safe'] else 'DANGER'} ({result['score']}%)")
    result["threats"] = translate_threats(result.get("threats", []))

    return {
        "type": "sms", "data": req.text, "source": "heuristic",
        "timestamp": datetime.now().isoformat(), "result": result
    }

@app.post("/api/scan/file")
async def scan_file(req: FileRequest, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    user_id = user["user_id"] if user else None

    print(f"[FAYL SKAN] {req.fileName}")
    result = dict(analyze_file(req.fileName, req.fileSize, req.fileType))
    save_scan("file", req.fileName, "heuristic", result, user_id)
    print(f"[Result] {'SAFE' if result['safe'] else 'DANGER'} ({result['score']}%)")
    result["threats"] = translate_threats(result.get("threats", []))

    return {
        "type": "file", "data": req.fileName, "source": "heuristic",
        "timestamp": datetime.now().isoformat(), "result": result
    }

# ============================================================
#  TARIX ENDPOINTLAR
# ============================================================
@app.get("/api/history")
def get_history(authorization: Optional[str] = Header(None)):
    user = require_auth(authorization)
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
        (user["user_id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ============================================================
#  ADMIN ENDPOINTLAR
# ============================================================
@app.get("/api/admin/stats")
def admin_stats(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    conn = get_db()

    total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    safe = conn.execute("SELECT COUNT(*) as c FROM scans WHERE is_safe=1").fetchone()["c"]
    danger = conn.execute("SELECT COUNT(*) as c FROM scans WHERE is_safe=0").fetchone()["c"]
    total_users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]

    by_type = conn.execute('''
        SELECT type, COUNT(*) as count,
               SUM(CASE WHEN is_safe=0 THEN 1 ELSE 0 END) as dangerous
        FROM scans GROUP BY type
    ''').fetchall()

    recent = conn.execute(
        "SELECT s.*, u.username FROM scans s LEFT JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 20"
    ).fetchall()

    daily = conn.execute('''
        SELECT DATE(created_at) as day, COUNT(*) as count,
               SUM(CASE WHEN is_safe=0 THEN 1 ELSE 0 END) as dangerous
        FROM scans GROUP BY DATE(created_at)
        ORDER BY day DESC LIMIT 7
    ''').fetchall()

    users = conn.execute(
        "SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()

    conn.close()

    return {
        "total": total, "safe": safe, "danger": danger,
        "totalUsers": total_users,
        "byType": [dict(r) for r in by_type],
        "recentScans": [dict(r) for r in recent],
        "dailyStats": [dict(r) for r in daily],
        "users": [dict(r) for r in users]
    }

@app.delete("/api/admin/scans/{scan_id}")
def delete_scan(scan_id: int, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
    return {"message": "O'chirildi"}

@app.put("/api/admin/users/{user_id}/role")
def update_role(user_id: int, role: str, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    if role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Noto'g'ri rol")
    conn = get_db()
    conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    conn.commit()
    conn.close()
    return {"message": "Rol yangilandi"}


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": "Foydalanuvchi o'chirildi"}

