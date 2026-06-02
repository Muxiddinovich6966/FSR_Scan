
# import httpx
# import base64
# import asyncio
# import re
# import requests
# from bs4 import BeautifulSoup
# from urllib.parse import urlparse
# from playwright.async_api import async_playwright
#
# VT_API_KEY = "d75471e2cf0fe25d09b902d31c0bb8628dfd7a1518460bff4ee9f37151c83418"
# VT_BASE = "https://www.virustotal.com/api/v3"
#
# BLACKLIST_DOMAINS = [
#     "secure-login-update.com", "verify-account-now.net",
#     "free-iphone-giveaway.xyz", "paypal-support-center.info",
#     "instagram-verify-badge.top"
# ]
#
# SUSPICIOUS_TLDS = [".xyz", ".top", ".info", ".club", ".work", ".gq", ".cf", ".tk", ".ml", ".buzz"]
# SUSPICIOUS_KEYWORDS = [
#     "login", "secure", "account", "update", "verify", "free", "bonus",
#     "bank", "wallet", "crypto", "signin", "confirm", "paypal", "apple",
#     "netflix", "amazon", "phishing", "trojan", "ransomware"
# ]
#
#
# # ============================================================
# #  VIRUSTOTAL
# # ============================================================
# def encode_vt_url(url: str) -> str:
#     return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
#
#
# async def check_url_virustotal(url: str) -> dict | None:
#     headers = {"x-apikey": VT_API_KEY}
#     encoded = encode_vt_url(url)
#
#     async with httpx.AsyncClient(timeout=30) as client:
#         try:
#             r = await client.get(f"{VT_BASE}/urls/{encoded}", headers=headers)
#             if r.status_code == 200:
#                 data = r.json()
#                 stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
#                 results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
#                 if stats:
#                     return parse_vt_stats(stats, results)
#
#             r = await client.post(f"{VT_BASE}/urls", headers=headers, data={"url": url})
#             if r.status_code != 200:
#                 return None
#
#             analysis_id = r.json()["data"]["id"]
#
#             for _ in range(4):
#                 await asyncio.sleep(4)
#                 r = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
#                 if r.status_code == 200:
#                     data = r.json()
#                     attrs = data.get("data", {}).get("attributes", {})
#                     if attrs.get("status") == "completed":
#                         return parse_vt_stats(attrs.get("stats", {}), attrs.get("results", {}))
#
#         except Exception as e:
#             print(f"[VT Xatolik] {e}")
#
#     return None
#
#
# def parse_vt_stats(stats: dict, results: dict) -> dict:
#     malicious = stats.get("malicious", 0)
#     suspicious = stats.get("suspicious", 0)
#
#     threats = []
#     for engine, res in results.items():
#         if res.get("category") in ("malicious", "suspicious"):
#             threats.append(f"{engine}: {res.get('result', res.get('category'))}")
#
#     score = 100
#     score -= min(malicious * 10, 80)
#     score -= min(suspicious * 5, 30)
#     score = max(0, score)
#
#     return {
#         "safe": malicious == 0 and suspicious == 0,
#         "score": score,
#         "threats": threats[:5],
#         "vtStats": {
#             "malicious": malicious,
#             "suspicious": suspicious,
#             "harmless": stats.get("harmless", 0),
#             "undetected": stats.get("undetected", 0),
#             "source": "VirusTotal (70+ antivirus)"
#         }
#     }
#
#
# # ============================================================
# #  CONTENT ANALYSIS — sahifa mazmunini tahlil qilish
# # ============================================================
#
# # Xavfli elementlar — karta, parol, OTP so'rash
# CARD_PATTERNS = [
#     "card number", "karta raqami", "credit card", "debit card",
#     "cvv", "cvc", "expiry", "amal qilish muddati", "card details"
# ]
# PASSWORD_PATTERNS = [
#     "password", "parol", "login", "username", "foydalanuvchi nomi",
#     "pin code", "pin kod"
# ]
# OTP_PATTERNS = [
#     "otp", "one time", "tasdiqlash kodi", "verification code",
#     "sms code", "sms kod"
# ]
# DOWNLOAD_PATTERNS = [
#     "download", "yuklab olish", "install", "o'rnatish",
#     "setup.exe", "apk", "click here to download"
# ]
# FINANCIAL_PATTERNS = [
#     "bank account", "hisob raqam", "swift", "iban",
#     "pul o'tkazma", "transfer money", "send money"
# ]
# PERSONAL_PATTERNS = [
#     "passport", "ssn", "social security", "id number",
#     "pasport", "shaxsiy raqam", "inn", "jshshir"
# ]
#
#
# def classify_page_purpose(soup, html_text: str, url: str) -> dict:
#     """Sahifa nima vazifa bajarishini aniqlayd"""
#     text_lower = html_text.lower()
#     warnings = []
#     purpose_tags = []
#     danger_score = 0
#
#     inputs = soup.find_all("input")
#     input_types = [i.get("type", "").lower() for i in inputs]
#     input_names = " ".join([
#         i.get("name", "").lower() + " " + i.get("placeholder", "").lower()
#         for i in inputs
#     ])
#
#     # 1. PAROL — faqat input[type=password] bo'lsa
#     if "password" in input_types:
#         warnings.append("⚠️ Bu sahifa sizdan PAROL so'ramoqda")
#         purpose_tags.append("Parol so'rash")
#         danger_score += 20
#
#     # 2. KARTA — bir vaqtda CVV + karta raqami input bo'lsa
#     has_card_input = any(p in input_names for p in ["card", "karta", "cvv", "cvc"])
#     has_card_text = sum(1 for p in ["card number", "cvv", "expir", "karta raqami"] if p in text_lower)
#     if has_card_input and has_card_text >= 1:
#         warnings.append("🚨 Bu sahifa sizdan BANK KARTA ma'lumotlarini so'ramoqda!")
#         purpose_tags.append("Bank karta ma'lumoti so'rash")
#         danger_score += 60
#
#     # 3. OTP — input + "tasdiqlash kodi" matni birga bo'lsa
#     has_otp_input = any(p in input_names for p in ["otp", "code", "kod", "token"])
#     has_otp_text = any(p in text_lower for p in ["tasdiqlash kodi", "verification code", "one time password", "sms kod"])
#     if has_otp_input and has_otp_text:
#         warnings.append("⚠️ Bu sahifa SMS TASDIQLASH KODI so'ramoqda")
#         purpose_tags.append("OTP/SMS kod so'rash")
#         danger_score += 25
#
#     # 4. SHAXSIY MA'LUMOT — bir nechta belgi birga
#     personal_count = sum(1 for p in ["passport", "pasport", "jshshir", "ssn", "inn", "shaxsiy raqam"] if p in text_lower)
#     if personal_count >= 2:
#         warnings.append("⚠️ Bu sahifa SHAXSIY MA'LUMOTLARINGIZNI so'ramoqda")
#         purpose_tags.append("Shaxsiy ma'lumot so'rash")
#         danger_score += 35
#
#     # 5. FAYL YUKLASH — faqat .exe, .apk, .bat kengaytmali havolalar bo'lsa
#     dangerous_links = soup.find_all("a", href=re.compile(r"\.(exe|apk|bat|msi|scr|vbs)$", re.I))
#     auto_download = soup.find_all(attrs={"download": True})
#     if dangerous_links or (auto_download and any(
#         ext in str(l.get("href","")) for l in auto_download
#         for ext in [".exe", ".apk", ".bat"]
#     )):
#         warnings.append("⚠️ Bu sahifa qurilmangizga XAVFLI FAYL YUKLAMOQCHI!")
#         purpose_tags.append("Xavfli fayl yuklash")
#         danger_score += 50
#
#     # 6. REDIRECT — meta refresh bilan boshqa saytga
#     meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
#     if meta_refresh:
#         content = meta_refresh.get("content", "")
#         if "url=" in content.lower():
#             warnings.append("⚠️ Bu sahifa sizni BOSHQA SAYTGA yo'naltirmoqda")
#             purpose_tags.append("Avtomatik yo'naltirish")
#             danger_score += 30
#
#     # 7. BREND TAQLIDI — FAQAT DOMENGA qarab
#     BRANDS = {
#         "paypal": "paypal.com",
#         "payme": "payme.uz",
#         "uzcard": "uzcard.uz",
#         "humo": "humo.uz",
#     }
#     parsed = urlparse(url)
#     domain = parsed.hostname or ""
#
#     for brand_key, official_domain in BRANDS.items():
#         if brand_key in domain and official_domain not in domain:
#             warnings.append(f"🚨 Bu sahifa {brand_key.upper()} NI TAQLID QILMOQDA! Rasmiy sayt emas!")
#             purpose_tags.append(f"{brand_key.title()} taqlidi (Phishing)")
#             danger_score += 70
#
#     # 8. Sahifa maqsadi — xavfli belgi yo'q bo'lsa oddiy deydi
#     page_title = soup.title.string.strip() if soup.title and soup.title.string else ""
#
#     if not purpose_tags:
#         if soup.find_all("article") or len(soup.find_all("p")) > 3:
#             purpose_tags.append("Axborot/Maqola sahifasi")
#         elif soup.find("form"):
#             purpose_tags.append("Forma sahifasi")
#         elif soup.find_all(["video", "audio"]):
#             purpose_tags.append("Media sahifasi")
#         else:
#             purpose_tags.append("Oddiy veb-sahifa")
#
#     return {
#         "warnings": warnings,
#         "purpose": purpose_tags,
#         "danger_score": min(danger_score, 100),
#         "page_title": page_title
#     }
#
#
#
# async def analyze_url_content(url: str) -> dict:
#     """Sahifa mazmunini requests + Playwright bilan tahlil qilish"""
#
#     if not url.startswith("http"):
#         url = "http://" + url
#
#     html = None
#     method_used = None
#
#     # 1-urinish: requests (tez, oddiy saytlar uchun)
#     try:
#         headers = {
#             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
#         }
#         resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
#         if resp.status_code == 200 and len(resp.text) > 100:
#             html = resp.text
#             method_used = "requests"
#             print(f"[Content] requests bilan olindi ({len(html)} belgi)")
#     except Exception as e:
#         print(f"[Content] requests ishlamadi: {e}")
#
#     # 2-urinish: Playwright (JavaScript saytlar uchun)
#     if not html:
#         try:
#             async with async_playwright() as p:
#                 browser = await p.chromium.launch(headless=True)
#                 page = await browser.new_page()
#                 await page.goto(url, timeout=12000, wait_until="domcontentloaded")
#                 await asyncio.sleep(2)  # JS bajarilishini kutamiz
#                 html = await page.content()
#                 await browser.close()
#                 method_used = "playwright"
#                 print(f"[Content] Playwright bilan olindi ({len(html)} belgi)")
#         except Exception as e:
#             print(f"[Content] Playwright ishlamadi: {e}")
#
#     if not html:
#         return {"warnings": [], "purpose": ["Sahifaga ulanib bo'lmadi"], "danger_score": 0, "page_title": ""}
#
#     soup = BeautifulSoup(html, "html.parser")
#     result = classify_page_purpose(soup, html, url)
#     result["method"] = method_used
#     return result
#
#
# # ============================================================
# #  HEURISTIK — zaxira
# # ============================================================
# def analyze_url(url: str) -> dict:
#     score = 100
#     threats = []
#
#     try:
#         if not url.startswith("http"):
#             url = "http://" + url
#         parsed = urlparse(url)
#         domain = parsed.hostname or ""
#     except Exception:
#         return {"safe": False, "score": 0, "threats": ["Noto'g'ri URL formati"]}
#
#     if any(b in domain for b in BLACKLIST_DOMAINS):
#         return {"safe": False, "score": 0, "threats": ["Domen phishing ro'yxatida topildi"]}
#
#     if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
#         score -= 40;
#         threats.append("URL domen o'rniga IP ishlatmoqda")
#
#     tld = domain[domain.rfind("."):]
#     if tld in SUSPICIOUS_TLDS:
#         score -= 30;
#         threats.append(f"Shubhali TLD: {tld}")
#
#     found_kw = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
#     if found_kw:
#         score -= 20 * len(found_kw)
#         threats.append(f"Shubhali kalit so'zlar: {', '.join(found_kw)}")
#
#     if len(url) > 75: score -= 15; threats.append("URL juda uzun")
#     if url.count("-") > 2: score -= 15; threats.append("Ko'p defis belgisi")
#     if "@" in url: score -= 60; threats.append("@ belgisi aniqlandi (yo'naltirish hujumi)")
#     if len(domain.split(".")) > 3: score -= 20; threats.append("Ko'p subdomen")
#     if parsed.scheme == "http": score -= 15; threats.append("Xavfsiz bo'lmagan HTTP ulanish")
#
#     score = max(0, score)
#     return {"safe": score >= 70, "score": score, "threats": threats}
#
#
# def analyze_sms(text: str) -> dict:
#     score = 100
#     threats = []
#
#     urgent = ["urgent", "immediately", "verify now", "suspended", "blocked",
#               "shoshilinch", "darhol", "tasdiqlang", "bloklandi"]
#     found = [p for p in urgent if p in text.lower()]
#     if found:
#         score -= 20 * len(found)
#         threats.append(f"Shoshilinch til: {', '.join(found)}")
#
#     financial = ["bank", "card", "payment", "transfer", "karta", "to'lov"]
#     found_fin = [p for p in financial if p in text.lower()]
#     if found_fin:
#         score -= 15
#         threats.append(f"Moliyaviy so'rov: {', '.join(found_fin)}")
#
#     if re.search(r"\+?\d{8,}", text):
#         score -= 10
#         threats.append("Telefon raqami aniqlandi")
#
#     urls = re.findall(r"https?://[^\s]+", text)
#     if urls:
#         score -= 10
#         threats.append(f"SMS ichida URL: {urls[0]}")
#
#     score = max(0, score)
#     return {"safe": score > 60, "score": score, "threats": threats}
#
#
# def analyze_file(name: str, size: int, file_type: str) -> dict:
#     score = 100
#     threats = []
#
#     dangerous_ext = [".exe", ".bat", ".cmd", ".scr", ".vbs", ".apk", ".msi", ".ps1", ".sh"]
#     ext = name[name.rfind("."):].lower()
#
#     if ext in dangerous_ext:
#         return {"safe": False, "score": 0, "threats": [f"Xavfli fayl kengaytmasi: {ext}"]}
#
#     if name.count(".") > 1:
#         score -= 40
#         threats.append("Qo'sh kengaytma aniqlandi")
#
#     if size < 1024 and ext in [".js", ".jar"]:
#         score -= 30
#         threats.append("G'ayrioddiy kichik skript fayli")
#
#     risky_types = ["application/x-msdownload", "application/x-executable"]
#     if file_type in risky_types:
#         score -= 50
#         threats.append(f"Xavfli MIME turi: {file_type}")
#
#     score = max(0, score)
#     return {"safe": score > 60, "score": score, "threats": threats}


import httpx
import base64
import asyncio
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from playwright.async_api import async_playwright
try:
    from playwright_stealth import stealth_async
except ImportError:
    async def stealth_async(page):
        pass

VT_API_KEY = "d75471e2cf0fe25d09b902d31c0bb8628dfd7a1518460bff4ee9f37151c83418"
VT_BASE = "https://www.virustotal.com/api/v3"

BLACKLIST_DOMAINS = [
    "secure-login-update.com", "verify-account-now.net",
    "free-iphone-giveaway.xyz", "paypal-support-center.info",
    "instagram-verify-badge.top"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".info", ".club", ".work", ".gq", ".cf", ".tk", ".ml", ".buzz"]
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "free", "bonus",
    "bank", "wallet", "crypto", "signin", "confirm", "paypal", "apple",
    "netflix", "amazon", "phishing", "trojan", "ransomware"
]


# ============================================================
#  VIRUSTOTAL
# ============================================================
def encode_vt_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


async def check_url_virustotal(url: str) -> dict | None:
    headers = {"x-apikey": VT_API_KEY}
    encoded = encode_vt_url(url)

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(f"{VT_BASE}/urls/{encoded}", headers=headers)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
                results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                if stats:
                    return parse_vt_stats(stats, results)

            r = await client.post(f"{VT_BASE}/urls", headers=headers, data={"url": url})
            if r.status_code != 200:
                return None

            analysis_id = r.json()["data"]["id"]

            for _ in range(4):
                await asyncio.sleep(4)
                r = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    if attrs.get("status") == "completed":
                        return parse_vt_stats(attrs.get("stats", {}), attrs.get("results", {}))

        except Exception as e:
            print(f"[VT Xatolik] {e}")

    return None


def parse_vt_stats(stats: dict, results: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    threats = []
    for engine, res in results.items():
        if res.get("category") in ("malicious", "suspicious"):
            threats.append(f"{engine}: {res.get('result', res.get('category'))}")

    score = 100
    score -= min(malicious * 10, 80)
    score -= min(suspicious * 5, 30)
    score = max(0, score)

    return {
        "safe": malicious == 0 and suspicious == 0,
        "score": score,
        "threats": threats[:5],
        "vtStats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "source": "VirusTotal (70+ antivirus)"
        }
    }


# ============================================================
#  LINK PREVIEW — Open Graph orqali tavsif olish
# ============================================================
async def get_link_preview(url: str) -> dict:
    """Har qanday sayt/video uchun qisqacha tavsif olish"""
    preview = {
        "title": "",
        "description": "",
        "image": "",
        "site_name": "",
        "content_type": "website"
    }

    # 1-urinish: requests bilan (tez)
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            preview = extract_og_tags(soup, url)
            if preview["title"]:
                print(f"[Preview] requests bilan olindi: {preview['title']}")
                return preview
    except Exception as e:
        print(f"[Preview] requests ishlamadi: {e}")

    # 2-urinish: Playwright stealth bilan (kuchli)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720}
            )
            page = await context.new_page()
            await stealth_async(page)
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            await asyncio.sleep(2)
            html = await page.content()
            await browser.close()

            soup = BeautifulSoup(html, "html.parser")
            preview = extract_og_tags(soup, url)
            print(f"[Preview] Playwright bilan olindi: {preview['title']}")
    except Exception as e:
        print(f"[Preview] Playwright ishlamadi: {e}")

    return preview


def extract_og_tags(soup, url: str) -> dict:
    """Open Graph va meta teglardan ma'lumot olish"""

    def og(prop):
        tag = soup.find("meta", property=f"og:{prop}") or soup.find("meta", attrs={"name": prop})
        return tag.get("content", "").strip() if tag else ""

    def tw(name):
        tag = soup.find("meta", attrs={"name": f"twitter:{name}"})
        return tag.get("content", "").strip() if tag else ""

    title = og("title") or tw("title") or (soup.title.string.strip() if soup.title and soup.title.string else "")
    description = og("description") or tw("description")
    image = og("image") or tw("image")
    site_name = og("site_name") or ""
    content_type = og("type") or "website"

    # Sayt turini aniqlaymiz
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    if "youtube.com" in domain or "youtu.be" in domain:
        site_name = "YouTube"
        content_type = "video"
    elif "instagram.com" in domain:
        site_name = "Instagram"
        content_type = "social"
    elif "facebook.com" in domain:
        site_name = "Facebook"
        content_type = "social"
    elif "twitter.com" in domain or "x.com" in domain:
        site_name = "Twitter/X"
        content_type = "social"
    elif "tiktok.com" in domain:
        site_name = "TikTok"
        content_type = "video"
    elif "t.me" in domain or "telegram.me" in domain:
        site_name = "Telegram"
        content_type = "messenger"

    return {
        "title": title[:200] if title else "",
        "description": description[:500] if description else "",
        "image": image,
        "site_name": site_name,
        "content_type": content_type,
        "domain": domain
    }


# ============================================================
#  CONTENT ANALYSIS — sahifa ichini tahlil qilish
# ============================================================
def classify_page_purpose(soup, html_text: str, url: str) -> dict:
    text_lower = html_text.lower()
    warnings = []
    purpose_tags = []
    danger_score = 0

    inputs = soup.find_all("input")
    input_types = [i.get("type", "").lower() for i in inputs]
    input_names = " ".join([
        i.get("name", "").lower() + " " + i.get("placeholder", "").lower()
        for i in inputs
    ])

    # Parol — faqat input[type=password] bo'lsa
    if "password" in input_types:
        warnings.append("⚠️ Bu sahifa sizdan PAROL so'ramoqda")
        purpose_tags.append("Parol so'rash")
        danger_score += 20

    # Karta — CVV + karta raqami input birga bo'lsa
    has_card_input = any(p in input_names for p in ["card", "karta", "cvv", "cvc"])
    has_card_text = sum(1 for p in ["card number", "cvv", "expir", "karta raqami"] if p in text_lower)
    if has_card_input and has_card_text >= 1:
        warnings.append("🚨 Bu sahifa sizdan BANK KARTA ma'lumotlarini so'ramoqda!")
        purpose_tags.append("Bank karta ma'lumoti so'rash")
        danger_score += 60

    # OTP
    has_otp_input = any(p in input_names for p in ["otp", "code", "kod", "token"])
    has_otp_text = any(
        p in text_lower for p in ["tasdiqlash kodi", "verification code", "one time password", "sms kod"])
    if has_otp_input and has_otp_text:
        warnings.append("⚠️ Bu sahifa SMS TASDIQLASH KODI so'ramoqda")
        purpose_tags.append("OTP/SMS kod so'rash")
        danger_score += 25

    # Shaxsiy ma'lumot
    personal_count = sum(
        1 for p in ["passport", "pasport", "jshshir", "ssn", "inn", "shaxsiy raqam"] if p in text_lower)
    if personal_count >= 3:
        warnings.append("⚠️ Bu sahifa SHAXSIY MA'LUMOTLARINGIZNI so'ramoqda")
        purpose_tags.append("Shaxsiy ma'lumot so'rash")
        danger_score += 35

    # Xavfli fayl yuklash
    dangerous_links = soup.find_all("a", href=re.compile(r"\.(exe|apk|bat|msi|scr|vbs)$", re.I))
    if dangerous_links:
        warnings.append("⚠️ Bu sahifa qurilmangizga XAVFLI FAYL YUKLAMOQCHI!")
        purpose_tags.append("Xavfli fayl yuklash")
        danger_score += 50

    # Redirect
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if meta_refresh and "url=" in (meta_refresh.get("content", "")).lower():
        warnings.append("⚠️ Bu sahifa sizni BOSHQA SAYTGA yo'naltirmoqda")
        purpose_tags.append("Avtomatik yo'naltirish")
        danger_score += 30

    # Brend taqlidi — FAQAT DOMENGA qarab
    BRANDS = {
        "paypal": "paypal.com",
        "payme": "payme.uz",
        "uzcard": "uzcard.uz",
        "humo": "humo.uz",
    }
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    for brand_key, official_domain in BRANDS.items():
        if brand_key in domain and official_domain not in domain:
            warnings.append(f"🚨 Bu sahifa {brand_key.upper()} NI TAQLID QILMOQDA! Rasmiy sayt emas!")
            purpose_tags.append(f"{brand_key.title()} taqlidi (Phishing)")
            danger_score += 70

    page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

    if not purpose_tags:
        if soup.find_all("article") or len(soup.find_all("p")) > 3:
            purpose_tags.append("Axborot/Maqola sahifasi")
        elif soup.find("form"):
            purpose_tags.append("Forma sahifasi")
        elif soup.find_all(["video", "audio"]):
            purpose_tags.append("Media sahifasi")
        else:
            purpose_tags.append("Oddiy veb-sahifa")

    return {
        "warnings": warnings,
        "purpose": purpose_tags,
        "danger_score": min(danger_score, 100),
        "page_title": page_title
    }


async def analyze_url_content(url: str) -> dict:
    """Sahifa mazmunini tahlil qilish"""
    if not url.startswith("http"):
        url = "http://" + url

    html = None
    method_used = None

    # 1-urinish: requests
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 100:
            html = resp.text
            method_used = "requests"
            print(f"[Content] requests bilan olindi ({len(html)} belgi)")
    except Exception as e:
        print(f"[Content] requests ishlamadi: {e}")

    # 2-urinish: Playwright stealth
    if not html:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1280, "height": 720}
                )
                page = await context.new_page()
                await stealth_async(page)
                await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                await asyncio.sleep(3)
                html = await page.content()
                await browser.close()
                method_used = "playwright"
                print(f"[Content] Playwright bilan olindi ({len(html)} belgi)")
        except Exception as e:
            print(f"[Content] Playwright ishlamadi: {e}")

    if not html:
        return {"warnings": [], "purpose": ["Sahifaga ulanib bo'lmadi"], "danger_score": 0, "page_title": "",
                "method": None}

    soup = BeautifulSoup(html, "html.parser")
    result = classify_page_purpose(soup, html, url)
    result["method"] = method_used
    return result


# ============================================================
#  HEURISTIK
# ============================================================
def analyze_url(url: str) -> dict:
    score = 100
    threats = []

    try:
        if not url.startswith("http"):
            url = "http://" + url

        # Qisqa linkni kengaytiramiz (redirect ni kuzatamiz)
        try:
            import requests as req_lib
            resp = req_lib.head(url, allow_redirects=True, timeout=5)
            if resp.url != url:
                print(f"[Redirect] {url} → {resp.url}")
                url = resp.url
        except:
            pass

        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        return {"safe": False, "score": 0, "threats": ["Noto'g'ri URL formati"]}

    if any(b in domain for b in BLACKLIST_DOMAINS):
        return {"safe": False, "score": 0, "threats": ["Domen phishing ro'yxatida topildi"]}

    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        score -= 40
        threats.append("URL domen o'rniga IP ishlatmoqda")

    tld = domain[domain.rfind("."):]
    if tld in SUSPICIOUS_TLDS:
        score -= 30
        threats.append(f"Shubhali TLD: {tld}")

    found_kw = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if found_kw:
        score -= 20 * len(found_kw)
        threats.append(f"Shubhali kalit so'zlar: {', '.join(found_kw)}")

    if len(url) > 75: score -= 15; threats.append("URL juda uzun")
    if url.count("-") > 2: score -= 15; threats.append("Ko'p defis belgisi")
    if "@" in url: score -= 60; threats.append("@ belgisi aniqlandi")
    if len(domain.split(".")) > 3: score -= 20; threats.append("Ko'p subdomen")
    if parsed.scheme == "http": score -= 15; threats.append("Xavfsiz bo'lmagan HTTP")

    score = max(0, score)
    return {"safe": score >= 70, "score": score, "threats": threats}


async def analyze_sms(text: str) -> dict:
    score = 100
    threats = []
    url_results = []

    urgent = ["urgent", "immediately", "verify now", "suspended", "blocked",
               "shoshilinch", "darhol", "tasdiqlang", "bloklandi"]
    found = [p for p in urgent if p in text.lower()]
    if found:
        score -= 20 * len(found)
        threats.append(f"Shoshilinch til: {', '.join(found)}")

    financial = ["bank", "card", "payment", "transfer", "karta", "to'lov"]
    found_fin = [p for p in financial if p in text.lower()]
    if found_fin:
        score -= 15
        threats.append(f"Moliyaviy so'rov: {', '.join(found_fin)}")

    if re.search(r"\+?\d{8,}", text):
        score -= 10
        threats.append("Telefon raqami aniqlandi")

    # SMS ichidagi linkni topib tekshiramiz
    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        score -= 10
        threats.append(f"SMS ichida URL topildi: {urls[0]}")

        # Linkni VirusTotal + Content Analysis bilan tekshiramiz
        vt_result, content_result, preview = await asyncio.gather(
            check_url_virustotal(urls[0]),
            analyze_url_content(urls[0]),
            get_link_preview(urls[0])
        )

        if vt_result and not vt_result["safe"]:
            score -= 40
            threats.append(f"SMS dagi link XAVFLI! VirusTotal: {vt_result['vtStats']['malicious']} antivirus xavfli deb belgiladi")
            threats += vt_result.get("threats", [])[:3]

        if content_result and content_result.get("danger_score", 0) > 30:
            score -= content_result["danger_score"] // 3
            threats += content_result.get("warnings", [])

        if preview and preview.get("title"):
            url_results.append({
                "url": urls[0],
                "preview": preview,
                "vt": vt_result,
                "content": content_result
            })

    score = max(0, score)
    return {
        "safe": score > 60,
        "score": score,
        "threats": threats,
        "urlResults": url_results
    }


def analyze_file(name: str, size: int, file_type: str) -> dict:
    score = 100
    threats = []
    description = ""

    dangerous_ext = [".exe", ".bat", ".cmd", ".scr", ".vbs", ".apk", ".msi", ".ps1", ".sh"]
    safe_ext = {
        ".pdf": "PDF hujjat",
        ".doc": "Word hujjat", ".docx": "Word hujjat",
        ".xls": "Excel jadval", ".xlsx": "Excel jadval",
        ".jpg": "Rasm fayl", ".jpeg": "Rasm fayl",
        ".png": "Rasm fayl", ".gif": "Rasm fayl",
        ".mp4": "Video fayl", ".avi": "Video fayl", ".mov": "Video fayl",
        ".mp3": "Audio fayl", ".wav": "Audio fayl",
        ".zip": "Arxiv fayl", ".rar": "Arxiv fayl",
        ".txt": "Matn fayl",
    }

    ext = name[name.rfind("."):].lower() if "." in name else ""

    # Fayl turi tavsifi
    if ext in safe_ext:
        description = safe_ext[ext]
    elif ext in dangerous_ext:
        description = "Bajariladigan dastur fayli"
    else:
        description = "Noma'lum fayl turi"

    # Xavf tekshiruvi
    if ext in dangerous_ext:
        return {
            "safe": False,
            "score": 0,
            "threats": [f"Xavfli fayl kengaytmasi: {ext}"],
            "fileInfo": {
                "extension": ext,
                "description": description,
                "size_kb": round(size / 1024, 1) if size else 0,
                "warning": "Bu fayl qurilmangizga zarar yetkazishi mumkin!"
            }
        }

    if name.count(".") > 1:
        score -= 40
        threats.append("Qo'sh kengaytma — niqoblash urinishi")

    if size < 1024 and ext in [".js", ".jar"]:
        score -= 30
        threats.append("G'ayrioddiy kichik skript fayli")

    risky_types = ["application/x-msdownload", "application/x-executable"]
    if file_type in risky_types:
        score -= 50
        threats.append(f"Xavfli MIME turi: {file_type}")

    # Arxiv fayllari haqida ogohlantirish
    if ext in [".zip", ".rar"]:
        threats.append("Arxiv ichida yashirin xavfli fayl bo'lishi mumkin")
        score -= 10

    score = max(0, score)
    return {
        "safe": score > 60,
        "score": score,
        "threats": threats,
        "fileInfo": {
            "extension": ext,
            "description": description,
            "size_kb": round(size / 1024, 1) if size else 0,
            "warning": "" if score > 60 else "Bu faylni ochishdan oldin ehtiyot bo'ling!"
        }
    }
