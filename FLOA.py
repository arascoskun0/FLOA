"""
Fully Legal OSINT API (FLOA)
Author: Aras
License: MIT

✔ Public OSINT only
✔ Cache + Provider based rate limit
✔ Owner key unlimited
"""

from fastapi import FastAPI, Request, HTTPException
import httpx, time, os, base64, hashlib

app = FastAPI(title="Fully Legal OSINT API (FLOA)")

# ==================================================
# 🔑 API KEY CONFIG
# ==================================================

# 👑 OWNER KEY (NO RATE LIMIT)
OWNER_KEYS = {
    "FLOA_OWNER_KEY"
}

# 🌍 PUBLIC GLOBAL LIMIT (minute)
PUBLIC_GLOBAL_LIMIT = 60

# Provider based limits (for public keys)
PROVIDER_LIMITS = {
    "ip": 100,
    "wigle": 30,
    "dork": 10,
    "leak": 20
}

# ==================================================
# 🌐 WIGLE CONFIG
# ==================================================
WIGLE_USER = os.getenv("WIGLE_USER")
WIGLE_TOKEN = os.getenv("WIGLE_TOKEN")

# ==================================================
# 🧠 CACHE (IN-MEMORY TTL)
# ==================================================
CACHE = {}

def cache_get(key):
    item = CACHE.get(key)
    if not item:
        return None
    if item["expire"] < time.time():
        del CACHE[key]
        return None
    return item["data"]

def cache_set(key, data, ttl):
    CACHE[key] = {
        "data": data,
        "expire": time.time() + ttl
    }

# ==================================================
#  RATE LIMIT STORAGE
# ==================================================

RATE = {}

def rate_check(api_key, provider, limit):
    now = int(time.time()) // 60
    k = f"{api_key}:{provider}:{now}"
    RATE[k] = RATE.get(k, 0) + 1
    if RATE[k] > limit:
        raise HTTPException(429, f"{provider} rate limit exceeded")

# ==================================================
# 🔐 API KEY MIDDLEWARE
# ==================================================
@app.middleware("http")
async def auth(request: Request, call_next):
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(401, "X-API-Key required")

    request.state.api_key = api_key
    request.state.is_owner = api_key in OWNER_KEYS

    if not request.state.is_owner:
        now = int(time.time()) // 60
        k = f"{api_key}:global:{now}"
        RATE[k] = RATE.get(k, 0) + 1
        if RATE[k] > PUBLIC_GLOBAL_LIMIT:
            raise HTTPException(429, "Global rate limit exceeded")

    return await call_next(request)

# ==================================================
# 🌍 IP OSINT
# ==================================================
@app.get("/osint/ip/{ip}")
async def ip_osint(ip: str, request: Request):
    ck = f"ip:{ip}"
    cached = cache_get(ck)
    if cached:
        return {"cached": True, **cached}

    if not request.state.is_owner:
        rate_check(request.state.api_key, "ip", PROVIDER_LIMITS["ip"])

    async with httpx.AsyncClient() as c:
        r = await c.get(f"http://ip-api.com/json/{ip}")
        data = r.json()

    cache_set(ck, data, 86400)
    return {"cached": False, **data}

# ==================================================
# 👤 USERNAME OSINT
# ==================================================
@app.get("/osint/username/{username}")
async def username_osint(username: str):
    sites = {
        "github": f"https://github.com/{username}",
        "reddit": f"https://reddit.com/user/{username}",
        "twitter": f"https://twitter.com/{username}"
    }
    found = []
    async with httpx.AsyncClient() as c:
        for site, url in sites.items():
            r = await c.get(url)
            if r.status_code == 200:
                found.append({"site": site, "url": url})
    return {"username": username, "found": found}

# ==================================================
# 📧 EMAIL OSINT
# ==================================================
@app.get("/osint/email/{email}")
def email_osint(email: str):
    domain = email.split("@")[-1]
    md5 = hashlib.md5(email.lower().encode()).hexdigest()
    return {
        "email": email,
        "domain": domain,
        "gravatar": f"https://www.gravatar.com/avatar/{md5}"
    }

# ==================================================
# 🧾 LEAK / PASTE (PUBLIC SEARCH LINKS)
# ==================================================
@app.get("/osint/leak/search")
def leak_search(q: str, request: Request):
    if not request.state.is_owner:
        rate_check(request.state.api_key, "leak", PROVIDER_LIMITS["leak"])

    return {
        "query": q,
        "sources": [
            f"https://github.com/search?q={q}",
            f"https://pastebin.com/search?q={q}"
        ]
    }

# ==================================================
# 🔍 GOOGLE DORK HELPER
# ==================================================
@app.get("/osint/dork")
def dork(q: str, request: Request):
    if not request.state.is_owner:
        rate_check(request.state.api_key, "dork", PROVIDER_LIMITS["dork"])

    return {
        "dork": q,
        "google": f"https://www.google.com/search?q={q}"
    }

# ==================================================
# 🔐 HASH INFO
# ==================================================
@app.get("/osint/hash/{hashv}")
def hash_info(hashv: str):
    l = len(hashv)
    t = "unknown"
    if l == 32: t = "MD5"
    elif l == 40: t = "SHA1"
    elif l == 64: t = "SHA256"
    return {"hash": hashv, "type": t}

# ==================================================
# 📡 Wi-Fi OSINT (WiGLE)
# ==================================================
def wigle_auth():
    raw = f"{WIGLE_USER}:{WIGLE_TOKEN}"
    return {
        "Authorization": "Basic " + base64.b64encode(raw.encode()).decode()
    }

@app.get("/osint/wifi/bssid/{bssid}")
async def wifi_bssid(bssid: str, request: Request):
    ck = f"wigle:{bssid}"
    cached = cache_get(ck)
    if cached:
        return {"cached": True, **cached}

    if not request.state.is_owner:
        rate_check(request.state.api_key, "wigle", PROVIDER_LIMITS["wigle"])

    async with httpx.AsyncClient() as c:
        r = await c.get(
            "https://api.wigle.net/api/v2/network/search",
            headers=wigle_auth(),
            params={"netid": bssid}
        )

    j = r.json()
    if not j.get("results"):
        return {"found": False}

    w = j["results"][0]
    data = {
        "ssid": w.get("ssid"),
        "bssid": w.get("netid"),
        "lat": w.get("trilat"),
        "lon": w.get("trilong")
    }

    cache_set(ck, data, 604800)
    return {"cached": False, **data}

# ==================================================
# 🗺️ MAP HELPER
# ==================================================
@app.get("/map")
def map_link(lat: float, lon: float):
    return {
        "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
    }

@app.get("/")
def root():
    return {"status": "FLOA RUNNING", "legal": True}
  
