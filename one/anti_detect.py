"""Anti-detection module for SheerID API requests.

Provides browser-like headers, NewRelic tracking, TLS fingerprint
spoofing (via curl_cffi), dynamic fingerprints, human-like delays,
session warmup, and proxy support.
"""

import os
import random
import hashlib
import time
import uuid
import base64
import json
import logging

logger = logging.getLogger(__name__)

# ===================== CONFIG =====================
# Single proxy or multiple proxies separated by | (pipe)
# Format: host:port:user:pass  or  http://user:pass@host:port
# Example: 1.2.3.4:6000:user:pass|5.6.7.8:7000:user:pass
PROXY_URL = os.environ.get("PROXY_URL", "")


def get_random_proxy() -> str | None:
    """Pick a random proxy from PROXY_URL (supports multiple, separated by |)."""
    if not PROXY_URL:
        return None
    proxies = [p.strip() for p in PROXY_URL.split("|") if p.strip()]
    if not proxies:
        return None
    return random.choice(proxies)

# ===================== CHROME VERSIONS =====================
IMPERSONATE_OPTIONS = {
    "chrome": ["chrome131", "chrome130", "chrome124", "chrome120"],
    "edge": ["edge131", "edge127", "edge101"],
    "safari": ["safari18", "safari17_2_ios", "safari17_0"],
}
DEFAULT_IMPERSONATE = "chrome131"

# ===================== USER AGENTS =====================
USER_AGENTS = [
    # Chrome 131
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Chrome 130
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome 131 Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Edge 131
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]

# ===================== PLATFORMS (sec-ch-ua) =====================
PLATFORMS = [
    ("Windows", '"Windows"', '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"'),
    ("Windows", '"Windows"', '"Chromium";v="130", "Google Chrome";v="130", "Not_A Brand";v="24"'),
    ("macOS", '"macOS"', '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"'),
    ("Linux", '"Linux"', '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"'),
]

LANGUAGES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9",
    "en-CA,en;q=0.9",
]

RESOLUTIONS = [
    "1920x1080", "1366x768", "1536x864", "1440x900",
    "1280x720", "2560x1440", "1600x900",
]


# ===================== FINGERPRINT =====================
def generate_fingerprint() -> str:
    """Generate realistic browser fingerprint hash."""
    components = [
        str(int(time.time() * 1000)),
        str(random.random()),
        random.choice(RESOLUTIONS),
        str(random.choice([-8, -7, -6, -5, -4, 0, 1, 2])),
        random.choice(LANGUAGES).split(",")[0],
        random.choice(["Win32", "MacIntel", "Linux x86_64"]),
        random.choice(["Google Inc.", "Apple Computer, Inc.", ""]),
        str(random.randint(2, 16)),   # CPU cores
        str(random.randint(4, 32)),   # device memory
        str(random.randint(0, 1)),    # touch support
        str(uuid.uuid4()),
    ]
    return hashlib.md5("|".join(components).encode()).hexdigest()


# ===================== NEWRELIC HEADERS =====================
def _newrelic_headers() -> dict:
    """Generate NewRelic tracking headers required by SheerID."""
    trace_id = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    trace_id = trace_id[:32]
    span_id = uuid.uuid4().hex[:16]
    ts = int(time.time() * 1000)

    payload = {
        "v": [0, 1],
        "d": {
            "ty": "Browser",
            "ac": "364029",
            "ap": "134291347",
            "id": span_id,
            "tr": trace_id,
            "ti": ts,
        },
    }
    return {
        "newrelic": base64.b64encode(json.dumps(payload).encode()).decode(),
        "traceparent": f"00-{trace_id}-{span_id}-01",
        "tracestate": f"364029@nr=0-1-364029-134291347-{span_id}----{ts}",
    }


# ===================== HEADERS =====================
def get_sheerid_headers() -> dict:
    """Full browser-like headers for SheerID API calls."""
    ua = random.choice(USER_AGENTS)
    platform = random.choice(PLATFORMS)
    lang = random.choice(LANGUAGES)
    nr = _newrelic_headers()

    return {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": lang,
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "content-type": "application/json",
        "sec-ch-ua": platform[2],
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": platform[1],
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": ua,
        "clientversion": "2.158.0",
        "clientname": "jslib",
        "origin": "https://services.sheerid.com",
        "referer": "https://services.sheerid.com/",
        **nr,
    }


# ===================== DELAYS =====================
def human_delay(min_ms: int = 300, max_ms: int = 1200):
    """Sleep with human-like timing (gamma distribution when possible)."""
    try:
        import numpy as np
        shape, scale = 2.0, (max_ms - min_ms) / 4000
        delay = min_ms / 1000 + np.random.gamma(shape, scale)
        delay = min(delay, max_ms / 1000)
    except ImportError:
        delay = random.randint(min_ms, max_ms) / 1000
        delay += random.uniform(0, 0.15)
    time.sleep(delay)


# ===================== SESSION =====================
def _format_proxy(proxy: str) -> str | None:
    """Normalize various proxy formats to http://... URL."""
    if not proxy:
        return None
    proxy = proxy.strip()
    if "://" in proxy:
        return proxy
    parts = proxy.split(":")
    if len(parts) == 2:
        return f"http://{parts[0]}:{parts[1]}"
    elif len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    elif "@" in proxy:
        return f"http://{proxy}"
    return None


def create_session(proxy: str = None):
    """Create HTTP session with best available library.

    Priority: curl_cffi (TLS spoofing)  > httpx > requests

    Args:
        proxy: Proxy URL override. Falls back to PROXY_URL env var.

    Returns:
        tuple: (session, library_name)
    """
    proxy = _format_proxy(proxy or get_random_proxy())
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy, "all://": proxy}
        logger.info(f"🔒 Proxy configured: {proxy[:35]}...")

    imp = DEFAULT_IMPERSONATE

    # 1. Try curl_cffi (best — TLS fingerprint matches real Chrome)
    try:
        from curl_cffi import requests as curl_requests

        for ver in [imp, "chrome120", "chrome110", "chrome100"]:
            try:
                sess = (
                    curl_requests.Session(proxies=proxies, impersonate=ver)
                    if proxies
                    else curl_requests.Session(impersonate=ver)
                )
                logger.info(f"✅ Anti-detect: curl_cffi + {ver} TLS impersonation")
                return sess, "curl_cffi"
            except Exception:
                continue

        # curl_cffi without impersonation
        sess = curl_requests.Session(proxies=proxies) if proxies else curl_requests.Session()
        logger.warning("⚠️  curl_cffi loaded but TLS impersonation failed")
        return sess, "curl_cffi"

    except ImportError:
        logger.warning("❌ curl_cffi not installed — TLS fingerprint detectable!")
        logger.warning("   Install: pip install curl_cffi")

    # 2. httpx (detectable TLS but functional)
    try:
        import httpx
        proxy_url = proxies.get("all://") if proxies else None
        sess = httpx.Client(timeout=30, proxy=proxy_url)
        logger.info("⚠️  Anti-detect: httpx (no TLS spoofing)")
        return sess, "httpx"
    except ImportError:
        pass

    # 3. Fallback to requests
    import requests
    sess = requests.Session()
    if proxies:
        sess.proxies = proxies
    logger.warning("❌ Anti-detect: requests (HIGH detection risk)")
    return sess, "requests"


# ===================== WARMUP =====================
def warm_session(session, program_id: str = None):
    """Pre-requests to simulate real browser page load."""
    base = "https://services.sheerid.com"
    hdrs = get_sheerid_headers()

    try:
        session.get(f"{base}/rest/v2/config", headers=hdrs, timeout=10)
        human_delay(500, 1000)
    except Exception:
        pass

    if program_id:
        try:
            session.get(f"{base}/rest/v2/program/{program_id}", headers=hdrs, timeout=10)
            human_delay(300, 700)
        except Exception:
            pass

    try:
        session.get(
            f"{base}/rest/v2/organization/search",
            params={"country": "US", "term": "", **({"programId": program_id} if program_id else {})},
            headers=hdrs,
            timeout=10,
        )
        human_delay(200, 500)
    except Exception:
        pass
