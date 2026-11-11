import re
import json
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
from urllib.parse import urljoin, urlsplit

MAX_URLS_TO_INSPECT = 5
DEFAULT_NETWORK_TIMEOUT = 2

def clean(t):
    t = str(t).lower()
    t = re.sub(r"http\S+|www\.\S+", " url ", t)
    t = re.sub(r"\d+", " num ", t)
    t = re.sub(r"[^a-z\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"]+")
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}
TRUSTED_BRANDS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "linkedin.com", "indeed.com", "paypal.com",
}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".work", ".zip"}


def extract_urls(text):
    """Return unique HTTP(S) links from a message."""
    urls = []
    for match in URL_PATTERN.findall(str(text)):
        url = match.rstrip(".,!?;:)]}")
        if url.lower().startswith("www."):
            url = f"https://{url}"
        if url not in urls:
            urls.append(url)
    return urls[:MAX_URLS_TO_INSPECT]


def verify_urls_with_google(urls, api_key, timeout=3):
    """Check links against Google Safe Browsing.

    An empty threat match means Google has no known threat for the URL; it
    does not establish that the site is legitimate or currently available.
    """
    if not urls:
        return []
    urls = list(dict.fromkeys(urls))[:MAX_URLS_TO_INSPECT]
    if not api_key:
        return [{"url": url, "status": "unavailable", "message": "Google verification is not configured."}
                for url in urls]

    payload = {
        "client": {"clientId": "scam-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }
    request = Request(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError):
        return [{"url": url, "status": "unavailable", "message": "Google verification could not be completed."}
                for url in urls]

    matches = {
        match.get("threat", {}).get("url"): match.get("threatType", "Known threat")
        for match in result.get("matches", [])
    }
    return [
        {
            "url": url,
            "status": "threat" if url in matches else "no_match",
            "message": matches.get(url, "No known threat reported by Google."),
        }
        for url in urls
    ]


def _registrable_domain(hostname):
    parts = hostname.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def _edit_distance(left, right):
    rows = range(len(right) + 1)
    previous = list(rows)
    for index, left_char in enumerate(left, 1):
        current = [index]
        for right_index, right_char in enumerate(right, 1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_char != right_char),
            ))
        previous = current
    return previous[-1]


def _looks_like_trusted_brand(domain):
    for trusted in TRUSTED_BRANDS:
        trusted_name = trusted.split(".")[0]
        domain_name = domain.split(".")[0]
        normalized = domain_name.replace("0", "o").replace("1", "l").replace("3", "e")
        if domain != trusted and (
            _edit_distance(normalized, trusted_name) <= 1
            or trusted_name in domain_name and domain.endswith("." + trusted) is False
        ):
            return trusted
    return ""


def _domain_registration_date(hostname, timeout):
    request = Request(
        f"https://rdap.org/domain/{hostname}",
        headers={"User-Agent": "ScamDetector/1.0"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError, UnicodeError):
        return None

    dates = [
        event.get("eventDate")
        for event in data.get("events", [])
        if event.get("eventAction") in {"registration", "registered"}
    ]
    if not dates:
        return None
    try:
        parsed = datetime.fromisoformat(dates[0].replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _safe_host(hostname, port, timeout):
    """Reject hosts that resolve to local, private, or otherwise reserved IPs."""
    try:
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return bool(addresses)


class _NoRedirectHandler(HTTPRedirectHandler):
    def http_error_301(self, request, response, code, message, headers):
        return response

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _inspect_url(url, timeout):
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {
            "url": url,
            "status": "warning",
            "score": 10,
            "reasons": ["The link has an invalid URL format."],
            "final_url": "",
        }
    hostname = (parsed.hostname or "").lower().rstrip(".")
    reasons = []
    score = 0
    final_url = ""

    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username
        or parsed.password
        or not re.fullmatch(r"[a-z0-9.-]+", hostname)
    ):
        return {
            "url": url,
            "status": "warning",
            "score": 10,
            "reasons": ["The link has an unsupported scheme or unsafe URL format."],
            "final_url": "",
        }
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return {
            "url": url,
            "status": "warning",
            "score": 10,
            "reasons": ["The link contains an invalid port."],
            "final_url": "",
        }
    if not _safe_host(hostname, port, timeout):
        return {
            "url": url,
            "status": "warning",
            "score": 10,
            "reasons": ["The destination resolves to a private, local, reserved, or unreachable network."],
            "final_url": "",
        }

    if parsed.scheme != "https":
        score += 1
        reasons.append("The link does not use HTTPS.")
    if hostname in SHORTENER_DOMAINS:
        score += 2
        reasons.append("This is a URL-shortening service, so the destination is hidden.")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
        score += 2
        reasons.append("The link uses an IP address instead of a recognizable domain.")
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 1
        reasons.append("The domain uses a TLD commonly seen in disposable links.")

    domain = _registrable_domain(hostname)
    brand = _looks_like_trusted_brand(domain)
    if brand:
        score += 3
        reasons.append(f"The domain resembles {brand} but is not that official domain.")

    registration_date = _domain_registration_date(hostname, timeout)
    if registration_date:
        age_days = max(
            0,
            (datetime.now(timezone.utc) - registration_date.astimezone(timezone.utc)).days,
        )
        if age_days < 30:
            score += 3
            reasons.append(f"The domain appears to be only {age_days} days old.")
        elif age_days < 180:
            score += 1
            reasons.append(f"The domain appears to be only {age_days} days old.")

    request = Request(url, method="HEAD", headers={"User-Agent": "ScamDetector/1.0"})
    try:
        opener = build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            location = response.headers.get("Location", "")
            if location:
                redirect_url = urljoin(url, location)
                redirect_host = (urlsplit(redirect_url).hostname or "").lower().rstrip(".")
                if redirect_host and redirect_host != hostname:
                    score += 2
                    reasons.append(f"The link redirects to {redirect_host}.")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        reasons.append("The destination could not be reached for redirect checking.")

    return {
        "url": url,
        "status": "warning" if score else "clean",
        "score": min(score, 10),
        "reasons": reasons,
        "final_url": final_url,
    }


def inspect_urls(urls, timeout=DEFAULT_NETWORK_TIMEOUT):
    """Assess URL structure, redirects, and domain age using explainable signals."""
    urls = list(dict.fromkeys(urls))[:MAX_URLS_TO_INSPECT]
    if not urls:
        return []
    with ThreadPoolExecutor(max_workers=min(4, len(urls))) as executor:
        return list(executor.map(lambda url: _inspect_url(url, timeout), urls))