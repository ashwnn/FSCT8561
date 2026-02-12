import requests

BASE_URL = "http://vm-ubuntu:3000"
TIMEOUT = 10

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
]

# Juice Shop may leak these (useful to show these headers)
LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
]

def full_url(path: str) -> str:
    return BASE_URL.rstrip("/") + path


def log_request(method: str, path: str, payload, status: int, length: int) -> None:
    print(f"[INFO] {method} {path} payload={payload} status={status} len={length}")


def check_headers(headers) -> None:
    # Show common info leakage headers if present
    for h in LEAKY_HEADERS:
        if h in headers:
            print(f"[INFO] Header {h}: {headers.get(h)}")

    for h in SECURITY_HEADERS:
        if h not in headers:
            print(f"Low Severity: missing header {h}")


def safe_get(session: requests.Session, path: str, params: dict):
    try:
        return session.get(full_url(path), params=params, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[ERROR] GET {path} failed: {e}")
        return None


def safe_post(session: requests.Session, path: str, body: dict):
    try:
        return session.post(full_url(path), json=body, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[ERROR] POST {path} failed: {e}")
        return None


def main() -> None:
    print("=" * 50)
    print("[INFO] Starting HTTP scan")
    print(f"[INFO] Target: {BASE_URL}")
    print("=" * 50)

    s = requests.Session()

    # GET /
    r = safe_get(s, "/", {})
    if r is not None:
        log_request("GET", "/", {}, r.status_code, len(r.text))
        check_headers(r.headers)
        print("-" * 50)

    # GET /rest/products/search?q=apple
    payload = {"q": "apple"}
    r = safe_get(s, "/rest/products/search", payload)
    if r is not None:
        log_request("GET", "/rest/products/search", payload, r.status_code, len(r.text))
        check_headers(r.headers)
        print("-" * 50)

    # GET /rest/products/search?q=test
    payload = {"q": "test"}
    r = safe_get(s, "/rest/products/search", payload)
    if r is not None:
        log_request("GET", "/rest/products/search", payload, r.status_code, len(r.text))
        check_headers(r.headers)
        print("-" * 50)

    # POST /rest/user/login (hard-coded)
    body = {"email": "test@test.com", "password": "test123"}
    r = safe_post(s, "/rest/user/login", body)
    if r is not None:
        log_request("POST", "/rest/user/login", body, r.status_code, len(r.text))
        check_headers(r.headers)
        print("-" * 50)

    print("[INFO] Done")


if __name__ == "__main__":
    main()
