#!/usr/bin/env python3
"""
npm/setup.py — Auto-configure Nginx Proxy Manager for PORTAL_URL.

Reads from environment (sourced via env_file ../captive-portal/.env):
  PORTAL_URL           — e.g. http://bf-network.kozow.com
  NPM_ADMIN_EMAIL      — NPM web UI login email
  NPM_ADMIN_PASSWORD   — NPM web UI login password
  ADMIN_EMAIL          — used as Let's Encrypt contact email
  NPM_URL              — override API base URL (default: http://127.0.0.1:81)
  PORTAL_FORWARD_HOST  — backend host NPM proxies to (default: 192.168.99.4)
  PORTAL_FORWARD_PORT  — backend port NPM proxies to (default: 8080)

Behaviour:
  1. Waits up to 3 minutes for the NPM API to become ready.
  2. Authenticates with NPM.
  3. If a proxy host for the PORTAL_URL domain already exists → exits cleanly.
  4. Creates the proxy host (HTTP only first so the domain is immediately usable).
  5. Requests a Let's Encrypt certificate via HTTP-01 challenge.
  6. Updates the proxy host to use the cert and force HTTPS.
  If SSL provisioning fails (e.g. port 80 not publicly reachable), the HTTP
  proxy host is left intact and a clear message is printed — add SSL manually
  via the NPM web UI at http://<host-ip>:81.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

NPM_URL      = os.environ.get("NPM_URL", "http://127.0.0.1:81")
NPM_EMAIL    = os.environ.get("NPM_ADMIN_EMAIL", "")
NPM_PASS     = os.environ.get("NPM_ADMIN_PASSWORD", "")
LE_EMAIL     = os.environ.get("ADMIN_EMAIL", "")
PORTAL_URL   = os.environ.get("PORTAL_URL", "")
FWD_HOST     = os.environ.get("PORTAL_FORWARD_HOST") or os.environ["PORTAL_IP"]
FWD_PORT     = int(os.environ.get("PORTAL_FORWARD_PORT", "8080"))


def _api(method, path, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        f"{NPM_URL}{path}", data=body, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read())
        except Exception:
            detail = e.reason
        raise RuntimeError(f"{method} {path} → HTTP {e.code}: {detail}") from None


def _wait_for_npm(max_wait=180):
    print("npm-setup: waiting for NPM API...", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{NPM_URL}/api/", timeout=5)
            print("npm-setup: NPM API is up.", flush=True)
            return
        except Exception:
            time.sleep(5)
    raise SystemExit(f"npm-setup: timed out after {max_wait}s waiting for NPM API")


def _proxy_host_payload(domain, cert_id=0, ssl_forced=False):
    advanced_config = """proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
"""
    return {
        "domain_names":           [domain],
        "forward_scheme":         "http",
        "forward_host":           FWD_HOST,
        "forward_port":           FWD_PORT,
        "access_list_id":         "0",
        "certificate_id":         cert_id,
        "meta":                   {"letsencrypt_agree": cert_id != 0, "dns_challenge": False},
        "advanced_config":        "advanced_config",
        "locations":              [],
        "block_exploits":         False,
        "caching_enabled":        False,
        "allow_websocket_upgrade": True,
        "http2_support":          False,
        "hsts_enabled":           False,
        "hsts_subdomains":        False,
        "ssl_forced":             ssl_forced,
        "enabled":                True,
    }


def main():
    if not PORTAL_URL:
        print("npm-setup: PORTAL_URL not set — nothing to do.")
        return

    domain = urlparse(PORTAL_URL).hostname
    if not domain:
        print(f"npm-setup: cannot parse domain from PORTAL_URL={PORTAL_URL!r}", flush=True)
        sys.exit(1)

    if not NPM_EMAIL or not NPM_PASS:
        print(
            "npm-setup: NPM_ADMIN_EMAIL or NPM_ADMIN_PASSWORD not set in captive-portal/.env — skipping.",
            flush=True,
        )
        return

    _wait_for_npm()

    # ── Authenticate ─────────────────────────────────────────────────────────
    try:
        resp = _api("POST", "/api/tokens", {"identity": NPM_EMAIL, "secret": NPM_PASS})
        token = resp["token"]
    except Exception as e:
        print(f"npm-setup: authentication failed: {e}", flush=True)
        sys.exit(1)

    # ── Check for existing proxy host ─────────────────────────────────────────
    hosts = _api("GET", "/api/nginx/proxy-hosts", token=token)
    for h in hosts:
        if domain in h.get("domain_names", []):
            print(
                f"npm-setup: proxy host for {domain} already exists (id={h['id']}) — skipping.",
                flush=True,
            )
            return

    # ── Create proxy host (HTTP first so the domain is immediately usable) ────
    print(f"npm-setup: creating proxy host for {domain}...", flush=True)
    host = _api("POST", "/api/nginx/proxy-hosts", _proxy_host_payload(domain), token=token)
    host_id = host["id"]
    print(f"npm-setup: proxy host created (id={host_id}).", flush=True)

    # ── Request Let's Encrypt certificate ─────────────────────────────────────
    if not LE_EMAIL:
        print(
            "npm-setup: ADMIN_EMAIL not set — skipping SSL. "
            "Add a certificate manually in the NPM web UI (http://<server>:81).",
            flush=True,
        )
        return

    print(f"npm-setup: requesting Let's Encrypt certificate for {domain}...", flush=True)
    try:
        cert = _api(
            "POST",
            "/api/nginx/certificates",
            {
                "provider":     "letsencrypt",
                "domain_names": [domain],
                "meta": {
                    "letsencrypt_email": LE_EMAIL,
                    "letsencrypt_agree": True,
                    "dns_challenge":     False,
                },
                "nice_name": domain,
            },
            token=token,
        )
        cert_id = cert["id"]
    except Exception as e:
        print(
            f"npm-setup: SSL cert request failed: {e}\n"
            f"npm-setup: proxy host is active on HTTP. "
            f"Add SSL manually in the NPM web UI.",
            flush=True,
        )
        return

    # ── Update proxy host — enable SSL + force HTTPS ──────────────────────────
    print(f"npm-setup: certificate issued (id={cert_id}). Enabling SSL...", flush=True)
    _api(
        "PUT",
        f"/api/nginx/proxy-hosts/{host_id}",
        _proxy_host_payload(domain, cert_id=cert_id, ssl_forced=True),
        token=token,
    )
    print(
        f"npm-setup: done. {domain} → {FWD_HOST}:{FWD_PORT} with Let's Encrypt SSL + force-HTTPS.",
        flush=True,
    )


if __name__ == "__main__":
    main()
