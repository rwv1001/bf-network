#!/usr/bin/env python3
"""
npm/setup.py - fully automatic Nginx Proxy Manager setup for bf-network.

This script is intentionally installer-friendly:
  - waits for the NPM API;
  - creates the initial admin account in setup mode if necessary;
  - creates or reuses the PORTAL_URL proxy host;
  - optionally skips NPM's HTTP-01 flow;
  - when DNS-01/acme.sh has already written a certificate, imports that
    certificate into NPM as a custom certificate and attaches it to the host.

Important for this deployment:
  The public domain points at the Oracle VPS. The VPS reverse tunnel forwards
  HTTPS to the Pi's local NPM port 443. Therefore NPM itself must have an SSL
  certificate attached to the proxy host, even if the certificate was issued by
  acme.sh/Bunny rather than by NPM's built-in HTTP-01 flow.
"""

import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

NPM_URL = os.environ.get("NPM_URL", "http://127.0.0.1:81").rstrip("/")
NPM_EMAIL = os.environ.get("NPM_ADMIN_EMAIL", "")
NPM_PASS = os.environ.get("NPM_ADMIN_PASSWORD", "")
LE_EMAIL = os.environ.get("ADMIN_EMAIL", "")
PORTAL_URL = os.environ.get("PORTAL_URL", "")
FWD_HOST = os.environ.get("PORTAL_FORWARD_HOST") or os.environ.get("PORTAL_IP", "127.0.0.1")
FWD_PORT = int(os.environ.get("PORTAL_FORWARD_PORT", "8080"))

SKIP_SSL = os.environ.get("NPM_SETUP_SKIP_SSL", "false").strip().lower() in {
    "1", "true", "yes", "y", "on"
}
FORCE_SSL = os.environ.get("NPM_SETUP_FORCE_SSL", "true").strip().lower() not in {
    "0", "false", "no", "n", "off"
}


def _api(method, path, data=None, token=None, timeout=60):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(
        f"{NPM_URL}{path}", data=body, headers=headers, method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            if not raw:
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read())
        except Exception:
            detail = error.reason
        raise RuntimeError(f"{method} {path} -> HTTP {error.code}: {detail}") from None


def _multipart_api(method, path, files, token=None, timeout=120):
    boundary = f"----bfnetwork{uuid.uuid4().hex}"
    chunks = []

    for field_name, file_path in files.items():
        file_path = Path(file_path)
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(
            (
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{file_path.name}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            ).encode("utf-8")
        )
        chunks.append(file_path.read_bytes())
        chunks.append(b"\r\n")

    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(chunks)

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(
        f"{NPM_URL}{path}", data=body, headers=headers, method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            if not raw:
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read())
        except Exception:
            detail = error.reason
        raise RuntimeError(f"{method} {path} -> HTTP {error.code}: {detail}") from None


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


def _login(email, password):
    return _api("POST", "/api/tokens", {"identity": email, "secret": password})["token"]


def _create_initial_admin(domain):
    payload = {
        "email": NPM_EMAIL,
        "name": "Admin",
        "nickname": "admin",
        "roles": ["admin"],
        "is_disabled": False,
        "auth": {
            "type": "password",
            "secret": NPM_PASS,
        },
    }

    try:
        _api("POST", "/api/users", payload)
        print(f"npm-setup: created initial admin {NPM_EMAIL} in setup mode", flush=True)
    except Exception as exc:
        print(f"npm-setup: setup-mode admin creation failed/skipped: {exc}", flush=True)

    return _login(NPM_EMAIL, NPM_PASS)


def _ensure_admin_token(domain):
    if not NPM_EMAIL or not NPM_PASS:
        raise SystemExit(
            "npm-setup: NPM_ADMIN_EMAIL or NPM_ADMIN_PASSWORD not set in .env."
        )

    try:
        token = _login(NPM_EMAIL, NPM_PASS)
        print("npm-setup: authenticated with configured admin credentials", flush=True)
        return token
    except Exception as first_exc:
        print(
            f"npm-setup: configured admin login failed; trying setup-mode admin creation: {first_exc}",
            flush=True,
        )

    try:
        return _create_initial_admin(domain)
    except Exception as second_exc:
        print(
            f"npm-setup: setup-mode login failed; trying legacy bootstrap account: {second_exc}",
            flush=True,
        )

    try:
        token = _login("admin@example.com", "changeme")
        print("npm-setup: authenticated with legacy bootstrap credentials", flush=True)
        try:
            _api(
                "PUT",
                "/api/users/me",
                {
                    "email": NPM_EMAIL,
                    "name": "Admin",
                    "nickname": "admin",
                    "roles": ["admin"],
                    "is_disabled": False,
                },
                token=token,
            )
            _api(
                "PUT",
                "/api/users/me/auth",
                {
                    "type": "password",
                    "current": "changeme",
                    "secret": NPM_PASS,
                },
                token=token,
            )
            token = _login(NPM_EMAIL, NPM_PASS)
            print("npm-setup: converted bootstrap admin to configured credentials", flush=True)
            return token
        except Exception as update_exc:
            raise RuntimeError(f"bootstrap login worked but admin update failed: {update_exc}") from update_exc
    except Exception as third_exc:
        raise SystemExit(
            "npm-setup: could not authenticate or create the NPM admin account: "
            f"{third_exc}"
        )


def _proxy_host_payload(domain, forward_host, forward_port, cert_id=0, ssl_forced=False):
    advanced_config = """proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
"""
    return {
        "domain_names": [domain],
        "forward_scheme": "http",
        "forward_host": forward_host,
        "forward_port": forward_port,
        "access_list_id": 0,
        "certificate_id": int(cert_id or 0),
        "meta": {},
        "advanced_config": advanced_config,
        "locations": [],
        "block_exploits": False,
        "caching_enabled": False,
        "allow_websocket_upgrade": True,
        "http2_support": True if cert_id else False,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "ssl_forced": bool(ssl_forced and cert_id),
        "enabled": True,
    }


def _get_proxy_host(token, domain):
    hosts = _api("GET", "/api/nginx/proxy-hosts", token=token)
    for host in hosts:
        if domain in host.get("domain_names", []):
            return host
    return None


def _create_or_get_proxy_host(token, domain, forward_host, forward_port):
    host = _get_proxy_host(token, domain)
    payload = _proxy_host_payload(domain, forward_host, forward_port)

    if host:
        needs_update = (
            host.get("forward_host") != forward_host
            or int(host.get("forward_port") or 0) != int(forward_port)
        )
        if needs_update:
            _api("PUT", f"/api/nginx/proxy-hosts/{host['id']}", payload, token=token)
            print(f"npm-setup: updated proxy host for {domain} (id={host['id']}).", flush=True)
            return _get_proxy_host(token, domain)
        print(f"npm-setup: proxy host for {domain} already exists (id={host['id']}).", flush=True)
        return host

    print(f"npm-setup: creating proxy host for {domain}...", flush=True)
    host = _api("POST", "/api/nginx/proxy-hosts", payload, token=token)
    print(f"npm-setup: proxy host created (id={host['id']}).", flush=True)
    return host


def _update_proxy_host_certificate(token, domain, forward_host, forward_port, host_id, cert_id):
    payload = _proxy_host_payload(domain, forward_host, forward_port, cert_id=cert_id, ssl_forced=FORCE_SSL)
    _api("PUT", f"/api/nginx/proxy-hosts/{host_id}", payload, token=token)
    print(
        f"npm-setup: attached certificate id={cert_id} to proxy host id={host_id}; "
        f"ssl_forced={payload['ssl_forced']}.",
        flush=True,
    )


def _custom_cert_paths(domain):
    fullchain = os.environ.get("NPM_CUSTOM_CERT_FULLCHAIN") or f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    privkey = os.environ.get("NPM_CUSTOM_CERT_KEY") or f"/etc/letsencrypt/live/{domain}/privkey.pem"
    return Path(fullchain), Path(privkey)


def _find_existing_custom_certificate(token, domain):
    certs = _api("GET", "/api/nginx/certificates", token=token)
    for cert in certs:
        if cert.get("provider") == "other" and domain in cert.get("domain_names", []):
            return cert
    return None


def _import_custom_certificate(token, domain):
    fullchain, privkey = _custom_cert_paths(domain)

    if not fullchain.exists() or not privkey.exists():
        print(
            "npm-setup: custom certificate files are not present yet; "
            f"looked for {fullchain} and {privkey}.",
            flush=True,
        )
        return None

    # Basic sanity check so bad paths fail before the API upload.
    if "BEGIN CERTIFICATE" not in fullchain.read_text(errors="ignore"):
        raise RuntimeError(f"{fullchain} does not look like a PEM certificate")
    key_text = privkey.read_text(errors="ignore")
    if "BEGIN" not in key_text or "PRIVATE KEY" not in key_text:
        raise RuntimeError(f"{privkey} does not look like a PEM private key")

    cert = _find_existing_custom_certificate(token, domain)
    if cert:
        cert_id = cert["id"]
        print(f"npm-setup: reusing existing custom certificate id={cert_id}", flush=True)
    else:
        cert = _api(
            "POST",
            "/api/nginx/certificates",
            {
                "provider": "other",
                "nice_name": domain,
                "domain_names": [domain],
                "meta": {},
            },
            token=token,
        )
        cert_id = cert["id"]
        print(f"npm-setup: created custom certificate record id={cert_id}", flush=True)

    _multipart_api(
        "POST",
        f"/api/nginx/certificates/{cert_id}/upload",
        {
            "certificate": str(fullchain),
            "certificate_key": str(privkey),
        },
        token=token,
    )
    print(f"npm-setup: uploaded custom certificate files for {domain}", flush=True)
    return cert_id


def _request_http01_certificate(token, domain):
    if not LE_EMAIL:
        print("npm-setup: ADMIN_EMAIL not set, so built-in HTTP-01 is skipped.", flush=True)
        return None

    print(f"npm-setup: requesting built-in NPM HTTP-01 certificate for {domain}...", flush=True)
    cert = _api(
        "POST",
        "/api/nginx/certificates",
        {
            "provider": "letsencrypt",
            "domain_names": [domain],
            "nice_name": domain,
            "meta": {"dns_challenge": False},
        },
        token=token,
        timeout=180,
    )
    cert_id = cert["id"]
    print(f"npm-setup: built-in NPM certificate issued id={cert_id}", flush=True)
    return cert_id

def csv_env(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]

def build_captive_hosts() -> list[dict]:
    portal_domain = urlparse(PORTAL_URL).hostname
    portal_backend_host = os.environ.get("PORTAL_FORWARD_HOST", "captive-portal-web")
    portal_backend_port = int(os.environ.get("PORTAL_FORWARD_PORT", "8080"))

    hosts: list[dict] = []

    # Public portal host
    if portal_domain:
        hosts.append({
            "domain": portal_domain,
            "forward_host": portal_backend_host,
            "forward_port": portal_backend_port,
            "ssl": True,
        })

    # Portal IP / local landing host(s)
    for ip in csv_env("CAPTIVE_PORTAL_IPS"):
        hosts.append({
            "domain": ip,
            "forward_host": portal_backend_host,
            "forward_port": portal_backend_port,
            "ssl": False,
        })

    # Captive-check domains
    for domain in csv_env("CAPTIVE_CHECK_HOSTS"):
        hosts.append({
            "domain": domain,
            "forward_host": portal_backend_host,
            "forward_port": portal_backend_port,
            "ssl": False,
        })

    # De-duplicate by domain while preserving order
    seen = set()
    unique_hosts = []
    for host in hosts:
        domain = host["domain"]
        if domain and domain not in seen:
            seen.add(domain)
            unique_hosts.append(host)

    return unique_hosts



def main():
    if not PORTAL_URL:
        print("npm-setup: PORTAL_URL not set - nothing to do.", flush=True)
        return

    CAPTIVE_HOSTS = build_captive_hosts()

    domain = urlparse(PORTAL_URL).hostname
    if not domain:
        raise SystemExit(f"npm-setup: cannot parse domain from PORTAL_URL={PORTAL_URL!r}")

    _wait_for_npm()
    token = _ensure_admin_token(domain)
    for host_def in CAPTIVE_HOSTS:
        domain = host_def["domain"]
        host = _create_or_get_proxy_host(
            token,
            domain,
            host_def["forward_host"],
            host_def["forward_port"],
        )

        if host_def["ssl"]:
            cert_id = _import_custom_certificate(token, domain)
            if cert_id:
                _update_proxy_host_certificate(token, domain, host_def["forward_host"], host_def["forward_port"], host["id"], cert_id)

    if SKIP_SSL:
        print(
            "npm-setup: NPM_SETUP_SKIP_SSL is true and no custom cert is present yet; "
            "leaving proxy host as HTTP for now. Run npm-setup again after DNS-01 "
            "certificate issuance.",
            flush=True,
        )
        return

    


if __name__ == "__main__":
    main()
