"""Classify a Microsoft ROPC domain-password result.

Default (DOMAIN_AUTH_REQUIRE_MFA unset/false):
  password incorrect / unknown user -> reject
  success, or MFA/interaction required -> accept

The password was not wrong in the MFA case; Microsoft only refused to issue a
token without the authenticator. Registration still emails that address.

Strict mode restores the device-code + authenticator step.
"""

import os

# Password was rejected, or the account does not exist.
INCORRECT_PASSWORD_CODES = {
    "50126",  # invalid username or password
    "50034",  # user account does not exist
    "50053",  # account locked
    "50055",  # password expired
    "50056",  # no password on account
    "50057",  # account disabled
}

# Password was accepted; extra proof was required to mint a token.
PASSWORD_ACCEPTED_MFA_CODES = {
    "50072",
    "50074",
    "50076",
    "50079",
    "50158",
    "53004",
    "65001",
}


def domain_auth_require_mfa():
    return os.environ.get("DOMAIN_AUTH_REQUIRE_MFA", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }


def classify_domain_password(token_response):
    """Return 'ok', 'mfa_required', or 'incorrect'.

    token_response is the parsed JSON from the Microsoft token endpoint.
    A successful token response has no error key.
    """
    if not token_response.get("error"):
        return "ok"

    codes = set()
    for blob in (
        token_response.get("error_codes") or [],
        token_response.get("error_description") or "",
        token_response.get("suberror") or "",
    ):
        text = " ".join(str(c) for c in blob) if isinstance(blob, list) else str(blob)
        for code in INCORRECT_PASSWORD_CODES | PASSWORD_ACCEPTED_MFA_CODES:
            if code in text:
                codes.add(code)

    if codes & INCORRECT_PASSWORD_CODES and not (codes & PASSWORD_ACCEPTED_MFA_CODES):
        return "incorrect"
    if codes & PASSWORD_ACCEPTED_MFA_CODES or "interaction_required" in str(token_response.get("error")):
        return "mfa_required"
    # Unknown failure: do not treat as verified.
    return "incorrect"


def domain_password_accepted(token_response):
    result = classify_domain_password(token_response)
    if result == "incorrect":
        return False
    if result == "mfa_required" and domain_auth_require_mfa():
        return False
    return True
