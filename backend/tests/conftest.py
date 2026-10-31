"""Local HTTP test client vs production Secure session cookies.

Signup and login set access_token and refresh_token with Secure and
SameSite=None. Production keeps that: browsers reject SameSite=None
without Secure, and they only attach Secure cookies to HTTPS (Chromium's
localhost exception aside). The flags are not an application bug.

Python's http.cookiejar is stricter than curl. DefaultCookiePolicy stores
the Secure cookies (so the jar assertions pass) but return_ok_secure
refuses to attach them unless the scheme is in secure_protocols
("https", "wss"). requests then calls GET /auth/me with no Cookie header
and the API returns 401. curl's cookie jar sends those same Secure
cookies on http://127.0.0.1 and /auth/me returns 200; replaying the stored
access_token as a Cookie header does too. The JWT and user row are valid.

When REACT_APP_BACKEND_URL is plain HTTP, relax only this process's cookie
policy so the suite can present those cookies. HTTPS preview runs keep the
default policy. Server cookie flags are unchanged.
"""
import os

import http.cookiejar


def pytest_configure() -> None:
    base = os.environ.get("REACT_APP_BACKEND_URL", "")
    if not base.startswith("http://"):
        return

    def return_ok_secure(self, cookie, request):  # noqa: ARG001
        return True

    http.cookiejar.DefaultCookiePolicy.return_ok_secure = return_ok_secure
