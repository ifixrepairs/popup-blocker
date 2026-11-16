"""AdTrapper PC licensing — the customer side of the license door.

This module is deliberately free of any GUI imports so its whole logic
can be tested headless. The patched AdTrapper build calls it before
the main window opens:

- first run: no saved key -> the app asks for the activation key;
- the key + this machine's id are checked with the license relay;
- a good key is remembered on this machine and re-checked at every
  start (and the result is what the NEXT start acts on — a running
  scan is never interrupted);
- if the relay cannot be reached, the app keeps working for
  GRACE_DAYS (default 7) from the last good check, so a customer's
  internet outage never bricks them;
- a paused or expired key lands on a plain "needs renewal" screen
  with the shop's contact words — never a crash, never a silent
  lockout.

CUSTOMER SHOP BUILD: this copy of the module has NO owner bypass.
The bypass code that exists in the shop's own build was removed
from this file entirely -- there is no file a customer can place
next to the app, and no phrase they can type, that skips the
license check. Every start on a customer machine goes through
the key, the relay, and the grace rules below.

Website sign-in (11.29): beside the key door, this module also
carries the adtrapperapp.com account door (portal SPEC section
6). The customer taps "Sign in with your AdTrapper account" in
the app; the browser opens the site's /authorize page; the
one-time code shown there is typed into the app and exchanged
at /api/authorize for a remembered app token. The raw token
lives only in the local state file -- it is never written to
the log. The app re-checks at /api/app-check on start and in
the background. Every good check serves offline_valid_until --
the EARLIER of (check time + the site's offline grace) and the
plan's own expiry -- and that instant is a HARD deadline: past
it the app stops as run out even if the site cannot be reached.
The app never adds days of its own and never computes the
deadline itself; it consumes the served field exactly.

One-click hand-off (11.30, ONE-CLICK-SPEC): on the
account page the signed-in customer taps "Open
AdTrapper"; the site mints a single-use hand-off token
(hash-only at rest, five minutes, bound to that
customer) and hands it to this program in an
adtrapper:// link. handoff_exchange() below trades it
at /api/handoff for the SAME remembered app token the
typed-code door issues -- no code typed, no key, no
second login. A refused hand-off changes nothing: the
code door and the key door are exactly as they were.

App-first poll sign-in (customer 1.3, portal 1.2):
the scheme door cannot reach every build -- the Mac
customer bundle's launcher is a shell script, and a
script executable cannot receive the adtrapper://
Apple Event, so on a Mac the one-click hand-off
fires into the void. The app-first door needs no
scheme at all: authorize_start() asks the portal
for a pending sign-in request, the app opens the
request's page in the browser and polls
authorize_poll() until the signed-in customer taps
"Sign this app in" there; the portal then delivers
the SAME remembered app token the code door issues.
Portal 1.3 (customer 1.4): the delivery is
RECOVERABLE -- the portal holds the issued token
for the request's whole thirty-minute life and a
later poll from the starting machine re-delivers
the SAME token, so an app that fails to land one
answer (the 2026-11-14 step-zero defect: the state
save raised inside a read-only bundle and the
next poll read the burned request as a refusal)
collects on its next poll instead. The request
id lives only in the
caller's memory -- never in the state file, never
in the log.
"""
import hashlib
import json
import os
import platform
import ssl
import time
import urllib.request
import uuid

DEFAULT_RELAY_URL = "https://keys.ifixxrepairs.com"   # production (re-applied after regeneration)
DEFAULT_GRACE_DAYS = 7
# The website account door (11.29): this constant is the ONE
# place the portal is named; local testing points it elsewhere
# through ADTRAPPER_PORTAL_URL.
DEFAULT_PORTAL_URL = "https://adtrapperapp.com"
STATE_FILE = "adtrapper-license.json"
LOG_FILE = "adtrapper-license.log"


def machine_id() -> str:
    """A stable id for this computer. Only its hash ever leaves the
    machine as an identifier; the relay stores the hash itself."""
    raw = "%s:%s:%s:%s" % (
        uuid.getnode(), platform.node(), platform.system(),
        platform.machine())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _iso_to_epoch(text):
    """Epoch seconds for the portal's ISO stamps
    ("2026-11-20T12:00:00Z"). None when unparseable -- a stamp
    we cannot read is never treated as time in hand."""
    if not text:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.strptime(
            text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def entitlement_words(ent):
    """Plain plan words for an /api entitlement snapshot:
    "Free trial - 1 computer", "Paid plan - 2 computers"."""
    ent = ent or {}
    plan = "Free trial" if ent.get("is_trial") else "Paid plan"
    n = int(ent.get("max_devices") or 1)
    return "%s - %d computer%s" % (plan, n, "" if n == 1 else "s")


# Plain words for the account door's refusals (portal SPEC
# section 6 reasons). One wording per reason, shared by the
# sign-in screen and the renewal screen; unit-tested so the
# words can never silently vanish.
SIGNIN_REASONS = {
    "invalid_code": "That code did not work. Codes are used "
                    "once and last 10 minutes - open the "
                    "sign-in page again for a fresh code, "
                    "then type the new one here.",
    "invalid_handoff": "That sign-in link did not work. "
                       "Sign-in links are used once and "
                       "last 5 minutes - go back to your "
                       "account page and tap Open "
                       "AdTrapper again.",
    "expired": "Your plan has run out. To renew, contact us:",
    "paused": "Your account is paused. To get going again, "
              "contact us:",
    "deleted": "This account was closed. Contact us:",
    "no_entitlement": "This account has no AdTrapper plan "
                      "yet. Contact us:",
    "machine_mismatch": "Every computer on this account is "
                        "already in use. Sign a computer "
                        "out on your account page, or "
                        "contact us:",
    "invalid_token": "This computer was signed out of the "
                     "account. Sign in again below, or "
                     "contact us:",
    "unreachable": "AdTrapper could not reach the sign-in "
                   "check and its offline time has run "
                   "out. Connect to the internet, or "
                   "contact us:",
    "invalid_request": "That sign-in is still "
                       "finishing. Wait a moment, then "
                       "tap Check again.",
    "request_expired": "That sign-in try ran out of "
                       "time. Tap Sign in and try "
                       "again.",
}


def signin_reason_words(reason, fallback="That did not work. "
                                         "Contact us:"):
    return SIGNIN_REASONS.get(reason or "", fallback)


def parse_handoff_url(url):
    """The hand-off token inside an adtrapper:// link,
    or "" when the link is not one of ours. Accepts the
    link exactly as the OS hands it over
    (adtrapper://handoff?t=<token>); anything else --
    another scheme, no token -- is not a hand-off and
    the caller falls through to the normal doors."""
    if not url or not isinstance(url, str):
        return ""
    try:
        from urllib.parse import parse_qs, urlparse
        parts = urlparse(url.strip())
        if parts.scheme != "adtrapper":
            return ""
        values = parse_qs(parts.query).get("t") or []
        return (values[0] or "").strip() if values else ""
    except Exception:
        return ""


# The key alphabet (portal keys.py): no 0/O/1/I/L, so a
# typed value can be told apart from a page code by
# shape alone -- the gate checks shapes locally BEFORE
# any server call (customer 1.3: a page code typed into
# the key door, or a key typed into the code door, is
# refused in plain words on the spot and nothing is
# sent anywhere).
KEY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _shape(value):
    return (value or "").replace("-", "").replace(" ", "").upper()


def looks_like_page_code(value):
    """True when the value is shaped like the sign-in
    page's one-time code: 8 alphabet characters, shown
    XXXX-XXXX (the dash is optional here)."""
    s = _shape(value)
    return len(s) == 8 and all(c in KEY_ALPHABET for c in s)


def looks_like_key(value):
    """True when the value is shaped like a license key:
    ADT-XXXX-XXXX-XXXX-XXXX (19 normalized characters),
    or the legacy AT + 15 form the relay still honors."""
    s = _shape(value)
    if s.startswith("ADT"):
        return len(s) == 19 and all(
            c in KEY_ALPHABET for c in s[3:])
    if s.startswith("AT"):
        return len(s) == 17 and all(
            c in KEY_ALPHABET for c in s[2:])
    return False


def match_code(request_id):
    """The sign-in MATCH CODE (gate round 2): SHA-256
    of the request id (UTF-8), the first six digest
    bytes each mapped mod len(KEY_ALPHABET) onto
    KEY_ALPHABET, shown XXX-XXX. The gate's waiting
    screen shows it big; the portal derives the same
    code for the approve page (its keys.match_code),
    and the customer approves only when the two
    match -- so a tricked approve of someone else's
    authorize link cannot silently sign a stranger's
    app into their account. A cross-check, never a
    credential: the request id stays the only secret.
    The portal's Python and the Android app's Dart
    carry the identical derivation; golden vectors
    pin all three alike."""
    digest = hashlib.sha256(
        (request_id or "").encode("utf-8")).digest()
    chars = "".join(KEY_ALPHABET[digest[i] % len(KEY_ALPHABET)]
                    for i in range(6))
    return chars[:3] + "-" + chars[3:]


def _license_https_context():
    """The TLS context for every call this module
    makes -- the relay check, the account door and
    the app-first poll door all ride
    _default_transport below.

    TLS REPAIR (2026-11-14, the step-zero round-2
    failure): on the owner's tech Mac every call
    the shipped module made failed verification
    (CERTIFICATE_VERIFY_FAILED) and the gate could
    only report "could not reach the sign-in
    check" -- while the portal itself answered a
    healthy host in half a second. The python.org
    Python the Mac bundle's launcher heads its
    list with loads NO CA certificates into the
    default context: its trust store is wired up
    only by python.org's one-time "Install
    Certificates" step, which had never run on
    that machine. The main program's own fetches
    were repaired for this exact cause on
    2026-10-25 (its _https_context); the license
    door never got the same repair. This helper
    builds the context by the same fallback chain
    and uses the first link that actually carries
    CA certificates:
      1. the default context (right on Windows,
         and on Macs whose Python was set up
         completely);
      2. /etc/ssl/cert.pem -- the macOS system
         bundle, present on every Mac even when
         Python's OpenSSL does not look there on
         its own;
      3. certifi's bundle, when certifi is
         importable.
    Verification is NEVER weakened: no CERT_NONE,
    no unverified context anywhere. If no link
    carries certificates, the default context is
    returned as-is and the call fails exactly as
    it did before this repair."""
    try:
        ctx = ssl.create_default_context()
        if ctx.get_ca_certs():
            return ctx
    except Exception:
        pass
    try:
        if os.path.exists("/etc/ssl/cert.pem"):
            ctx = ssl.create_default_context(
                cafile="/etc/ssl/cert.pem")
            if ctx.get_ca_certs():
                return ctx
    except Exception:
        pass
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        if ctx.get_ca_certs():
            return ctx
    except Exception:
        pass
    return ssl.create_default_context()


def _default_transport(url, payload, timeout=8):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout,
                                context=_license_https_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _user_state_path(app_dir):
    """Where the license state file rests
    (customer 1.4): the per-user data folder --
    ~/Library/Application Support/AdTrapper on a
    Mac, %LOCALAPPDATA%\\AdTrapper on Windows --
    never the folder the app itself lives in. A
    state file an older build left beside the app
    is copied across once, so a remembered sign-in
    carries over."""
    if platform.system() == "Darwin":
        base = os.path.join(os.path.expanduser("~"),
                            "Library",
                            "Application Support")
    elif platform.system() == "Windows":
        base = (os.environ.get("LOCALAPPDATA")
                or os.path.join(os.path.expanduser("~"),
                                "AppData", "Local"))
    else:
        base = os.path.join(os.path.expanduser("~"),
                            ".local", "share")
    new_path = os.path.join(base, "AdTrapper", STATE_FILE)
    legacy = os.path.join(app_dir, STATE_FILE)
    if not os.path.exists(new_path) and os.path.exists(legacy):
        try:
            os.makedirs(os.path.dirname(new_path),
                        exist_ok=True)
            tmp = new_path + ".tmp"
            with open(legacy, "rb") as fh:
                blob = fh.read()
            with open(tmp, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, new_path)
        except OSError:
            pass
    return new_path


class LicenseManager:
    def __init__(self, relay_url, state_path, transport=None, clock=None,
                 portal_url=None):
        self.relay_url = relay_url.rstrip("/")
        self.state_path = state_path
        self.transport = transport or _default_transport
        self.clock = clock or time.time
        self.portal_url = (portal_url or DEFAULT_PORTAL_URL).rstrip("/")
        self.machine = machine_id()

    @classmethod
    def from_env(cls, app_dir):
        relay = os.environ.get("ADTRAPPER_LICENSE_URL", DEFAULT_RELAY_URL)
        state = os.environ.get(
            "ADTRAPPER_LICENSE_STATE") or _user_state_path(app_dir)
        portal = os.environ.get("ADTRAPPER_PORTAL_URL",
                                DEFAULT_PORTAL_URL)
        return cls(relay, state, portal_url=portal)

    # -- local state --------------------------------------------------
    def _load(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _save(self, state):
        try:
            self._write_state(self.state_path, state)
        except OSError:
            # The state folder refused the write (the
            # read-only / translocated bundle of the
            # 2026-11-14 step-zero defect). Retry once
            # against the per-user data folder before
            # giving up -- a sign-in must not be lost
            # to a folder the app does not own.
            fallback = _user_state_path(os.path.dirname(
                os.path.abspath(self.state_path)))
            if os.path.abspath(fallback) == os.path.abspath(
                    self.state_path):
                raise
            self._write_state(fallback, state)
            self.state_path = fallback

    def _write_state(self, path, state):
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)

    def _log(self, line):
        try:
            log_path = os.path.join(
                os.path.dirname(os.path.abspath(self.state_path)),
                LOG_FILE)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write("%s %s\n" % (
                    time.strftime("%Y-%m-%d %H:%M:%S"), line))
        except Exception:
            pass

    # -- relay calls ------------------------------------------------------
    def _call(self, door, key):
        return self.transport(
            self.relay_url + door,
            {"key": key, "machine_id": self.machine})

    def activate(self, key):
        """First-run activation. Returns the relay's answer dict."""
        answer = self._call("/api/activate", key)
        if answer.get("ok"):
            self._save({
                "key": key,
                "machine_id": self.machine,
                "last_ok": self.clock(),
                "expires_at": answer.get("expires_at"),
                "grace_days": answer.get("grace_days", DEFAULT_GRACE_DAYS),
                "shop_contact": answer.get("shop_contact", ""),
            })
            self._log("activated; expires %s" % answer.get("expires_at"))
        return answer

    # -- website account door (11.29, portal SPEC section 6) --------
    def _portal_call(self, door, payload):
        return self.transport(self.portal_url + door, payload)

    def signed_in(self):
        """True when a website sign-in token is remembered here."""
        return bool(self._load().get("portal_token"))

    def _save_portal(self, answer, entitlement=None):
        """Merge the account door's truth into the local state.
        The raw token is stored ONLY here (the state file) --
        it is never passed to the log."""
        state = self._load()
        ent = entitlement or {}
        if answer.get("token"):
            state["portal_token"] = answer["token"]
        if answer.get("shop_name") is not None:
            state["portal_shop_name"] = answer.get("shop_name") or ""
        if answer.get("email") is not None:
            state["portal_email"] = answer.get("email") or ""
        if ent:
            state["portal_expires_at"] = ent.get("expires_at")
            state["portal_days_left"] = ent.get("days_left")
            state["portal_is_trial"] = bool(ent.get("is_trial"))
            state["portal_max_devices"] = ent.get("max_devices")
            state["portal_devices_used"] = ent.get("devices_used")
        if answer.get("offline_valid_until"):
            state["portal_offline_valid_until"] = \
                answer["offline_valid_until"]
        state["portal_last_ok"] = self.clock()
        self._save(state)
        return state

    def signin_exchange(self, code):
        """Trade the one-time code from the /authorize page for
        the remembered app token (POST /api/authorize). Returns
        the portal's answer dict; on success the token and the
        account's shop/plan truth are stored locally."""
        answer = self._portal_call("/api/authorize", {
            "code": (code or "").strip(),
            "machine_id": self.machine})
        if answer.get("ok") and answer.get("token"):
            self._save_portal(answer, answer.get("entitlement"))
            ent = answer.get("entitlement") or {}
            self._log("signed in: %s; %s; runs out %s" % (
                answer.get("shop_name") or "account",
                entitlement_words(ent), ent.get("expires_at")))
        return answer

    def handoff_exchange(self, raw):
        """Trade a one-click hand-off token for the
        remembered app token (POST /api/handoff,
        ONE-CLICK-SPEC section 2). The token arrived in
        an adtrapper:// link the account page minted for
        the signed-in customer; the portal burns it on
        this call and answers exactly like
        /api/authorize. On success the token and the
        account truth are stored exactly as the code
        door stores them. A refusal stores nothing."""
        answer = self._portal_call("/api/handoff", {
            "token": (raw or "").strip(),
            "machine_id": self.machine})
        if answer.get("ok") and answer.get("token"):
            self._save_portal(answer, answer.get("entitlement"))
            ent = answer.get("entitlement") or {}
            self._log("signed in via one-click hand-off: "
                      "%s; %s; runs out %s" % (
                          answer.get("shop_name") or "account",
                          entitlement_words(ent),
                          ent.get("expires_at")))
        return answer

    def authorize_start(self):
        """Ask the portal for a pending app-first sign-in
        request (POST /api/authorize/start). The answer
        carries the request_id and the authorize_url
        the app opens in the browser. The request id is
        a thirty-minute credential: the CALLER keeps it in
        memory only -- it is never stored or logged."""
        return self._portal_call("/api/authorize/start", {
            "machine_id": self.machine})

    def authorize_poll(self, request_id):
        """Poll one app-first sign-in request
        (POST /api/authorize/poll). Answers:
          {"ok": True, "status": "pending"} -- keep
              waiting;
          the /api/authorize success shape -- approved:
              the token and the account truth are
              stored exactly as the code door stores
              them;
          {"ok": False, ...} -- refused or expired;
          nothing is stored."""
        answer = self._portal_call("/api/authorize/poll", {
            "request_id": (request_id or "").strip(),
            "machine_id": self.machine})
        if answer.get("ok") and answer.get("token"):
            self._save_portal(answer, answer.get("entitlement"))
            ent = answer.get("entitlement") or {}
            self._log("signed in via app-first sign-in: "
                      "%s; %s; runs out %s" % (
                          answer.get("shop_name") or "account",
                          entitlement_words(ent),
                          ent.get("expires_at")))
        return answer

    def authorize_cancel(self, request_id):
        """Burn a pending app-first sign-in request
        (POST /api/authorize/cancel) -- the waiting
        screen's Cancel. Without it the request stayed
        live for anyone holding the link until its
        thirty minutes ran out. Best-effort by design: the
        gate fires this and moves on whether or not
        the portal answered; a request that never got
        cancelled still expires on its own. Answers
        the portal's one generic ok; stores nothing,
        logs nothing with the request id in it."""
        return self._portal_call("/api/authorize/cancel", {
            "request_id": (request_id or "").strip(),
            "machine_id": self.machine})

    def portal_token_hint(self):
        """The remembered sign-in token's value, or "".
        The activation gate compares it across its
        hand-off watch ticks to notice a sign-in landing
        in the shared state file while the gate is on
        screen. The value never leaves this machine and
        is never logged."""
        return self._load().get("portal_token") or ""

    def app_check(self):
        """POST /api/app-check with the remembered token. On a
        good answer the stored entitlement and the served
        offline deadline are refreshed. Transport failure
        raises, like _call -- callers decide what unreachable
        means."""
        state = self._load()
        token = state.get("portal_token")
        if not token:
            return {"ok": False, "reason": "no_token"}
        answer = self._portal_call("/api/app-check", {
            "token": token, "machine_id": self.machine})
        if answer.get("ok"):
            self._save_portal(answer, answer.get("entitlement"))
        return answer

    def sign_out(self):
        """Forget the website sign-in on THIS computer (the
        token is cleared locally; the account page / owner door
        owns server-side revocation, SPEC section 5). The key
        door's saved state is untouched. Returns True when a
        sign-in was actually cleared."""
        state = self._load()
        keys = [k for k in state if k.startswith("portal_")]
        if not keys:
            return False
        for k in keys:
            del state[k]
        self._save(state)
        self._log("signed out of the website account")
        return True

    def _portal_offline_status(self, state):
        """No answer from the site: the served deadline decides.
        Inside offline_valid_until the app is in grace; past it
        the app stops as run out -- the deadline already has the
        plan's expiry folded in (the server caps it), so this
        branch can never carry the app past expiry."""
        deadline = _iso_to_epoch(state.get("portal_offline_valid_until"))
        now = self.clock()
        if deadline and now <= deadline:
            return {"state": "grace", "door": "account",
                    "days_left": int((deadline - now) // 86400),
                    "expires_at": state.get("portal_expires_at"),
                    "shop_name": state.get("portal_shop_name", "")}
        return {"state": "needs_renewal", "reason": "unreachable",
                "door": "account",
                "shop_contact": state.get("shop_contact", "")}

    def _portal_status(self, state):
        """The token door's verdict, in startup_status words."""
        try:
            answer = self.app_check()
        except Exception:
            return self._portal_offline_status(state)
        if answer.get("ok"):
            ent = answer.get("entitlement") or {}
            return {"state": "licensed", "door": "account",
                    "shop_name": state.get("portal_shop_name", ""),
                    "plan_words": entitlement_words(ent),
                    "days_left": ent.get("days_left"),
                    "expires_at": ent.get("expires_at")}
        reason = answer.get("reason", "unknown")
        ent = answer.get("entitlement") or {}
        if reason == "invalid_token":
            # The site says this sign-in is dead (revoked, or
            # the account was deleted): forget it locally so
            # the next start goes straight to the sign-in ask.
            self.sign_out()
            return {"state": "needs_signin", "reason": reason,
                    "door": "account",
                    "shop_contact": state.get("shop_contact", "")}
        return {"state": "needs_renewal", "reason": reason,
                "door": "account",
                "plan_words": entitlement_words(ent) if ent else "",
                "days_left": ent.get("days_left"),
                "expires_at": ent.get("expires_at"),
                "shop_contact": state.get("shop_contact", "")}

    def background_check(self):
        """The periodic re-check (11.29): same doors, same words
        as startup_status, but the caller is the running app --
        the verdict is RECORDED in the local state and acted on
        at the next start; a scan already running is never
        interrupted (the license door's rule since day one).
        Only a bad verdict is logged, so the log stays thin."""
        state = self._load()
        if state.get("portal_token"):
            status = self._portal_status(state)
        elif state.get("key"):
            status = self.startup_status()
        else:
            return {"state": "needs_key"}
        if status["state"] not in ("licensed", "grace"):
            self._log("background check: %s (%s)" % (
                status["state"], status.get("reason", "")))
        return status

    def startup_status(self):
        """The one question the app asks before it opens.

        Returns {"state": ...} where state is one of:
          licensed       - relay says the key is good
          grace          - relay unreachable, still inside the
                           offline grace from the last good check
          needs_key      - nothing saved yet (first run)
          needs_signin   - a website sign-in was remembered but
                           the site says it is dead (revoked);
                           sign in again (account door only)
          needs_renewal  - relay says paused/expired/not ours, or
                           the grace ran out with no contact
        """
        state = self._load()
        if state.get("portal_token"):
            return self._portal_status(state)
        key = state.get("key")
        if not key:
            return {"state": "needs_key"}
        grace_days = int(state.get("grace_days", DEFAULT_GRACE_DAYS))
        try:
            answer = self._call("/api/check", key)
        except Exception:
            last_ok = float(state.get("last_ok") or 0)
            age = self.clock() - last_ok
            if last_ok and age <= grace_days * 86400:
                return {"state": "grace",
                        "days_left": grace_days - int(age // 86400),
                        "expires_at": state.get("expires_at")}
            return {"state": "needs_renewal", "reason": "unreachable",
                    "shop_contact": state.get("shop_contact", "")}
        if answer.get("ok"):
            state["last_ok"] = self.clock()
            state["expires_at"] = answer.get("expires_at")
            state["grace_days"] = answer.get("grace_days", grace_days)
            state["shop_contact"] = answer.get("shop_contact", "")
            self._save(state)
            return {"state": "licensed",
                    "expires_at": answer.get("expires_at")}
        return {"state": "needs_renewal",
                "reason": answer.get("reason", "unknown"),
                "expires_at": answer.get("expires_at"),
                "shop_contact": answer.get("shop_contact", "")}
