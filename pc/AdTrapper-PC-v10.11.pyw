#!/usr/bin/env python3
"""
AdTrapper -- Malware & Adware Scanner
Copyright (c) 2026 iFixx Repairs, Englewood, Florida. All rights reserved.
Adware/malware detector and remover for Android phones.

Just double-click this file.
  1. Plug the customer's phone into the computer with USB.
  2. On the phone: enable Developer options > USB debugging, then tap
     "Allow" on the USB debugging prompt.
  3. Click SCAN. Tick what to remove, or hit REMOVE ALL. Done.

Detection: weighted red-flag scoring (sideloaded apps, device admins,
accessibility abuse, popup permission, hidden icons, never-opened apps,
junk-name patterns, known junk, boot autostart) plus a browser-notification
site list for the cases where no app is behind the popups.
Extras: privacy audit (SMS/contacts/location/mic/camera access), APK backup
before every removal, one-tap UNDO, BLOCK POPUPS (revoke overlay permission
without uninstalling), disable-app fallback when uninstall is blocked.

Needs: Python 3 + the platform-tools folder downloaded (this script finds
adb by itself in the usual spots).
"""

import os
import uuid
import hmac
import hashlib
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk

if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(
            ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass
from tkinter import messagebox, ttk
from datetime import datetime, timedelta, date
from math import cos, sin, pi
from pathlib import Path
import json
import urllib.request

# --- hide the black console window on Windows; the GUI is the interface ---
if sys.platform == "win32":
    try:
        import ctypes
        _hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if _hwnd:
            ctypes.windll.user32.ShowWindow(_hwnd, 0)
    except Exception:
        pass

# ------------------------------------------------------------------ core ---

# App NAMES confirmed as junk in shop testing (exact label match, any
# package) -- for offenders whose package id hides or varies by variant.
# Both shop-tested on Duncan's A16, 2026-10-12.
KNOWN_BAD_LABELS = {"chore focus"}
KNOWN_BAD_LABEL_PREFIXES = ("phone clear", "phone cleaner")

# Packages confirmed as junk in shop testing -- always flagged.
# Bundled baseline synchronized with server/blocklist.json (125 entries).
KNOWN_BAD = {
    "antivirus.anti.virus.applock.protection.vpn",
    "antivirus.virus.cleaner.clean.vpn.booster",
    "app.luckymoneygames",
    "appicon.diy.tools.prop",
    "call.recorder.automatic.acr",
    "casinoplus.pindo3",
    "cleaner.clean.booster",
    "com.MoneyBingo.LuckyRewards.CashGame.BigWinner",
    "com.Solitaire.Card.MoneyGame.CashRewards",
    "com.againstvirus.flux",
    "com.androidneonkeyboard.app",
    "com.anti.virus.security",
    "com.antivirus.cleaner.supersecurity",  # Super Security (PC-caught, shop-filmed 2026-10-13)
    "com.antivi.shield.loish",
    "com.applabstudios.ai.mail.homescreen.inbox",  # Easy Mail (gauntlet test app)
    "com.arcfolio.pdf.mrrmfo",  # Arcfolio PDF (Duncan pen-test)
    "com.aviator.aviatorgamejamantech2",
    "com.bat.batsaver",
    "com.benjaminone.client",
    "com.bingo.games.bingo.offline.win.cash",
    "com.blue.deep.cleaner",
    "com.boost.clean",
    "com.burakgon.gamebooster3",
    "com.cachecleanereasytool.app",
    "com.caller.theme.slow",
    "com.callercallwallpaper.app",
    "com.callertheme.firstref",
    "com.capcut.capvideoeditorapp58",
    "com.chorefocus.app",  # Chore Focus (shop-tested 2026-10-12)
    "com.clea.mas.pro",
    "com.clean.maestro.security.speed.booster",
    "com.clean.mix.junk",
    "com.cleaner.phone.junk.files",
    "com.dl.guard.lock",
    "com.dmstudio.weather",
    "com.fancyanimatedbattery.app",
    "com.fastcleanercashecleaner.app",
    "com.flash.booster.Cleaner",
    "com.flintos.capcut2",
    "com.funnycallercustomtheme.app",
    "com.funnywallpapaerslive.app",
    "com.g19mobile.gamebooster",
    "com.godwin.applehealth2",
    "com.godwin.applepay3",
    "com.grouprx.pureanti",
    "com.hello.miheapp.secretspace",
    "com.hld.anzenbokusucal",
    "com.intelli.clean",
    "com.intelligent.heimlich.tool",
    "com.junkeraser.clean",
    "com.keli.imessage3",
    "com.keli.siriapp1",
    "com.lagofast.mobile.acclerater",
    "com.learned.guard.jildo",  # MiraClean (gauntlet test app)
    "com.lionmobi.powerclean",
    "com.m24apps.acr",
    "com.mbkristine8.cleanmaster",
    "com.mhd.zelleapp2",
    "com.mobile.applock.en",
    "com.mobile.applock.wt",
    "com.mycallcallpersonalization.app",
    "com.mycallcustomcallscrean.app",
    "com.neonthemekeyboard.app",
    "com.newscrean4dwallpapers.app",
    "com.notesreminderslists.app",
    "com.novabrain.tool.cleanboost",
    "com.papaya.bingocash.play",
    "com.papaya.solitairecash.play",
    "com.paypal.wallawalled11",
    "com.pdfsprint.viewer.vertigerdig",
    "com.phcleanquickly.cleanplus",  # Quick Clean Plus (gauntlet test app)
    "com.planb.cleaner",
    "com.premkumar.zelleapp2",
    "com.premkumar.zelleapp5",
    "com.procleaner.clean",
    "com.react.fallguysgame1",
    "com.react.gta6game1",
    "com.rockskinthemes.app",
    "com.sas.virus.cleaner.antivirus.unusedapps",
    "com.sec.reclean",  # SecureClean variant (USB-cable verified 2026-10-13)
    "com.second.space",
    "com.shahdi.imessage2",
    "com.shahdi.siri1",
    "com.shahdi.siri2",
    "com.sitaram.robloxgame1",
    "com.sitaram.robloxgame3",
    "com.smartnettools.studio.easyclean",
    "com.sp.protector.free",
    "com.spaceclean.quickcleaner",
    "com.sr.clear2.jb",  # Phone Clear / AI Clean Storage cleaner (Galaxy Store, shop-tested 2026-10-12)
    "com.stg.plus.win.real.money.cash.app",
    "com.storage.androidcleaner",
    "com.tf.phonecleaner.booster",
    "com.trpz.travel",
    "com.ultimate.cleanerpro.ucp",
    "com.westhorizont.appsforge.filehorizon_explorereaddocuments",
    "com.winde.apex",
    "com.winrgames.solitaire",
    "com.works.amazing.colour",
    "com.zelleapp.devnexus2",
    "de.andromo.ssfiftylivesixcc",
    "de.fiftyninecamera.rollredactor",
    "de.hitopgop.sixtyeightgx",
    "de.instgang.fiftyggfife",
    "de.nineergysh.quickarttwo",
    "de.photoground.twentysixshot",
    "de.sixtyonecollice.cameraroll",
    "de.stockeighty.onewallpapers",
    "de.xnano.photoexifeditornine",
    "gb.artfilter.tenvarnist",
    "gb.crazykey.sevenboard",
    "gb.painnt.moonlightingnine",
    "gb.twentynine.redaktoridea",
    "helectronsoft.com.grubl.live.wallpapers3d",
    "huwaei.health1",
    "il.co.smedia.callrecorder.yoni",
    "live.weather.vitality.studio.forecast.widget",
    "mtr.cpumonitor.temperature",
    "myfiles.filemanager.fileexplorer.cleaner",
    "netflixgamecontroller.uzair1",
    "netflixgamecontroller.uzair2",
    "picturetranslate.extractor.text.lite",
    "vault.gallery.lock",
    "ws.clockthevault",
    "xboxgame.abdul2",
}

# Installers that count as legitimate app stores.
STORES = {
    "com.android.vending": "Play Store",
    "com.sec.android.app.samsungapps": "Galaxy Store",
    "com.amazon.venezia": "Amazon Appstore",
    "com.huawei.appmarket": "AppGallery",
}
TRANSFER = {
    "com.sec.android.easyMover": "Smart Switch transfer",
    "com.google.android.apps.restore": "Google restore",
}
CARRIER = re.compile(r"^com\.(dti|att|tmobile|verizon|vzw|sprint|uscellular|motricity|ironsrc\.aura)\b")

# Junk-name pattern (cleaner/booster/shield-type utility disguises).
# ------------------------- licensing -------------------------
# Hardware-locked license keys. Duncan generates keys with keygen.py.
# !!! CHANGE THIS SECRET BEFORE SELLING - keep it private !!!
_LICENSE_SECRET = b"deceptacon-licensing-v1-d5e9fd4b5e59153fa82022f985378404"

def get_hwid():
    """Stable hardware ID for this PC (12 hex chars, grouped)."""
    raw = "%s-%s-%s" % (uuid.getnode(), platform.node(), platform.machine())
    digest = hashlib.sha256(raw.encode()).hexdigest().upper()
    h = digest[:12]
    return "%s-%s-%s" % (h[0:4], h[4:8], h[8:12])

def _b32_noconfuse(data):
    """Base32 without confusing chars (0/O, 1/I/L)."""
    import base64
    s = base64.b32encode(data).decode().rstrip("=")
    return s.replace("0", "X").replace("1", "Y")

def make_license_key(hwid, days_valid=365):
    """Duncan's keygen logic (mirrored in keygen.py)."""
    import time
    expiry = int(time.time()) + days_valid * 86400 if days_valid > 0 else 0
    payload = "%s|%d" % (hwid.replace("-", ""), expiry)
    sig = hmac.new(_LICENSE_SECRET, payload.encode(),
                   hashlib.sha256).digest()
    key = _b32_noconfuse(sig)[:16]
    return "%s-%s-%s-%s" % (key[0:4], key[4:8], key[8:12], key[12:16]), expiry

def validate_license_key(hwid, key):
    """Returns (valid, expiry_timestamp). Checks all reasonable expiries."""
    import time
    clean = key.replace("-", "").replace(" ", "").upper()
    if len(clean) != 16:
        return False, 0
    # Try perpetual (expiry=0) and day-boundary expiries (keygen uses midnight UTC)
    now = int(time.time())
    day_start = now - (now % 86400)
    hwid_c = hwid.replace("-", "")
    candidates = [0] + [day_start + d * 86400 for d in range(1, 1826)]
    for expiry in candidates:
        payload = "%s|%d" % (hwid_c, expiry)
        sig = hmac.new(_LICENSE_SECRET, payload.encode(),
                       hashlib.sha256).digest()
        expect = _b32_noconfuse(sig)[:16]
        if hmac.compare_digest(expect, clean):
            return True, expiry
    return False, 0

def _license_path():
    return _script_dir_path() / "popup_defender_license.json"

def load_license():
    try:
        with open(_license_path()) as f:
            d = json.load(f)
        ok, exp = validate_license_key(get_hwid(), d.get("key", ""))
        if ok:
            return d["key"], exp
    except Exception:
        pass
    return None, 0

def save_license(key):
    try:
        with open(_license_path(), "w") as f:
            json.dump({"key": key}, f)
    except Exception:
        pass
# ----------------------- end licensing -----------------------

# ------------------------------------------------- shop / report branding ---
SHOP_NAME = "iFixx Repairs"
SHOP_TAGLINE = "PHONE & DEVICE REPAIR"
SHOP_ADDRESS = "2828 S McCall Rd Unit 346, Englewood, FL 34224"
SHOP_PHONE = "(941) 875-7511"
SHOP_WEB = "ifixxrepairs.com"
APP_NAME = "AdTrapper"
VERSION = "10.11"
REPORT_TITLE = "PHONE CLEANUP REPORT"

# Known remote-access / screen-sharing apps. After a bank fraud, this is
# the row the bank looks for: could a stranger see or drive this phone?
REMOTE_ACCESS_PACKAGES = {
    "com.anydesk.anydeskandroid", "com.teamviewer.remote",
    "com.teamviewer.host", "com.teamviewer.quicksupport.market",
    "com.logmein.rescue", "com.splashtop.remote", "com.realvnc.viewer",
    "com.microsoft.rdc.androidx", "com.google.chromeremotedesktop",
    "com.zoho.assist", "com.getscreen.me", "com.ammyy.admin",
    "com.rustdesk.rustdesk", "com.duowan.kiwi", "air.net.aisaac.app",
}


def report_remote_access(threats):
    """Remote-access / screen-sharing verdict for the cleanup report.

    Clean -> "" (the checked table prints "None found - normal").
    Found -> names the app(s): a flagged row when one of the threats is
    a remote-access package, otherwise an accessibility-abuse fallback
    (screen-sharing scams ride accessibility when no known package is
    present).
    """
    hits = []
    for label, pkg, reasons, verdict in threats:
        if str(pkg or "").lower() in REMOTE_ACCESS_PACKAGES:
            hits.append(str(label or pkg))
    if hits:
        return "Found: " + ", ".join(hits[:3])
    if any("accessibility" in _reasons_str(r).lower()
           for _l, _p, r, _v in threats):
        return ("An app abused accessibility - see above (can be used "
                "to watch this screen)")
    return ""


# What the scanner checks, in plain customer English.
SCAN_FEATURES = (
    ("Every installed app",
     "scored for adware signals: fake cleaner, booster and PDF names; "
     "hidden app icons; pop-up (overlay) permission; device-admin abuse; "
     "accessibility abuse; auto-start on boot; sideloaded from outside "
     "the Play Store; apps never opened."),
    ("Known-malware blocklist",
     "%d threat packages from our daily threat-intel feed, plus anything "
     "this shop has flagged before."),
    ("Browser notification senders",
     "websites allowed to pop up notifications in Chrome, Samsung "
     "Internet and Firefox."),
    ("Privacy audit",
     "apps that can read your SMS, contacts, location, microphone "
     "or camera."),
    ("App sources",
     "where each app came from: Play Store, Galaxy Store, sideloaded, "
     "or preinstalled."),
)

STAY_SAFE_TIPS = (
    'If a website asks to "Allow notifications", tap Block or Don\'t allow.',
    'Never install a "cleaner", "booster", or "PDF" app from a pop-up ad.',
    "In free games, close ads with the small X \u2014 don't tap the ad itself.",
    "Pop-ups again? Don't tap anything in them \u2014 call us and we'll take a look.",
)

# Small iFixx logo JPG for the report header (base64). Written to a temp
# file on first use so the script stays single-file.
LOGO_B64 = "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"

# Virus-monsters cutout (no background) for the report header (base64).
MONSTERS_B64 = "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"


def _report_monsters_path():
    import base64 as _b64
    import tempfile as _tf
    try:
        p2 = os.path.join(_tf.gettempdir(), "popup_monsters_cutout.png")
        if not os.path.isfile(p2):
            with open(p2, "wb") as f:
                f.write(_b64.b64decode(MONSTERS_B64))
        return p2
    except Exception:
        return None



def _report_logo_path():
    import base64 as _b64
    import tempfile as _tf
    try:
        p = os.path.join(_tf.gettempdir(), "ifixx_report_logo.jpg")
        if not os.path.isfile(p):
            with open(p, "wb") as f:
                f.write(_b64.b64decode(LOGO_B64))
        return p
    except Exception:
        return None


def _reasons_str(r):
    if isinstance(r, (list, tuple)):
        return "; ".join(str(x) for x in r)
    return str(r or "")


def _t(s):
    """Make text safe for the PDF's core (latin-1) fonts."""
    t = str(s or "")
    t = (t.replace("\u2022", "-").replace("\u2192", "->")
          .replace("\u2014", "-").replace("\u2013", "-")
          .replace("\u2018", "'").replace("\u2019", "'")
          .replace("\u201c", '"').replace("\u201d", '"')
          .replace("\u2026", "...").replace("\u26a0", "!"))
    return t.encode("latin-1", "replace").decode("latin-1")


def generate_customer_report(device_info, threats, actions_taken, sites,
                             scan_summary, save_dir, blank=False):
    """Build the iFixx Repairs phone cleanup report PDF.

    device_info: {"model", "android", "serial"}
    threats: [(label, pkg, reasons, verdict)] -- reasons may be list or str
    actions_taken: [(label, action_str)]
    sites: [(date_str, host)] notification senders found
    scan_summary: {"apps": N scanned, "overlay": n, "admin": n, "a11y": n}
    blank: True -> printable hand-fillable template (empty fields/rows)
    Returns the PDF path, or None if the PDF lib is missing.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        return None
    import time

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    W = 190.0

    def rule(w=1.0):
        pdf.set_draw_color(0, 0, 0)
        pdf.set_line_width(w)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)

    def section_title(t):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, t.upper(), new_x="LMARGIN", new_y="NEXT")

    def black_header(cols):
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(0, 0, 0)
        pdf.set_text_color(255, 255, 255)
        for w_, txt in cols:
            pdf.cell(w_, 6, " " + txt, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln()

    def thin_line():
        pdf.set_draw_color(150, 150, 150)
        pdf.set_line_width(0.2)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())

    def wrap_lines(txt, width_mm, max_lines=3):
        # Greedy wrap in the CURRENT font. Unbroken tokens (package
        # names) are pre-split after '.' so they break at dots instead
        # of being cut off mid-word.
        toks = []
        for wd in str(txt).split(" "):
            while pdf.get_string_width(wd) > width_mm and len(wd) > 1:
                cut = -1
                for i, ch in enumerate(wd):
                    if pdf.get_string_width(wd[:i + 1]) > width_mm:
                        break
                    if ch == ".":
                        cut = i
                if cut < 0:
                    n = 1
                    while n < len(wd) and \
                            pdf.get_string_width(wd[:n + 1]) <= width_mm:
                        n += 1
                    cut = n - 1
                toks.append(wd[:cut + 1])
                wd = wd[cut + 1:]
            toks.append(wd)
        lines, cur = [], ""
        for wd in toks:
            trial = (cur + " " + wd) if cur else wd
            if pdf.get_string_width(trial) <= width_mm or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = wd
                if len(lines) >= max_lines:
                    return lines
        if cur:
            lines.append(cur)
        return lines[:max_lines] or [""]

    def draw_row(cells, lh=6.5):
        # cells: [(width_mm, text, bold)] at font size 9; wraps text so
        # long app / package names are never truncated.
        parts = []
        n = 1
        for w_, txt, bold in cells:
            pdf.set_font("Helvetica", "B" if bold else "", 9)
            ls = wrap_lines(" " + str(txt), w_ - 2)
            parts.append((w_, ls, bold))
            n = max(n, len(ls))
        if pdf.get_y() + lh * n > 278:
            pdf.add_page()
        y0 = pdf.get_y()
        x = 10.0
        for w_, ls, bold in parts:
            pdf.set_font("Helvetica", "B" if bold else "", 9)
            for i, ln in enumerate(ls):
                pdf.set_xy(x, y0 + i * lh)
                pdf.cell(w_, lh, _t(ln))
            x += w_
        pdf.set_xy(10, y0 + lh * n)
        thin_line()

    def short_threat(reason):
        r = _reasons_str(reason).lower()
        if "known-bad" in r or "known malware" in r or "blocklist" in r:
            return "Confirmed malware"
        if "home app" in r or "launcher hijack" in r:
            return "Hijacked the home screen"
        if "device admin" in r:
            return "Abused device admin to resist removal"
        if "accessibility" in r:
            return "Abused accessibility service"
        if "overlay" in r or "draw over" in r:
            return "Popup adware"
        if "pdf" in r:
            return "Fake PDF app"
        if "cleaner" in r or "booster" in r:
            return "Fake cleaner/booster app"
        if "sideloaded" in r:
            return "Suspicious sideloaded app"
        if "hidden" in r or "no app icon" in r or "no icon" in r:
            return "Hidden app (no icon)"
        if "boot" in r:
            return "Auto-starts on boot"
        txt = _reasons_str(reason).strip()
        return txt[:55] if txt else "Flagged by scan"

    def short_action(act):
        a = str(act or "").lower()
        if "could not" in a:
            return "Could not remove - needs manual step"
        if "device admin stripped" in a:
            return "Removed (admin stripped)"
        if "uninstall" in a or "removed" in a:
            return "Uninstalled"
        if "disabl" in a:
            return "Disabled"
        if "block" in a:
            return "Blocked"
        return str(act or "")[:40]

    # ---- header: logo + shop left, monsters beside the title ----
    y_top = pdf.get_y()
    logo = _report_logo_path()
    if logo:
        try:
            pdf.image(logo, x=10, y=y_top, w=24)
        except Exception:
            logo = None
    tx = 38 if logo else 10
    pdf.set_xy(tx, y_top + 1)
    pdf.set_font("Helvetica", "B", 17)
    pdf.cell(80, 9, SHOP_NAME)
    pdf.set_xy(tx, y_top + 10)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(80, 5, SHOP_TAGLINE)
    pdf.set_xy(tx, y_top + 15)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.cell(88, 5, SHOP_ADDRESS)
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(104, y_top + 2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(56, 7, APP_NAME.upper(), align="R")
    pdf.set_xy(104, y_top + 9)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(56, 6, REPORT_TITLE, align="R")
    monsters = _report_monsters_path()
    if monsters:
        try:
            pdf.image(monsters, x=163, y=y_top, w=37)
        except Exception:
            monsters = None
    pdf.set_xy(10, y_top + 21)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(190, 5, "Service date: %s"
             % time.strftime("%B %d, %Y - %I:%M %p"), align="R")
    pdf.set_y(y_top + 28)
    rule(1.2)

    # ---- device info grid ----
    cols = ("DEVICE", "ANDROID", "SERIAL", "CUSTOMER", "TICKET NO.")
    col_w = W / 5
    pdf.set_font("Helvetica", "B", 8)
    for i, c in enumerate(cols):
        border = "LTR" if i < 4 else "LTR"
        pdf.cell(col_w, 5, c, border=border,
                 new_x="RIGHT" if i < 4 else "LMARGIN", new_y="TOP")
    pdf.ln()
    vals = [device_info.get("model", ""),
            device_info.get("android", ""),
            device_info.get("serial", ""),
            device_info.get("customer", ""),
            device_info.get("ticket", "")]
    if blank:
        vals = ["", "", "", "", ""]
    pdf.set_font("Helvetica", "", 9)
    for i, v in enumerate(vals):
        txt = (v or "")[:19]
        if i in (3, 4) and not txt:
            txt = "__________________"
        pdf.cell(col_w, 7, _t(txt), border="LBR",
                 new_x="RIGHT" if i < 4 else "LMARGIN", new_y="TOP")
    pdf.ln()
    pdf.ln(4)

    # ---- result box ----
    def result_text():
        n_found = len(threats)
        n_sites = len(sites)
        n_removed = sum(1 for _, a in actions_taken
                        if "could not" not in str(a).lower())
        if n_found == 0 and n_sites == 0:
            return ("No threats were found on this device. It is clean. "
                    "Your apps, permissions and notification senders were "
                    "all reviewed.")
        if n_found and n_removed == n_found and n_sites == 0:
            return ("The pop-ups have been stopped. We found and removed "
                    "%d unwanted app(s) that were causing them." % n_found)
        if n_found and n_sites == 0:
            return ("We found %d unwanted app(s). %d were removed; the rest "
                    "need a manual step (see below)." % (n_found, n_removed))
        if n_found == 0:
            return ("No bad apps were found, but %d website(s) were allowed "
                    "to send pop-up notifications. Follow the cleanup steps "
                    "below to remove them." % n_sites)
        return ("We found and removed %d unwanted app(s), and found %d "
                "website(s) allowed to send pop-up notifications "
                "(cleanup steps below)." % (n_removed, n_sites))

    pdf.set_fill_color(0, 0, 0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(25, 6, "  RESULT", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    x0, y0 = pdf.get_x(), pdf.get_y()
    pdf.set_xy(x0 + 2, y0 + 2)
    if blank:
        pdf.set_font("Helvetica", "", 10)
        for _ in range(3):
            pdf.cell(W - 4, 7, "_" * 88, new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(x0 + 2)
    else:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(W - 4, 6, _t(result_text()))
    y1 = pdf.get_y() + 2
    pdf.rect(10, y0, W, y1 - y0)
    pdf.set_xy(10, y1)
    pdf.ln(4)

    # ---- certification line (this paper goes to banks / records) ----
    if not blank:
        pdf.set_font("Helvetica", "", 9)
        _cert = ("This report documents an inspection and cleanup of the "
                 "device above by %s on %s."
                 % (SHOP_NAME, time.strftime("%B %d, %Y")))
        _tick = str(device_info.get("ticket", "") or "").strip()
        if _tick:
            _cert += " Service ticket: %s." % _tick
        _cert += (" It was prepared at the customer's request for their "
                  "own records, including for their bank.")
        pdf.multi_cell(W, 5.5, _t(_cert))
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(W, 5.5, _t(
            "Privacy: we did not open, copy, or access your messages, "
            "photos, or accounts. This inspection checks apps and "
            "permissions only."))
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(W, 5.5, _t(
            "Scope: this report covers the inspection on the date "
            "shown. It is not a guarantee against future infections."))
        pdf.ln(2)

    # ---- what it scanned for ----
    section_title("What it scanned for")
    pdf.set_font("Helvetica", "", 9)
    feats = []
    _threat_n = scan_summary.get("threat_count") or len(KNOWN_BAD)
    for lead, desc in SCAN_FEATURES:
        if "%d" in desc:
            try:
                desc = desc % int(_threat_n)
            except Exception:
                pass
        feats.append((lead, desc))
    for lead, desc in feats:
        x0 = pdf.get_x()
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(5, 5.5, "-")
        pdf.set_font("Helvetica", "B", 9)
        pdf.write(5.5, lead + " - ")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5.5, _t(desc))
        pdf.set_x(10)
    n_apps = scan_summary.get("apps", 0) if scan_summary else 0
    if n_apps and not blank:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "%d apps on this phone were individually checked." % n_apps,
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # ---- what we found and fixed ----
    rows = []
    if not blank:
        action_map = {lbl: act for lbl, act in actions_taken}
        for label, pkg, reasons, verdict in threats:
            rl = _reasons_str(reasons).lower()
            lbl = str(label or "").lower()
            area = "Installed app"
            if "home app" in rl or "launcher" in rl:
                area = "Fake launcher"
            elif "pdf" in lbl or "pdf" in rl:
                area = "Fake PDF app"
            elif "cleaner" in lbl or "booster" in lbl:
                area = "Fake cleaner"
            found_txt = ("%s - %s" % (label, short_threat(reasons).lower()))
            act = action_map.get(label, action_map.get(pkg, "Reviewed"))
            rows.append((area, found_txt, short_action(act)[:70]))
    if blank or rows:
        section_title("What we found and fixed")
        black_header([(42, "AREA"), (73, "WHAT WE FOUND"), (75, "WHAT WE DID")])
        show_rows = rows if rows else [("", "", "")] * 5
        for area, found, did in show_rows:
            draw_row([(42, area, True), (73, found, False),
                      (75, did, True)])
        pdf.ln(3)

    # ---- notification senders ----
    if not blank and sites:
        section_title("Websites allowed to send pop-ups")
        black_header([(120, "WEBSITE"), (70, "ALLOWED SINCE")])
        for dstr, host in sites[:20]:
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(120, 6, _t(" " + str(host)[:60]))
            pdf.cell(70, 6, " " + str(dstr),
                     new_x="LMARGIN", new_y="NEXT")
            thin_line()
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 5.5, "These were listed in the app with cleanup "
                               "steps - remove them in your browser's "
                               "notification settings.")
        pdf.ln(3)

    # ---- apps removed ----
    if blank or actions_taken:
        section_title("Apps removed")
        black_header([(70, "APP"), (120, "WHY IT WAS REMOVED")])
        if blank:
            for _ in range(6):
                pdf.cell(70, 7, "", border="B")
                pdf.cell(120, 7, "", border="B",
                         new_x="LMARGIN", new_y="NEXT")
        else:
            for label, act in actions_taken:
                why = ""
                for t_lbl, _pkg, reasons, _v in threats:
                    if t_lbl == label:
                        why = short_threat(reasons)
                        break
                draw_row([(70, str(label), True), (120, why, False)])
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5.5, "Every removed app was backed up first "
                                   "and can be restored with the UNDO button.")
        pdf.ln(3)

    # ---- checked, no problems ----
    section_title("Checked - no problems found")
    black_header([(70, "CHECK"), (120, "RESULT")])
    if blank:
        checks = [("Apps with pop-up (overlay) permission", ""),
                  ("Device administrator apps", ""),
                  ("Accessibility services in use", ""),
                  ("Websites allowed to send notifications", ""),
                  ("Remote-access / screen-sharing apps", "")]
    else:
        def res(n, noun):
            return ("%d flagged - see above" % n) if n else \
                ("None found - normal")
        checks = [
            ("Apps with pop-up (overlay) permission",
             res(scan_summary.get("overlay", 0), "overlay")),
            ("Device administrator apps",
             res(scan_summary.get("admin", 0), "admin")),
            ("Accessibility services in use",
             res(scan_summary.get("a11y", 0), "a11y")),
            ("Websites allowed to send notifications",
             res(len(sites), "sites")),
            ("Remote-access / screen-sharing apps",
             report_remote_access(threats) or "None found - normal"),
        ]
    for chk, r in checks:
        draw_row([(70, chk, True), (120, r, False)])
    pdf.ln(4)

    # ---- how to stay safe ----
    if pdf.get_y() > 225:  # keep the whole box on one page
        pdf.add_page()
    pdf.set_fill_color(0, 0, 0)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(45, 6, "  HOW TO STAY SAFE", fill=True,
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    x0, y0 = pdf.get_x(), pdf.get_y()
    pdf.set_xy(x0 + 3, y0 + 2)
    pdf.set_font("Helvetica", "", 9)
    for t in STAY_SAFE_TIPS:
        pdf.cell(5, 6, "-")
        pdf.multi_cell(W - 13, 6, _t(t))
        pdf.set_x(x0 + 3)
    y1 = pdf.get_y() + 2
    pdf.rect(10, y0, W, y1 - y0)
    pdf.set_xy(10, y1)
    pdf.ln(6)

    # ---- footer ----
    rule(0.6)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(95, 6, SHOP_ADDRESS)
    pdf.cell(95, 6, "%s \u00b7 %s" % (SHOP_PHONE, SHOP_WEB),
             new_x="LMARGIN", new_y="NEXT", align="R")
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 4, "\u00a9 2026 iFixx Repairs. All rights reserved. "
                   "AdTrapper is a product of iFixx Repairs.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10)
    _tech = str(device_info.get("technician", "") or "").strip()
    if blank or not _tech:
        pdf.cell(95, 6, "Technician: ____________________")
    else:
        pdf.cell(95, 6, _t("Technician: " + _tech[:28]))
    pdf.cell(95, 6, "Customer: ____________________",
             new_x="LMARGIN", new_y="NEXT")

    os.makedirs(save_dir, exist_ok=True)
    _tickf = re.sub(r"[^A-Za-z0-9-]+", "",
                    str(device_info.get("ticket", "") or "").strip())
    if blank:
        fname = "PhoneCleanup_BLANK.pdf"
    elif _tickf:
        fname = "cleanup-report-%s.pdf" % _tickf
    else:
        fname = "PhoneCleanup_%s.pdf" % time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(save_dir, fname)
    pdf.output(path)
    return path

def _script_dir_path():
    return Path(sys.argv[0]).parent


def _load_local_bad():
    """Packages this shop has removed before - learned, never miss again."""
    try:
        with open(_script_dir_path() / "learned_bad.json") as f:
            return set(json.load(f))
    except Exception:
        return set()

def _save_local_bad(pkgs):
    try:
        path = _script_dir_path() / "learned_bad.json"
        existing = _load_local_bad()
        with open(path, "w") as f:
            json.dump(sorted(existing | set(pkgs)), f)
    except Exception:
        pass

LEARNED_BAD = _load_local_bad()

def _load_blocklist_feed():
    """Load threat feed from local blocklist.json or cached feed if present,
    merging into KNOWN_BAD so PC scanner stays in sync with server/blocklist.json."""
    candidates = [
        _script_dir_path() / "blocklist.json",
        _script_dir_path().parent / "server" / "blocklist.json",
    ]
    for c in candidates:
        if c.is_file():
            try:
                with open(c, encoding="utf-8") as f:
                    data = json.load(f)
                pkgs = data.get("packages", [])
                if pkgs:
                    return set(pkgs)
            except Exception:
                pass
    return set()

KNOWN_BAD.update(_load_blocklist_feed())

# Legitimate home apps (system launchers) - never flagged as hijackers
TRUSTED_LAUNCHERS = {
    "com.sec.android.app.launcher",      # Samsung One UI Home
    "com.google.android.apps.nexuslauncher",  # Pixel Launcher
    "com.android.launcher3",             # AOSP Launcher
    "com.mi.android.globallauncher",     # MIUI
}

# First-party package prefixes whose apps are never flagged by heuristics.
# Matches lib/services/app_scanner.dart in the Android app (Hard Rule #3).
FIRST_PARTY_PREFIXES = (
    "com.google.",
    "com.samsung.",
    "com.sec.",
    "com.adobe.",
    "com.amazon.",
    "com.microsoft.",
    "com.miui.",
    "com.oneplus.",
    "com.motorola.",
    "com.android.",
    "android.",
    "com.qualcomm.",
    "com.mediatek.",
    "org.chromium.",
    "com.skms.",
)
WEBAPK_PREFIX = "org.chromium.webapk."

# Legitimate apps never flagged, even if the name looks "junky"
TRUSTED_PKGS = {
    "com.adobe.reader",              # Adobe Acrobat Reader
    "com.foxit.mobile.pdf.lite",     # Foxit PDF Reader
    "com.google.android.apps.docs",  # Google Drive (PDF viewer)
}

JUNK_RE = re.compile(
    r"clean|boost|junk|cooler|antivirus|virus|shield|guard|battery|flashlight|torch|"
    r"applock|qrcode|qrscan|wallpaper|weather|launcher|optimi[sz]|speed|phonemaster|"
    r"vpn|antispy|phonecare|ramclean|cpucool|"
    r"pdfreader|pdfviewer|pdfupdate|clarifypdf|pdf|adblock|adremov|"
    r"adblocker|ad\s*remov|doc\s*reader|document\s*reader", re.I)

PKG_RE = r"[a-zA-Z][\w]*(?:\.[\w]+)+"

# Permissions worth flagging in the privacy audit.
# Ad / tracking networks whose components are declared inside an app's
# manifest (visible in dumpsys). One network in a free app is normal
# monetization; a stack of them - or an aggressive one - is how "free"
# games and tools hide pop-up machines. AGGRESSIVE = repeatedly caught
# serving ads OUTSIDE their host app.
AD_SDKS = {
    "Google Ads": ("com.google.android.gms.ads", "com.google.ads"),
    "AppLovin": ("com.applovin",),
    "Unity Ads": ("com.unity3d.ads", "com.unity3d.services"),
    "ironSource": ("com.ironsource",),
    "Mintegral": ("com.mbridge", "com.mintegral"),
    "Vungle": ("com.vungle",),
    "Chartboost": ("com.chartboost",),
    "Meta Audience Network": ("com.facebook.ads",),
    "Pangle": ("com.bytedance.sdk", "com.pangle"),
    "StartApp": ("com.startapp",),
    "Fyber": ("com.fyber",),
    "InMobi": ("com.inmobi",),
    "Tapjoy": ("com.tapjoy",),
    "AdColony": ("com.adcolony",),
    "Ogury": ("com.ogury",),
    "Amazon Ads": ("com.amazon.device.ads",),
    "Moloco": ("com.moloco",),
    "BidMachine": ("io.bidmachine",),
    "Yandex Ads": ("com.yandex.mobile.ads",),
}
AGGRESSIVE_SDKS = ("Mintegral", "StartApp")


SENSITIVE_PERMS = {
    "texts": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
              "android.permission.SEND_SMS"],
    "contacts": ["android.permission.READ_CONTACTS"],
    "call log": ["android.permission.READ_CALL_LOG"],
    "location": ["android.permission.ACCESS_FINE_LOCATION",
                 "android.permission.ACCESS_COARSE_LOCATION",
                 "android.permission.ACCESS_BACKGROUND_LOCATION"],
    "microphone": ["android.permission.RECORD_AUDIO"],
    "camera": ["android.permission.CAMERA"],
}

# Score at which an app is auto-flagged (pre-checked) for removal.
FLAG_SCORE = 3

ADB = None  # resolved at startup


def find_adb():
    """Locate adb.exe: PATH first, then the usual download spots."""
    found = shutil.which("adb")
    if found:
        return found
    home = Path.home()
    candidates = [
        Path(sys.argv[0]).parent / "platform-tools" / "adb.exe",
        Path.cwd() / "platform-tools" / "adb.exe",
        home / "Downloads" / "platform-tools-latest-windows"
             / "platform-tools" / "adb.exe",
        home / "Downloads" / "platform-tools" / "adb.exe",
        home / "platform-tools" / "adb.exe",
        Path("C:/platform-tools/adb.exe"),
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def _no_console():
    """Windows: keep subprocess calls from flashing a console window."""
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return {"startupinfo": si}
    return {}


def run(cmd, timeout=60):
    """Run an adb command, return stdout text ('' on failure)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, **_no_console())
        return out.stdout.strip()
    except Exception:
        return ""


def adb_cmd(*args, timeout=60):
    return run([ADB, *args], timeout=timeout)


def check_device():
    """Returns (ok, message)."""
    global ADB
    ADB = find_adb()
    if not ADB:
        return (False, "ADB_NOT_FOUND")
    out = adb_cmd("devices")
    devices = [l for l in out.splitlines()[1:] if l.strip().endswith("device")]
    if not devices:
        return (False, "NO_PHONE")
    if len(devices) > 1:
        return (False, "MULTI_PHONE")
    return (True, "")




def packages_in(text):
    """Extract package names from adb output text."""
    return set(re.findall(PKG_RE + r"(?=/|:|\s|$)", text or ""))


def third_party_with_installers():
    """Returns {pkg: installer_pkg} for third-party apps."""
    out = adb_cmd("shell", "pm", "list", "packages", "-3", "-i")
    result = {}
    for line in out.splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip())
        if m:
            result[m.group(1)] = m.group(2)
    return result


def install_source(installer):
    """(label, sideloaded?) for an installer package name."""
    if installer in STORES:
        return STORES[installer], False
    if installer in TRANSFER:
        return TRANSFER[installer], False
    if CARRIER.match(installer or ""):
        return "carrier preload", False
    if installer in ("null", "", None):
        return "sideloaded (no installer)", True
    return "sideloaded via " + installer, True


def parse_pkg_dump(out):
    """(first_install, last_update, label, granted_perms) from dumpsys output."""
    first = last = None
    for key, var in (("firstInstallTime", "first"), ("lastUpdateTime", "last")):
        m = re.search(key + r"=(\S+)", out)
        if m:
            try:
                val = datetime.strptime(m.group(1)[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                try:
                    val = datetime.strptime(m.group(1)[:10], "%Y-%m-%d")
                except ValueError:
                    val = None
            if var == "first":
                first = val
            else:
                last = val
    label = None
    m = re.search(r"application-label:'([^']+)'", out)
    if not m:
        m = re.search(r'application-label:"([^"]+)"', out)
    if m:
        label = m.group(1)
    perms = set(re.findall(r"\s*([\w.]+): granted=true", out))
    return first, last, label, perms


def usage_map():
    """{pkg: (last_used_str, launch_count)} from usage stats."""
    out = adb_cmd("shell", "dumpsys", "usagestats", timeout=90)
    result = {}
    for m in re.finditer(r'package=(\S+) totalTimeUsed="[^"]*" lastTimeUsed="([^"]+)"(.*)', out):
        pkg, last, rest = m.group(1), m.group(2), m.group(3)
        lm = re.search(r"appLaunchCount=(\d+)", rest)
        launches = int(lm.group(1)) if lm else 0
        prev_last, prev_launch = result.get(pkg, ("", 0))
        clean_last = last if not last.startswith("19") else ""
        result[pkg] = (max(prev_last, clean_last), max(prev_launch, launches))
    return result


def site_channels():
    """Browser site-notification grants as [(date_str, host)], newest first."""
    out = adb_cmd("shell", "dumpsys", "notification", "--noredact", timeout=90)
    rows = []
    for host, stamp in set(re.findall(r"mId='web:https?://([^;']*);(\d+)'", out)):
        try:
            # Chrome stores grant time as microseconds since 1601-01-01.
            when = datetime.fromtimestamp(int(stamp) / 1_000_000 - 11644473600)
            rows.append((when.strftime("%Y-%m-%d"), host))
        except (ValueError, OSError):
            pass
    return sorted(rows, reverse=True)


def phone_today():
    d = adb_cmd("shell", "date", "+%F").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
        return date.fromisoformat(d)
    return date.today()


# Issue #36: manufacturer namespaces for the learned-list rule. A package
# whose ONLY hit is the shop's learned list, living in one of these
# namespaces, is OEM software the shop once removed - a REVIEW item
# ("shop history"), not a REMOVE conviction.
OEM_LEARNED_PREFIXES = ("com.samsung.", "com.sec.android.",
                        "com.google.android.", "com.android.")


def _known_or_learned_verdict(pkg, in_known_bad, label_bad, in_learned):
    """(verdict, reason) for list-based hits, or None if no list hit.

    Convictions (KNOWN_BAD or a known-bad label) are always REMOVE -
    including OEM-namespace mimics like com.sec.reclean, which is not a
    manufacturer package at all. Learned-only hits on manufacturer
    packages are REVIEW (Issue #36); other learned hits stay REMOVE.
    """
    if in_known_bad or label_bad:
        return ("remove", "known junk app (confirmed in shop testing)")
    if in_learned:
        if pkg.startswith(OEM_LEARNED_PREFIXES):
            return ("review",
                    "removed by this shop before (shop history)")
        return ("remove", "removed by this shop before (learned)")
    return None


# ------------------------------------------------------- guided clean ---
# Guided Clean (beginner mode) sorts each flagged row into one of three
# piles: "remove" (junk -- safe to take off), "keep" (the customer's own
# stuff -- Guided Clean NEVER removes it), "ask" (left on the phone for a
# human to decide). System/manufacturer namespaces and famous consumer
# apps are always "keep" -- UNLESS the package is a feed conviction
# (KNOWN_BAD): a shield never overrides a conviction (com.sec.reclean
# wears a Samsung-style namespace but is confirmed junk).
SHIELD_PREFIXES = ("com.google.android.", "com.android.",
                   "com.samsung.", "com.sec.android.")

POPULAR_KEEP = {
    "com.facebook.katana", "com.facebook.orca", "com.instagram.android",
    "com.whatsapp", "com.zhiliaoapp.musically", "com.snapchat.android",
    "com.amazon.mShop.android.shopping", "com.netflix.mediaclient",
    "com.spotify.music", "net.zedge.android",
}
POPULAR_KEEP_PREFIXES = ("com.zynga.", "net.peakgames.",
                         "com.peoplefun.", "com.easybrain.")


def guided_pile(pkg, verdict, convicted=False):
    """Which Guided Clean pile a flagged row belongs to.

    "keep"   -- shielded/famous app (unless convicted), or clean verdict
    "remove" -- REMOVE verdict on a non-shielded app, or any conviction
    "ask"    -- REVIEW verdict: a human decides
    """
    shielded = (pkg.startswith(SHIELD_PREFIXES)
                or pkg in POPULAR_KEEP
                or pkg.startswith(POPULAR_KEEP_PREFIXES))
    if shielded and not convicted:
        return "keep"
    if verdict == "remove" or convicted:
        return "remove"
    if verdict == "review":
        return "ask"
    return "keep"


def scan_numbers(scan_data):
    """Main-list scan number for every flagged row (issue #46).

    The results list numbers the flagged rows 1..N in scan order
    (remove/review verdicts, default All-sources view). Guided Clean
    walks the same rows in the same order, so a row's number here is
    the number the operator sees next to it in the list -- the guide
    prints it in front of each name so a ruling can be given and
    followed BY NUMBER, identically in both places.
    Returns {pkg: number}."""
    nums = {}
    n = 0
    for r in scan_data:
        if r[4] in ("remove", "review"):
            n += 1
            nums[r[0]] = n
    return nums


GUIDE_PILE_STYLE = {
    "remove": "#ff4d4d",   # RED text    = take it off
    "keep":   "#35d05a",   # GREEN text  = it stays
    "ask":    "#ffcf40",   # YELLOW text = ask first
}

GUIDE_HEADERS = {
    "remove": "JUNK -- will be removed (%d):",
    "keep":   "YOUR STUFF -- kept, never touched (%d):",
    "ask":    "NOT SURE -- left on the phone for a human to decide (%d):",
}


def guided_sections(scan_data):
    """Guided Clean guide sections (issues #46 + #49).

    Returns [(pile, header, [(number, name, row), ...]), ...] in
    remove / keep / ask order. Every flagged row appears exactly once,
    carrying its main-list scan number (issue #46), and NOTHING is
    truncated: the guide is what staff and customers follow, so no app
    may hide behind a '+ N more' line. The dialog WRITES each line in
    its pile color (GUIDE_PILE_STYLE) -- RED = remove, GREEN = keep,
    YELLOW = ask first -- on the guide's normal background, so the
    guide can be followed by color alone (issue #49)."""
    piles = {"remove": [], "keep": [], "ask": []}
    for r in scan_data:
        if r[4] not in ("remove", "review"):
            continue
        piles[guided_pile(r[0], r[4],
                          convicted=r[0] in KNOWN_BAD)].append(r)
    nums = scan_numbers(scan_data)
    return [(k, GUIDE_HEADERS[k] % len(piles[k]),
             [(nums[r[0]], r[1] or r[0], r) for r in piles[k]])
            for k in ("remove", "keep", "ask")]


STABLE_NAME = "AdTrapper-PC.pyw"


def ensure_stable_alias(src=None):
    """Keep a stable-named copy of the running build next to it.

    Every update installs a NEW versioned filename (…-v10.8.pyw), which
    breaks any desktop shortcut pointing at the old name. This alias
    (AdTrapper-PC.pyw, no version in the name) is refreshed to the
    running build at every startup, so a shortcut pointed at it works
    forever — updates included. Returns the alias path, or None.
    """
    try:
        src = os.path.abspath(src or __file__)
        dst = os.path.join(os.path.dirname(src), STABLE_NAME)
        if os.path.normcase(src) == os.path.normcase(dst):
            return dst
        if os.path.exists(dst) \
                and os.path.getsize(dst) == os.path.getsize(src):
            with open(src, "rb") as a, open(dst, "rb") as b:
                if a.read() == b.read():
                    return dst
        shutil.copyfile(src, dst)
        return dst
    except Exception:
        return None


def row_default_checked(pkg, verdict):
    """Initial checkbox state for a results-list row.

    A row starts checked only if it is flagged (remove/review) AND
    Guided Clean would not keep it. Shielded rows (Facebook, Google
    system apps) still show their verdict badge, but start UNCHECKED --
    after a removal pass the app auto re-scans and rebuilds this list,
    and one stray REMOVE ALL click must never take a keeper with it.
    (convicted=False here on purpose: the shield namespaces are exact
    prefixes -- com.sec.android. is shielded, com.sec.<junk> is not.)
    """
    return (verdict in ("remove", "review")
            and guided_pile(pkg, verdict) != "keep")


def scan_core(progress_cb=None):
    """Returns (results, sites).
    results: [(pkg, label, score, reasons, verdict, source_cat, privacy,
               threat_type, boot_hit)] for every third-party app.
    verdict is "remove" (high-confidence junk, pre-checked), "review"
    (suspicious, needs a human look) or "clean". threat_type is one of
    Malware/Adware/Spyware/Tracking/Suspicious/Clean.
    sites: [(date_str, host)] allowed to send browser notifications.
    """
    installers = third_party_with_installers()
    today = phone_today()
    boot_pkgs = packages_in(adb_cmd("shell", "pm", "queryreceivers", "--components",
                                    "-a", "android.intent.action.BOOT_COMPLETED"))

    overlays = packages_in(adb_cmd("shell", "appops", "query-op",
                                   "SYSTEM_ALERT_WINDOW", "allow"))
    admins = packages_in(" ".join(
        re.findall(r"ComponentInfo\{[^}]+\}", adb_cmd("shell", "dumpsys", "device_policy"))))
    a11y = packages_in(adb_cmd("shell", "settings", "get", "secure",
                               "enabled_accessibility_services"))
    can_install = packages_in(adb_cmd("shell", "appops", "query-op",
                                      "REQUEST_INSTALL_PACKAGES", "allow"))
    listeners = packages_in(adb_cmd("shell", "settings", "get", "secure",
                                    "enabled_notification_listeners"))
    usage_access = packages_in(adb_cmd("shell", "appops", "query-op",
                                       "GET_USAGE_STATS", "allow"))
    launcher_raw = adb_cmd("shell", "cmd", "package", "query-activities", "--brief",
                           "-a", "android.intent.action.MAIN",
                           "-c", "android.intent.category.LAUNCHER")
    launcher = packages_in(launcher_raw)
    if len(launcher) < 5:
        launcher = None  # unsupported on this Android version: skip hidden-icon check
    # HOME apps: who can be the device's home screen? A "cleaner" or "PDF"
    # app registered as HOME is a launcher hijack - massive red flag.
    home_raw = adb_cmd("shell", "cmd", "package", "query-activities", "--brief",
                       "-a", "android.intent.action.MAIN",
                       "-c", "android.intent.category.HOME")
    home_apps = packages_in(home_raw)
    # Preloaded apps with a launcher icon that are NOT core system parts:
    # carrier/maker junk (cleaners, ad apps) hides here because the
    # third-party list (-3) never includes it.
    ALL_PKGS = packages_in(adb_cmd("shell", "pm", "list", "packages"))
    PRELOAD_EXTRA = set()
    if launcher:
        CORE_PREFIXES = ("com.samsung.", "com.sec.", "com.google.",
                         "com.android.", "android.", "com.qualcomm.",
                         "com.mediatek.", "org.chromium.", "com.skms.")
        for p in ALL_PKGS:
            if (p not in installers and p in launcher
                    and not p.startswith(CORE_PREFIXES)):
                PRELOAD_EXTRA.add(p)
                installers[p] = None

    used = usage_map()

    recent_cutoff = datetime.now() - timedelta(days=30)
    results = []
    pkgs = sorted(installers)
    total = len(pkgs)
    for i, pkg in enumerate(pkgs):
        installer = installers[pkg]
        out = adb_cmd("shell", "dumpsys", "package", pkg)
        first, last, label, perms = parse_pkg_dump(out)
        if not label:
            label = pkg

        source, sideloaded = install_source(installer)
        if pkg in PRELOAD_EXTRA:
            source, sideloaded = "preinstalled (carrier/maker)", False
        if sideloaded and (not first or first.year < 2010 or
                           pkg.startswith(("com.samsung.", "com.sec."))):
            source, sideloaded = "factory preinstalled", False

        if sideloaded:
            source_cat = "Sideloaded"
        elif source in STORES.values():
            source_cat = source  # "Play Store", "Galaxy Store", ...
        else:
            source_cat = "Preinstalled"

        score, reasons = 0, []
        _lab = (label or "").strip().lower()
        _label_bad = (_lab in KNOWN_BAD_LABELS
                      or _lab.startswith(KNOWN_BAD_LABEL_PREFIXES))
        _kl = _known_or_learned_verdict(pkg, pkg in KNOWN_BAD,
                                        _label_bad, pkg in LEARNED_BAD)
        if _kl is not None:
            verdict, _kl_reason = _kl
            score = 99
            reasons = [_kl_reason]
            threat_type = "Malware"
            boot_hit = pkg in boot_pkgs
            privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                       if any(pr in perms for pr in plist)]
            if progress_cb:
                try:
                    progress_cb(i + 1, total, pkg)
                except Exception:
                    pass
            results.append((pkg, label, score, reasons, verdict, source_cat,
                            privacy, threat_type, boot_hit))
            continue

        if (pkg.startswith(FIRST_PARTY_PREFIXES)
                and not pkg.startswith(WEBAPK_PREFIX)):
            # First-party shield: vendor apps are never flagged by heuristics.
            # (Matches lib/services/app_scanner.dart - Hard Rule #3).
            boot_hit = pkg in boot_pkgs
            privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                       if any(pr in perms for pr in plist)]
            if progress_cb:
                try:
                    progress_cb(i + 1, total, pkg)
                except Exception:
                    pass
            results.append((pkg, label, 0, [], "clean", source_cat,
                            privacy, "Clean", boot_hit))
            continue

        webapk_hit = pkg.startswith(WEBAPK_PREFIX)
        admin_hit = pkg in admins
        a11y_hit = pkg in a11y
        hidden_hit = launcher is not None and pkg not in launcher
        overlay_hit = pkg in overlays
        home_hit = pkg in home_apps and pkg not in TRUSTED_LAUNCHERS
        installer_hit = ("android.permission.REQUEST_INSTALL_PACKAGES" in perms
                         or pkg in can_install)
        if webapk_hit:
            score += 2
            reasons.append("a website installed as an app (WebAPK)")
        if sideloaded:
            score += 4
            reasons.append("not from an app store (%s)" % source)
        if admin_hit:
            score += 3
            reasons.append("device admin (can resist uninstall)")
        if a11y_hit:
            score += 3
            reasons.append("uses accessibility service")
        if hidden_hit:
            score += 2
            reasons.append("no app icon (hidden from app drawer)")
        if overlay_hit:
            score += 2
            reasons.append("can draw over other apps (POPUP CAPABLE)")
        if home_hit:
            score += 5
            reasons.append("registers as a HOME app (launcher hijack!)")
        if installer_hit:
            score += 1
            reasons.append("can install other apps")

        never_hit = recent_hit = abandoned_hit = False
        age = (today - first.date()).days if first else None
        if age is not None:
            last_used, launches = used.get(pkg, ("", 0))
            if age > 3 and not last_used and launches == 0:
                never_hit = True
                score += 1
                reasons.append("never opened")
            if age <= 30:
                recent_hit = True
                score += 1
                reasons.append("installed recently (%s)" % first.date())
        if last and (today - last.date()).days > 730:
            abandoned_hit = True
            score += 1
            reasons.append("not updated since %s (abandoned)" % last.date())
        junk_hit = bool(
            pkg not in TRUSTED_PKGS
            and (JUNK_RE.search(pkg) or JUNK_RE.search(label or "")))
        if junk_hit:
            score += 1
            reasons.append("cleaner/booster/PDF-type name (common adware disguise)")
        # Inside the app: ad networks declared in its manifest.
        _low = out.lower()
        sdk_hits = sorted({nm for nm, prefs in AD_SDKS.items()
                           if any(pf in _low for pf in prefs)})
        n_sdk = len(sdk_hits)
        aggressive_hit = any(nm in AGGRESSIVE_SDKS for nm in sdk_hits)
        listener_hit = pkg in listeners
        usage_hit = pkg in usage_access
        if n_sdk >= 3:
            score += 2
            reasons.append("stuffed with %d ad networks (%s)"
                           % (n_sdk, ", ".join(sdk_hits[:4])))
        elif aggressive_hit:
            score += 2
            reasons.append("runs aggressive ad network %s (known for "
                           "pop-up ads outside the app)"
                           % ", ".join(nm for nm in sdk_hits
                                       if nm in AGGRESSIVE_SDKS))
        if listener_hit:
            score += 4
            reasons.append("can READ all notifications "
                           "(notification listener access)")
        if usage_hit and n_sdk:
            score += 1
            reasons.append("can track which apps you use (usage access)")
        # Sideloaded "PDF" app: classic scareware (legit readers use Play Store)
        if sideloaded and "pdf" in (pkg + " " + (label or "")).lower():
            score += 2
            reasons.append("sideloaded PDF app (common scareware disguise)")
        # Name mimicry: pretends to be "Google Play", "Settings", etc. (McAfee HiddenAds)
        _mimic_labels = {"google play", "settings", "google settings", "play store",
                         "google home", "system update", "android system"}
        _genuine_pkgs = {"com.android.vending", "com.google.android.gms",
                         "com.android.settings", "com.google.android.apps.home"}
        _mimic_hit = False
        if (label or "").strip().lower() in _mimic_labels and pkg not in _genuine_pkgs:
            score += 4
            reasons.append('pretends to be "%s" (name mimicry - review required)' % label.strip())
            _mimic_hit = True
        boot_hit = pkg in boot_pkgs
        if boot_hit:
            score += 2
            reasons.append("starts at boot (survives restart)")
        privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                   if any(pr in perms for pr in plist)]
        if privacy and (junk_hit or sideloaded or len(privacy) >= 2):
            score += 1
            reasons.append("can access your " + ", ".join(privacy))

        # Verdict: "remove" = high-confidence junk, pre-checked.
        # "review" = suspicious, shown for a human decision. "clean" = leave alone.
        if (webapk_hit
              or home_hit
              or (sideloaded and (junk_hit or overlay_hit or admin_hit))
              or (junk_hit and (recent_hit or overlay_hit or abandoned_hit))
              or (overlay_hit and junk_hit)
              or (overlay_hit and n_sdk >= 1)
              or (listener_hit and n_sdk >= 1)
              or (aggressive_hit and recent_hit)
              or (admin_hit and junk_hit)):
            verdict = "remove"
        elif score >= FLAG_SCORE:
            verdict = "review"
        elif _mimic_hit:
            verdict = "review"
        elif junk_hit:
            verdict = "review"
            reasons.append("cleaner/booster-type: never trusted blind "
                           "(common adware disguise)")
        elif n_sdk >= 3 or listener_hit:
            verdict = "review"
        elif overlay_hit or admin_hit or a11y_hit:
            verdict = "review"
        else:
            verdict = "clean"

        if _mimic_hit and verdict == "remove":
            # Owner rule: name mimicry is review-only, never auto-remove
            verdict = "review"

        if verdict in ("remove", "review"):
            if admin_hit:
                threat_type = "Malware"
            elif _mimic_hit:
                threat_type = "Suspicious"
            elif privacy and (sideloaded or junk_hit):
                threat_type = "Spyware"
            elif "location" in privacy:
                threat_type = "Tracking"
            elif junk_hit or overlay_hit or n_sdk >= 2:
                threat_type = "Adware"
            else:
                threat_type = "Suspicious"
        else:
            threat_type = "Clean"

        if progress_cb:
            try:
                progress_cb(i + 1, total, pkg)
            except Exception:
                pass
        results.append((pkg, label, score, reasons, verdict, source_cat,
                        privacy, threat_type, boot_hit))

    # Fake copies: several apps sharing one system-app name.
    _COMMON = {"messages", "messenger", "phone", "camera", "gallery",
               "settings", "play store", "calculator", "clock",
               "calendar", "contacts", "weather", "browser", "email"}
    _counts = {}
    for r in results:
        if len(r) == 9:
            k = (r[1] or "").strip().lower()
            _counts[k] = _counts.get(k, 0) + 1
    _fixed = []
    for r in results:
        if len(r) == 9 and r[4] == "clean":
            pkg, label, score, reasons, verdict, sc, priv, tt, bt = r
            lab = (label or "").strip().lower()
            if lab in _COMMON and _counts.get(lab, 0) >= 2:
                if pkg.startswith(FIRST_PARTY_PREFIXES):
                    _fixed.append(r)
                    continue
                score += 3
                reasons = reasons + ["multiple apps named '%s' - fake copy (review required)"
                                     % label]
                verdict = "review"  # Owner rule: review-only, never auto-remove
                if tt == "Clean":
                    tt = "Suspicious"
                r = (pkg, label, score, reasons, verdict, sc, priv, tt, bt)
        _fixed.append(r)
    results = _fixed

    # Tripwire: any app with a drawer icon that the scan did NOT process
    # gets flagged REVIEW - a silent miss becomes a loud one.
    if launcher:
        _scanned = {r[0] for r in results}
        for p in sorted(launcher):
            if (p not in _scanned and p in ALL_PKGS
                    and not p.startswith(CORE_PREFIXES)):
                results.append(
                    (p, p, 3,
                     ["has an app-drawer icon but was NOT in the scan "
                      "list (hiding from the scan)"],
                     "review", "Unknown", [], "Suspicious", False))

    results.sort(key=lambda r: (-r[2], r[1].lower()))
    return results, site_channels()


def backup_apk(pkg, backup_dir):
    """Pull the app's APK(s) into backup_dir/pkg/. Returns base apk path or None."""
    paths = [l.replace("package:", "") for l in
             adb_cmd("shell", "pm", "path", pkg).splitlines()
             if l.startswith("package:")]
    if not paths:
        return None
    dest = Path(backup_dir) / pkg
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    saved = None
    for ap in paths:
        local = dest / Path(ap).name
        try:
            subprocess.run([ADB, "pull", ap, str(local)],
                           capture_output=True, text=True, timeout=120,
                           **_no_console())
        except Exception:
            pass
        if local.is_file() and saved is None:
            saved = str(local)
    return saved


def strip_device_admin(pkg):
    """Revoke device-admin via dpm so the app can be uninstalled.
    Returns True if an admin was found and verified removed."""
    out = adb_cmd("shell", "dumpsys", "device_policy")
    for m in re.finditer(r"ComponentInfo\{([^}]+)\}", out):
        comp = m.group(1)  # e.g. "com.pkg/.AdminReceiver"
        if comp.split("/")[0] == pkg:
            r = adb_cmd("shell", "dpm", "remove-active-admin",
                        "--user", "0", comp)
            # Re-check dumpsys to verify active admin was actually stripped
            post = adb_cmd("shell", "dumpsys", "device_policy")
            if comp not in post:
                return True
            if "Success" in r or "removed" in r.lower():
                return True
    return False


def uninstall_core(pkg):
    """Returns a short result message. Three methods, strongest last."""
    out = adb_cmd("uninstall", pkg)
    if "Success" in out:
        return "uninstalled"
    out = adb_cmd("shell", "pm", "uninstall", "--user", "0", pkg)
    if "Success" in out:
        return "uninstalled (stubborn-app method)"
    # Brick-wall breaker: strip device admin, then retry uninstall
    if strip_device_admin(pkg):
        out = adb_cmd("shell", "pm", "uninstall", "--user", "0", pkg)
        if "Success" in out:
            return "uninstalled (device admin stripped first)"
    out = adb_cmd("shell", "pm", "disable-user", "--user", "0", pkg)
    if "disabled" in out.lower():
        return "disabled (can't run or show popups)"
    return ("COULD NOT REMOVE - on the phone go to Settings > Security and privacy > "
            "Device admin apps, turn it off there, then uninstall from Settings > Apps")


# ------------------------------------------------- original GUI ---

# Original Pop-Up Blocker look (from the first build):
#   dark window, red POP-UP BLOCKER header, teal ADWARE SCANNER subhead,
#   green-dot status bar, cyan SCAN PHONE, filter radios, purple-gray
#   results pane, red REMOVE ALL, Activity log. Single window.

DBG  = "#0c0c11"   # near-black window
DBAR = "#1b1b24"   # status bar
DRED = "#d92b2b"   # POP-UP BLOCKER header / REMOVE ALL
DTEAL = "#4fd1c5"  # ADWARE SCANNER subhead
DCYAN = "#00a8cc"  # SCAN PHONE button
DPANE = "#5e576e"  # results pane (purple-gray)
DTEXT = "#e8e8ec"
DGRAY = "#9a9aa5"

_BANNER_B64 = """
iVBORw0KGgoAAAANSUhEUgAABLAAAAIjCAMAAAAk3RIqAAADAFBMVEUWWmIbnt+fGFri3twaZJ8e
JlfbJ1dj1+2lGCcbYCMhHSqe3efZGSniWGNapuBbVmViIVfjmKRaqBzip9qimaadpdheFinkYplg
l6Wc4mBZaJwclKMh2fKdZ5ik5J5doV+eV2cZZtOeK5iT3yMujxjW8Klxyh0lk2MSMZZl0aLbZtKd
YNVfZNTWMJRjLZptzF/nTyhLaiHP8GiOpWnzhXnznhinVCOYqyWdOMY1xaL3yylrOcc1w2PMOsMU
OMUBAAH6+/wWAALHAgK3AQLnAwQCBhb5KTT5NDrXAgMmAAKXAQKnAQKHAQP0AwX6Q0dnAQR3AQRX
AQM3AQJHAQL6O0Pp+fvn6vTV2egCCib5JCwCFjbJ0+jX+/0EFCj5Gyj5VVi1uslpdId6hJfH+v0C
GUaao7X5ZmgCJlekqrqKk6b5dnjFydf6hointtja5PQF9/sXBRb5SVSrs8T6lpiTmqu5w9b7pqcE
NwS3+PwCJwT7trf75+iDiZvl5esYVgO4x+MEJUh3AxbEzOX46vf5WWRkbYPnFRiHBBYoZgP2CRX8
x8foNjkHRgPnCRXb4usCN3f6anTnJSn81tc2dwRYAxao9/wCFwTYFhhnAxUWGCfoRkj2FRgBKWbo
GSaWBRbYCBUlWQMWSQPoVVcECzT6mKQmBRaFjKL6eoQDNWgXByfoKTUFExpzeoznOUUCNxenBhYC
RYfYJSj6ipWGAyZ3AyY4hgWm6PmX6PlIlgV1fJJFiAQCOYYCR5cCV6cZZgNiany3BxYodgScq9SH
BTeWBCfoZmdbZHgFJDjHCBXL0txXpgVnAyc3BhaY9/yWBje36Pnl2udaaoUDeNaH5/kEGlUERicD
SDfYNTjo/OgXJDcERheWm7PHFRdHBhUDZrgmBifoSVXYGCUENVi0vNfW2/Q5V4jH6foDaMYJVgR4
BDbodnf62eUDVpimueW3FRgEhtiH2Pj7qrQCKBcDdsgDWLYmFynYKTZ45/i5wc37uMWml6jI1/UC
OCYEVkdTmQUzaQOqAFMSAAEAAElEQVR42uz9DVyTd5b3j0cuCHm4LsIVQgI4JGkFH2orWHn9dvd1
732LEEkUjaKgpaLxoaYaM77EaMYG67QDppqUltBq2jCUmZSWFsu2MGsfp7b+ZrFOa8fptLvYrU6x
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
gg==
"""

DGREEN = "#35d05a"
DFONT = "Segoe UI"
DMONO = "Consolas"


# ------------------------------------------------------------ self-update --
# Issue #37: one-click self-update, the way the phone app does it.
# The program checks a small manifest on OUR feed repo only:
#   pc-version.json  {version, url, sha256, size, notes}
# A download is installed only after its size AND SHA-256 match the
# manifest; a helper script performs the file swap after this process
# exits and rolls back to the backup copy if the new version fails to
# start. Updates are never offered or applied while a scan/removal
# (phone session) is in progress, and never applied automatically.
UPDATE_MANIFEST_URL = ("https://raw.githubusercontent.com/ifixrepairs/"
                       "popup-blocker/main/pc-version.json")
UPDATE_ALIVE_SECONDS = 10  # new version must stay alive this long

UPDATE_HELPER_SRC = """import json, os, subprocess, sys, time

def pid_alive(pid):
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(h)
        return code.value == 259
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def main():
    (wait_pid, current, downloaded, target, backup, result_path,
     python_exe, alive_secs, from_v, to_v) = sys.argv[1:11]
    wait_pid = int(wait_pid)
    alive_secs = float(alive_secs)
    deadline = time.time() + 30
    while pid_alive(wait_pid) and time.time() < deadline:
        time.sleep(0.25)
    outcome = "updated"
    try:
        if os.path.exists(backup):
            os.remove(backup)
        os.replace(current, backup)
        os.replace(downloaded, target)
        proc = subprocess.Popen([python_exe, target])
        time.sleep(alive_secs)
        if proc.poll() is not None:
            outcome = "rolled_back"
            try:
                os.remove(target)
            except OSError:
                pass
            os.replace(backup, current)
            subprocess.Popen([python_exe, current])
    except Exception:
        outcome = "rolled_back"
        try:
            if not os.path.exists(current) and os.path.exists(backup):
                os.replace(backup, current)
                subprocess.Popen([python_exe, current])
        except Exception:
            pass
    try:
        with open(result_path, "w") as f:
            json.dump({"outcome": outcome, "from_version": from_v,
                       "to_version": to_v}, f)
    except Exception:
        pass

main()
"""


def _version_tuple(v):
    parts = []
    for piece in str(v).strip().split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_newer(remote, local):
    r, l = _version_tuple(remote), _version_tuple(local)
    n = max(len(r), len(l))
    r += (0,) * (n - len(r))
    l += (0,) * (n - len(l))
    return r > l


def _default_fetch_bytes(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": "AdTrapper-PC-Updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_update_manifest(raw):
    """Validate manifest bytes -> dict, or None if malformed."""
    try:
        data = json.loads(raw.decode("utf-8"))
        version = str(data["version"]).strip()
        url = str(data["url"]).strip()
        sha = str(data["sha256"]).strip().lower()
        size = int(data["size"])
        notes = str(data.get("notes", ""))
    except Exception:
        return None
    if not version or not url or len(sha) != 64 or size <= 0:
        return None
    return {"version": version, "url": url, "sha256": sha,
            "size": size, "notes": notes}


def check_for_update(fetch_bytes=None):
    """Manifest dict if the feed offers a NEWER version, else None.
    Any network or parse problem returns None quietly - offline is a
    normal state for a shop PC, never an error."""
    fetch = fetch_bytes or _default_fetch_bytes
    try:
        info = parse_update_manifest(fetch(UPDATE_MANIFEST_URL))
    except Exception:
        return None
    if info and _version_newer(info["version"], VERSION):
        return info
    return None


def verify_update_file(path, expected_size, expected_sha256):
    """True only if the file's size and SHA-256 both match the manifest."""
    try:
        p = Path(path)
        if p.stat().st_size != int(expected_size):
            return False
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower() == str(expected_sha256).lower()
    except Exception:
        return False


def download_update(manifest, dest_dir, fetch_bytes=None):
    """Download the update into dest_dir and verify it.
    Returns (path, None) on success, (None, reason) on failure. A failed
    or unverifiable download is always deleted, never installed."""
    fetch = fetch_bytes or _default_fetch_bytes
    dest = Path(dest_dir) / ("AdTrapper-PC-v%s.download"
                             % manifest["version"])
    try:
        data = fetch(manifest["url"], timeout=120)
        dest.write_bytes(data)
    except Exception as e:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        return (None, "download failed (%s)" % e)
    if not verify_update_file(dest, manifest["size"], manifest["sha256"]):
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        return (None, "the downloaded file failed its safety check "
                      "(size/hash mismatch) and was discarded")
    return (dest, None)


def updater_guard_reason(busy):
    """Self-update is refused while a scan/removal (a phone session) is
    running. Returns a plain reason string, or None if update may go on."""
    if busy:
        return ("a scan or removal is in progress - finish it "
                "before updating")
    return None


def begin_update(current_path, downloaded_path, new_version, from_version,
                 wait_pid=None, alive_seconds=UPDATE_ALIVE_SECONDS):
    """Write the swap helper next to the program, launch it detached,
    and return its process handle. The CALLER exits right after this;
    the helper waits for that exit, renames the current file to
    AdTrapper-PC-v<old>-backup.pyw, moves the verified download in as
    AdTrapper-PC-v<new>.pyw, relaunches it, and - if it does not stay
    alive - restores the backup and relaunches that instead. Either way
    it leaves update_result.json for the relaunched program to report."""
    current_path = Path(current_path)
    folder = current_path.parent
    target = folder / ("AdTrapper-PC-v%s.pyw" % new_version)
    backup = folder / ("AdTrapper-PC-v%s-backup.pyw" % from_version)
    result_path = folder / "update_result.json"
    helper = folder / "adtrapper_update_helper.py"
    helper.write_text(UPDATE_HELPER_SRC, encoding="utf-8")
    if wait_pid is None:
        wait_pid = os.getpid()
    args = [sys.executable, str(helper), str(wait_pid), str(current_path),
            str(downloaded_path), str(target), str(backup),
            str(result_path), sys.executable, str(alive_seconds),
            str(from_version), str(new_version)]
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(args, **kwargs)


class PopupBlockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AdTrapper v%s -- Malware & Adware Scanner" % VERSION)
        self.root.minsize(640, 620)
        self.root.configure(bg=DBG)
        try:
            self.root.iconbitmap("popup_blocker.ico")
        except Exception:
            pass

        self.q = queue.Queue()
        self.busy = False
        self.scan_data = []      # full scan_core results
        self.sites = []          # [(date, host)]
        self._guided_pending = False  # guided clean awaiting its re-scan
        self._guided_ask = []         # names left for a human decision
        self.last_report_path = None
        self.report_customer = ""   # customer name for the cleanup report
        self.report_ticket = ""     # POS ticket no. (bank-proof reports)
        self.report_technician = ""  # technician printed on the report
        self._details_asked = False
        self._scan_completed = False
        self.row_vars = []       # [(BooleanVar, pkg, label)]
        self.show_var = tk.StringVar(value="sites")   # flagged | all | sites
        self.source_var = tk.StringVar(value="All sources")

        # ---------- header ----------
        # v10.9 (owner spec, 2026-10-14): the banner is a slim strip, not
        # a billboard. The writing is what matters -- the results list
        # gets the height the banner used to eat.
        head = tk.Frame(root, bg=DBG)
        head.pack(fill="x", padx=22, pady=(10, 0))
        self._banner_img = None
        try:
            import base64 as _b64h
            import io as _ioh
            from PIL import Image as _PImg, ImageTk as _PITk
            _rawb = _PImg.open(_ioh.BytesIO(_b64h.b64decode(_BANNER_B64)))
            _flat = _PImg.new("RGBA", _rawb.size, (12, 12, 17, 255))
            _flat.alpha_composite(_rawb.convert("RGBA"))
            _bw = max(1, int(84 * _rawb.width / float(_rawb.height)))
            self._banner_img = _PITk.PhotoImage(
                _flat.resize((_bw, 84), _PImg.LANCZOS))
        except Exception:
            try:
                self._banner_img = tk.PhotoImage(
                    data=_BANNER_B64).subsample(6, 6)
            except Exception:
                self._banner_img = None
        if self._banner_img is not None:
            tk.Label(head, image=self._banner_img, bg=DBG).pack(side="left")
        _htxt = tk.Frame(head, bg=DBG)
        _htxt.pack(side="left", padx=(16, 0))
        tk.Label(_htxt, text="M A L W A R E   &   A D W A R E   S C A N N E R",
                 font=(DFONT, 12, "bold"), fg=DTEAL, bg=DBG,
                 anchor="w").pack(fill="x")
        tk.Label(_htxt, text="iFixx Repairs \u2014 phone cleanup & repair",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG,
                 anchor="w").pack(fill="x", pady=(3, 0))

        # ---------- status bar ----------
        sbar = tk.Frame(root, bg=DBAR)
        sbar.pack(fill="x", padx=22, pady=(6, 10))
        self.dot = tk.Label(sbar, text="●", font=(DFONT, 12), fg=DGRAY,
                            bg=DBAR)
        self.dot.pack(side="left", padx=(14, 6), pady=10)
        self.status = tk.Label(sbar, text="Checking for phone …",
                               font=(DFONT, 11), fg=DTEXT, bg=DBAR)
        self.status.pack(side="left", pady=10)

        # ---------- scan button ----------
        bwrap = tk.Frame(root, bg=DBG)
        bwrap.pack(fill="x", padx=22, pady=(0, 12))
        btnrow = tk.Frame(bwrap, bg=DBG)
        btnrow.pack()
        self.scan_btn = tk.Button(
            btnrow, text="SCAN PHONE", font=(DFONT, 13, "bold"),
            fg="white", bg=DCYAN, activebackground="#0090b3",
            activeforeground="white", relief="flat", bd=0,
            padx=34, pady=12, cursor="hand2", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.usb_btn = tk.Button(
            btnrow, text="USB GUIDE", font=(DFONT, 11, "bold"),
            fg="white", bg="#3a3a48", activebackground="#4a4a58",
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.show_usb_guide)
        self.usb_btn.pack(side="left", padx=(12, 0))
        self.update_btn = tk.Button(
            btnrow, text="CHECK FOR UPDATES", font=(DFONT, 11, "bold"),
            fg="white", bg="#3a3a48", activebackground="#4a4a58",
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.on_update_click)
        self.update_btn.pack(side="left", padx=(12, 0))
        self.guided_btn = tk.Button(
            btnrow, text="GUIDED CLEAN", font=(DFONT, 11, "bold"),
            fg="white", bg=DGREEN, activebackground="#27ae49",
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.guided_clean)
        self.guided_btn.pack(side="left", padx=(12, 0))
        self.update_info = None  # manifest dict when an update is known
        self.prog = tk.Label(bwrap, text="", font=(DFONT, 9), fg=DGRAY,
                             bg=DBG)
        self.prog.pack(pady=(4, 0))

        # ---------- filter row ----------
        frow = tk.Frame(root, bg=DBG)
        frow.pack(fill="x", padx=22, pady=(0, 6))
        tk.Label(frow, text="Show:", font=(DFONT, 10), fg=DTEXT,
                 bg=DBG).pack(side="left")
        self.flagged_radio = None
        for val, txt in (("flagged", "⚠ Flagged only"),
                         ("all", "All apps"),
                         ("sites", "Notification sites")):
            rb = tk.Radiobutton(frow, text=txt, variable=self.show_var,
                                value=val, font=(DFONT, 10), fg=DTEXT, bg=DBG,
                                activebackground=DBG, selectcolor=DBAR,
                                command=self.render)
            rb.pack(side="left", padx=(10, 0))
            if val == "flagged":
                self.flagged_radio = rb
        tk.Label(frow, text="Source:", font=(DFONT, 10), fg=DTEXT,
                 bg=DBG).pack(side="left", padx=(18, 4))
        self.source_menu = tk.OptionMenu(frow, self.source_var,
                                         "All sources")
        self.source_menu.configure(font=(DFONT, 10), fg=DTEXT, bg=DBAR,
                                   activebackground=DBAR,
                                   activeforeground=DTEXT, relief="flat",
                                   bd=0, highlightthickness=0)
        self.source_menu.pack(side="left")
        try:
            self.source_menu["menu"].configure(bg=DBAR, fg=DTEXT,
                                               activebackground="#2a2a38")
        except Exception:
            pass

        # ---------- results pane ----------
        pane_wrap = tk.Frame(root, bg=DBG)
        pane_wrap.pack(fill="both", expand=True, padx=22, pady=(0, 8))
        self.pane = tk.Canvas(pane_wrap, bg=DPANE, highlightthickness=0,
                              bd=0, height=120)
        vsb = tk.Scrollbar(pane_wrap, orient="vertical",
                           command=self.pane.yview)
        self.pane.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.pane.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.pane, bg=DPANE)
        self._win = self.pane.create_window((0, 0), window=self.inner,
                                            anchor="nw")
        self.inner.bind("<Configure>",
                        lambda e: self.pane.configure(
                            scrollregion=self.pane.bbox("all")))
        self.pane.bind("<Configure>",
                       lambda e: self.pane.itemconfig(self._win,
                                                      width=e.width))
        self._mousewheel(self.pane)

        # ---------- remove row ----------
        rrow = tk.Frame(root, bg=DBG)
        rrow.pack(fill="x", padx=22, pady=(0, 10))
        self.remove_btn = tk.Button(
            rrow, text="REMOVE ALL", font=(DFONT, 11, "bold"),
            fg="white", bg=DRED, activebackground="#a81f1f",
            activeforeground="white", relief="flat", bd=0,
            padx=26, pady=9, cursor="hand2", command=self.remove_all)
        self.remove_btn.pack(side="left")
        tk.Label(rrow, text="removes everything checkmarked",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     side="left", padx=(12, 0))
        self.autoprint_var = tk.BooleanVar(value=True)
        tk.Checkbutton(rrow, text="Auto-print report",
                       variable=self.autoprint_var,
                       font=(DFONT, 10), fg=DTEXT, bg=DBG,
                       activebackground=DBG, activeforeground=DTEXT,
                       selectcolor=DBAR).pack(side="left", padx=(14, 0))
        self.undo_btn = tk.Button(
            rrow, text="UNDO", font=(DFONT, 10, "bold"),
            fg=DTEXT, bg="#2a2a35", activebackground="#3a3a48",
            activeforeground=DTEXT, relief="flat", bd=0,
            padx=18, pady=7, cursor="hand2", command=self.undo_last,
            state="disabled")
        self.undo_btn.pack(side="right")
        self.print_btn = tk.Button(
            rrow, text="PRINT", font=(DFONT, 10, "bold"),
            fg=DTEXT, bg="#2a2a35", activebackground="#3a3a48",
            activeforeground=DTEXT, relief="flat", bd=0,
            padx=18, pady=7, cursor="hand2", command=self._print_report)
        self.print_btn.pack(side="right", padx=(0, 8))

        # ---------- activity ----------
        tk.Label(root, text="Activity", font=(DFONT, 11, "bold"),
                 fg=DTEXT, bg=DBG, anchor="w").pack(fill="x", padx=22)
        log_wrap = tk.Frame(root, bg=DBG)
        log_wrap.pack(fill="x", padx=22, pady=(2, 16))
        self.logbox = tk.Text(log_wrap, height=3, font=(DMONO, 9),
                              fg="#c9c9d2", bg="#08080c", relief="flat",
                              bd=0, wrap="word", state="disabled")
        lsb = tk.Scrollbar(log_wrap, orient="vertical",
                           command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        self.logbox.pack(side="left", fill="x", expand=True)

        # v10.1 window sizing: ~1100x720, centered; height hugs the
        # content (clamped 720-800) so nothing is clipped by default.
        self.root.update_idletasks()
        try:
            _w = 1100
            _h = max(780, min(880, self.root.winfo_reqheight()))
            _h = min(_h, max(620, self.root.winfo_screenheight() - 30))
            _x = max(0, (self.root.winfo_screenwidth() - _w) // 2)
            _y = max(0, (self.root.winfo_screenheight() - _h) // 2)
            self.root.geometry("%dx%d+%d+%d" % (_w, _h, _x, _y))
        except Exception:
            self.root.geometry("1100x720")
        self.root.after(120, self.process_queue)
        threading.Thread(target=self._startup_check, daemon=True).start()
        self.log("AdTrapper v%s ready. (Title bar shows the version - "
                 "if it isn't v%s, this PC opened an old copy.)"
                 % (VERSION, VERSION))
        if ensure_stable_alias():
            self.log("Desktop shortcut file ready: %s — point the "
                     "shortcut at that name; it never changes."
                     % STABLE_NAME)
        self._report_update_result()
        threading.Thread(target=self._quiet_update_check,
                         daemon=True).start()

    # ------------------------------------------------------- helpers ---
    def _mousewheel(self, widget):
        def _on_wheel(e):
            try:
                widget.yview_scroll(int(-1 * (e.delta / 120)), "units")
            except Exception:
                pass
        widget.bind_all("<MouseWheel>", _on_wheel)

    def _script_dir(self):
        return Path(sys.argv[0]).parent

    def _undo_manifest_path(self):
        return self._script_dir() / "popup_blocker_undo.json"

    def _backup_dir(self):
        d = self._script_dir() / "PopUpBlockerBackups"
        d.mkdir(exist_ok=True)
        return d

    def _write_undo_manifest(self, removed):
        try:
            self._undo_manifest_path().write_text(json.dumps(
                {"date": datetime.now().isoformat(), "apps": removed}))
        except Exception:
            pass

    def _read_undo_manifest(self):
        try:
            p = self._undo_manifest_path()
            if p.is_file():
                data = json.loads(p.read_text())
                if data.get("apps"):
                    return data
        except Exception:
            pass
        return None

    def _clear_undo_manifest(self):
        try:
            self._undo_manifest_path().unlink(missing_ok=True)
        except Exception:
            pass

    def log(self, text):
        try:
            self.logbox.configure(state="normal")
            self.logbox.insert("end", text + "\n")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        except Exception:
            pass

    def set_busy(self, busy):
        self.busy = busy
        try:
            self.scan_btn.configure(
                text="SCANNING …" if busy else "SCAN PHONE",
                state="disabled" if busy else "normal",
                bg="#5a6a7a" if busy else DCYAN)
            self.remove_btn.configure(state="disabled" if busy else "normal")
        except Exception:
            pass

    # ------------------------------------------------------- updates ---
    def _report_update_result(self):
        """Report the outcome of a self-update that relaunched us."""
        p = self._script_dir() / "update_result.json"
        try:
            if p.is_file():
                data = json.loads(p.read_text())
                p.unlink(missing_ok=True)
                if data.get("outcome") == "rolled_back":
                    self.log("update didn't take \u2014 you're back "
                             "on v%s." % data.get("from_version", VERSION))
                elif data.get("outcome") == "updated":
                    self.log("Updated to AdTrapper v%s."
                             % data.get("to_version", VERSION))
        except Exception:
            pass

    def _quiet_update_check(self):
        info = check_for_update()
        if info:
            self.q.put(("update_badge", info))

    def on_update_click(self):
        reason = updater_guard_reason(self.busy)
        if reason:
            self.log("Update not started: %s." % reason)
            return
        if self.update_info:
            self._offer_update(self.update_info)
            return
        self.log("Checking for updates \u2026")
        threading.Thread(target=self._manual_update_check,
                         daemon=True).start()

    def _manual_update_check(self):
        info = check_for_update()
        if info:
            self.q.put(("update_badge", info))
            self.q.put(("update_offer", info))
        else:
            self.q.put(("log", "No update found \u2014 you're on the "
                               "latest version (v%s), or the check "
                               "couldn't reach the feed." % VERSION))

    def _offer_update(self, info):
        reason = updater_guard_reason(self.busy)
        if reason:
            self.log("Update not started: %s." % reason)
            return
        msg = ("AdTrapper v%s is available (you have v%s).\n\n%s\n\n"
               "Download and install it now? AdTrapper will restart."
               % (info["version"], VERSION, info.get("notes") or ""))
        if not messagebox.askyesno("AdTrapper update", msg):
            return
        self.log("Downloading AdTrapper v%s \u2026" % info["version"])
        threading.Thread(target=self._do_update_download,
                         args=(info,), daemon=True).start()

    def _do_update_download(self, info):
        path, err = download_update(info, self._script_dir())
        if err:
            self.q.put(("log", "Update not installed: %s. "
                               "You're still on v%s." % (err, VERSION)))
            return
        self.q.put(("update_install", (info, str(path))))

    def _install_update(self, info, downloaded):
        reason = updater_guard_reason(self.busy)
        if reason:
            self.log("Update not started: %s." % reason)
            return
        self.log("Installing AdTrapper v%s \u2014 restarting \u2026"
                 % info["version"])
        try:
            begin_update(Path(sys.argv[0]).resolve(), downloaded,
                         info["version"], VERSION)
        except Exception as e:
            self.log("Update could not start (%s). You're still on "
                     "v%s." % (e, VERSION))
            return
        self.root.after(400, self.root.destroy)

    # ------------------------------------------------------- device ---
    def _startup_check(self):
        ok, msg = check_device()
        if ok:
            self.q.put(("phone_ok", ""))
            try:
                model = adb_cmd("shell", "getprop",
                                "ro.product.model").strip()
                if model:
                    self.q.put(("phone_model", model))
            except Exception:
                pass
        else:
            self.q.put(("phone_bad", msg))

    # ------------------------------------------------------- scan ---
    def start_scan(self):
        if self.busy:
            return
        self.set_busy(True)
        self.report_customer = ""
        self.report_ticket = ""
        self.report_technician = ""
        self._details_asked = False
        self._scan_completed = False
        self.prog.configure(text="starting …")
        self.log("▸ scan initiated …")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        ok, msg = check_device()
        if not ok:
            self.q.put(("scan_error", msg))
            return
        self.q.put(("phone_ok", ""))
        try:
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            if model:
                self.q.put(("phone_model", model))
        except Exception:
            pass
        try:
            self.q.put(("scan_done", scan_core(
                progress_cb=lambda d, t, p: self.q.put(
                    ("progress", (d, t, p))))))
        except Exception as e:
            self.q.put(("log", "SCAN CRASHED: %s" % e))
            self.q.put(("scan_error", "SCAN_CRASHED"))

    # ------------------------------------------------------- usb guide ---
    USB_GUIDE_STEPS = (
        ("1", "On the phone, open Settings \u2192 About phone \u2192 "
              "Software information."),
        ("2", "Tap \"Build number\" 7 times (enter the PIN if asked) "
              "until it says \"Developer mode has been turned on\"."),
        ("3", "Go back to Settings \u2192 Developer options "
              "(at the very bottom), and turn ON \"USB debugging\". "
              "Greyed out? See the fix below."),
        ("4", "Plug the phone into this computer with the USB cable. "
              "If the phone asks about the USB mode, choose "
              "\"File transfer\"."),
        ("5", "On the phone, tap \"Allow\" on the \"Allow USB debugging?\" "
              "popup (tick \"Always allow from this computer\")."),
        ("6", "Back here, the dot turns green and it says "
              "\"Phone connected\" \u2014 hit SCAN PHONE."),
    )

    USB_GUIDE_GREY_STEPS = (
        ("1", "Unplug the USB cable from the phone."),
        ("2", "On the phone, open Settings \u2192 Security and privacy "
              "\u2192 Auto Blocker and turn it OFF (enter the PIN if it "
              "asks)."),
        ("3", "Go back to Settings \u2192 Developer options and turn "
              "ON \"USB debugging\" \u2014 it works now."),
    )

    def show_usb_guide(self):
        win = tk.Toplevel(self.root)
        win.title("Enable USB debugging")
        win.configure(bg=DBG)
        try:
            win.resizable(False, False)
        except Exception:
            pass
        tk.Label(win, text="Enable USB debugging",
                 font=(DFONT, 14, "bold"), fg="white", bg=DBG).pack(
                     anchor="w", padx=20, pady=(16, 4))
        tk.Label(win, text="Takes about 30 seconds. Do it once per phone.",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     anchor="w", padx=20, pady=(0, 10))
        for num, text in self.USB_GUIDE_STEPS:
            row = tk.Frame(win, bg=DBG)
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=num, font=(DFONT, 12, "bold"),
                     fg=DCYAN, bg=DBG, width=2).pack(side="left",
                                                    anchor="n")
            tk.Label(row, text=text, font=(DFONT, 11), fg=DTEXT,
                     bg=DBG, wraplength=460, justify="left").pack(
                         side="left", anchor="w")
        tk.Label(win, text="If \"USB debugging\" is greyed out:",
                 font=(DFONT, 12, "bold"), fg="#ffb02e", bg=DBG).pack(
                     anchor="w", padx=20, pady=(12, 4))
        for num, text in self.USB_GUIDE_GREY_STEPS:
            row = tk.Frame(win, bg=DBG)
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=num, font=(DFONT, 12, "bold"),
                     fg="#ffb02e", bg=DBG, width=2).pack(side="left",
                                                        anchor="n")
            tk.Label(row, text=text, font=(DFONT, 11), fg=DTEXT,
                     bg=DBG, wraplength=460, justify="left").pack(
                         side="left", anchor="w")
        tk.Label(win, text="When finished: turn USB debugging back OFF in "
                           "Developer options.",
                 font=(DFONT, 10, "italic"), fg=DGRAY, bg=DBG,
                 wraplength=480, justify="left").pack(
                     anchor="w", padx=20, pady=(10, 4))
        tk.Button(win, text="CLOSE", font=(DFONT, 11, "bold"),
                  fg="white", bg=DCYAN, activebackground="#0090b3",
                  activeforeground="white", relief="flat", bd=0,
                  padx=24, pady=8, cursor="hand2",
                  command=win.destroy).pack(pady=(6, 16))
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass

    # ------------------------------------------------------- render ---
    def _threat_rows(self):
        src = self.source_var.get()
        return [r for r in self.scan_data
                if r[4] in ("remove", "review")
                and (src == "All sources" or r[5] == src)]

    def _refresh_sources(self):
        srcs = sorted({r[5] for r in self.scan_data
                       if r[4] in ("remove", "review")})
        menu = self.source_menu["menu"]
        menu.delete(0, "end")
        cur = self.source_var.get()
        for s in ["All sources"] + srcs:
            menu.add_command(label=s,
                             command=lambda v=s: self.source_var.set(v))
        if cur not in (["All sources"] + srcs):
            self.source_var.set("All sources")

    def render(self):
        for w in self.inner.winfo_children():
            w.destroy()
        self.row_vars = []
        mode = self.show_var.get()

        if mode == "sites":
            if not self.sites:
                tk.Label(self.inner,
                         text="No notification sites found."
                              if self.scan_data else
                              "Run a scan to list sites allowed to send "
                              "browser notifications.",
                         font=(DFONT, 12), fg="#2c2836",
                         bg=DPANE).pack(padx=16, pady=24, anchor="w")
            for dstr, host in self.sites:
                f = tk.Frame(self.inner, bg=DPANE)
                f.pack(fill="x", padx=12, pady=5)
                tk.Label(f, text="🌐", font=(DFONT, 14), bg=DPANE).pack(
                    side="left", padx=(0, 8))
                tk.Label(f, text=host, font=(DFONT, 13, "bold"),
                         fg="#1d1a26", bg=DPANE).pack(side="left")
                tk.Label(f, text="  allowed since %s" % dstr,
                         font=(DFONT, 11), fg="#3a3547",
                         bg=DPANE).pack(side="left")
            return

        if mode == "all":
            rows = [r for r in self.scan_data if len(r) == 9]
            srcf = self.source_var.get()
            if srcf != "All sources":
                rows = [r for r in rows if r[5] == srcf]
            _ord = {"remove": 0, "review": 1, "clean": 2}
            rows.sort(key=lambda r: _ord.get(r[4], 3))
        else:
            rows = self._threat_rows()
        if not rows:
            tk.Label(self.inner,
                     text="Nothing flagged." if self.scan_data else
                     "Run a scan to check the phone for adware.",
                     font=(DFONT, 12), fg="#2c2836",
                     bg=DPANE).pack(padx=16, pady=24, anchor="w")
            return

        for _idx, (pkg, label, score, reasons, verdict, src, privacy,
                   ttype, boot) in enumerate(rows, 1):
            var = tk.BooleanVar(value=row_default_checked(pkg, verdict))
            f = tk.Frame(self.inner, bg=DPANE)
            f.pack(fill="x", padx=8, pady=5)
            tk.Label(f, text="%d." % _idx, font=(DMONO, 13, "bold"),
                     fg="#14121a", bg=DPANE, width=4,
                     anchor="e").pack(side="left", padx=(2, 2))
            cb = tk.Checkbutton(f, variable=var, bg=DPANE,
                                activebackground=DPANE,
                                selectcolor="#d8d4e2")
            cb.pack(side="left", padx=(4, 6))
            badge = {"remove": "REMOVE", "review": "REVIEW",
                     "clean": "OK"}.get(verdict, "OK")
            bcol = {"remove": "#a31616", "review": "#8a5a00",
                    "clean": "#5a5470"}.get(verdict, "#5a5470")
            tk.Label(f, text="[%s]" % badge, font=(DMONO, 12, "bold"),
                     fg=bcol, bg=DPANE).pack(side="left", padx=(0, 6))
            txt = tk.Frame(f, bg=DPANE)
            txt.pack(side="left", fill="x", expand=True)
            tk.Label(txt, text=label or pkg, font=(DFONT, 15, "bold"),
                     fg="#14121a", bg=DPANE, anchor="w").pack(fill="x")
            tk.Label(txt, text=pkg, font=(DMONO, 12),
                     fg="#241f31", bg=DPANE, anchor="w").pack(fill="x")
            if reasons:
                tk.Label(txt, text="; ".join(reasons)[:160],
                         font=(DFONT, 12), fg="#2c2836", bg=DPANE,
                         anchor="w", wraplength=640,
                         justify="left").pack(fill="x")
            self.row_vars.append((var, pkg, label or pkg))

    # ------------------------------------------------------- queue ---
    def process_queue(self):
        try:
            while True:
                try:
                    kind, payload = self.q.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle(kind, payload)
                except Exception as e:
                    self.log("display hiccup: %s" % e)
        except Exception:
            pass
        self.root.after(120, self.process_queue)

    def _handle(self, kind, payload):
        if kind == "log":
            self.log(payload)
        elif kind == "phone_ok":
            self.dot.configure(fg=DGREEN)
            self.status.configure(
                text="Phone connected -- ready to scan", fg=DTEXT)
        elif kind == "phone_model":
            self.status.configure(
                text="Phone connected -- %s" % payload, fg=DTEXT)
        elif kind == "phone_bad":
            self.dot.configure(fg=DGRAY)
            if payload == "ADB_NOT_FOUND":
                self.status.configure(
                    text="ADB not found -- install platform-tools", fg=DGRAY)
            else:
                self.status.configure(
                    text="No phone -- connect via USB", fg=DGRAY)
        elif kind == "progress":
            done, total, pkg = payload
            pct = int(done * 100 / max(total, 1))
            short = pkg if len(pkg) < 40 else pkg[:39] + "…"
            self.prog.configure(text="%d%%  %d/%d  %s"
                                     % (pct, done, total, short))
            if done == 1 or done == total or done % 25 == 0:
                self.log("… %d/%d  %s" % (done, total, short))
        elif kind == "scan_done":
            self.scan_data, self.sites = payload
            self._scan_completed = True
            self.set_busy(False)
            self.prog.configure(text="")
            n_rm = sum(1 for r in self.scan_data if r[4] == "remove")
            n_rv = sum(1 for r in self.scan_data if r[4] == "review")
            self.source_var.set("All sources")
            if n_rm + n_rv:
                self.show_var.set("flagged")
            self._refresh_sources()
            self.render()
            if self.flagged_radio is not None:
                self.flagged_radio.configure(
                    text="⚠ Flagged only (%d)" % (n_rm + n_rv))
            self.log("Scanned %d apps: %d marked for removal, "
                     "%d to review, %d notification sites."
                     % (len(self.scan_data), n_rm, n_rv, len(self.sites)))
            self._update_undo_btn()
            if self._guided_pending:
                self._guided_pending = False
                ask = self._guided_ask
                self._guided_ask = []
                n_flag = n_rm + n_rv
                if n_flag == 0 and not ask:
                    msg = ("GUIDED CLEAN finished.\n\n"
                           "This phone is CLEAN.")
                else:
                    msg = ("GUIDED CLEAN finished.\n\nFlagged now: %d."
                           % n_flag)
                    if ask:
                        msg += ("\n\nLeft for a human decision:\n"
                                + "\n".join(ask[:15]))
                        if len(ask) > 15:
                            msg += "\n+ %d more" % (len(ask) - 15)
                self.log("Guided Clean finished. Flagged now: %d."
                         % n_flag)
                messagebox.showinfo("AdTrapper", msg)
        elif kind == "update_badge":
            self.update_info = payload
            try:
                self.update_btn.configure(
                    text="\u2b06 UPDATE: v%s" % payload["version"],
                    bg="#8a5a00")
            except Exception:
                pass
            self.log("Update available: AdTrapper v%s. Click CHECK "
                     "FOR UPDATES to install it." % payload["version"])
        elif kind == "update_offer":
            self._offer_update(payload)
        elif kind == "update_install":
            info, dl_path = payload
            self._install_update(info, dl_path)
        elif kind == "scan_error":
            self.set_busy(False)
            self._guided_pending = False
            self._guided_ask = []
            self.prog.configure(text="")
            self.dot.configure(fg=DGRAY)
            if payload == "ADB_NOT_FOUND":
                self.status.configure(
                    text="ADB not found -- install platform-tools", fg=DGRAY)
                self.log("ADB not found. Download platform-tools and "
                         "extract it into your Downloads folder.")
            elif payload == "MULTI_PHONE":
                self.status.configure(text="Multiple phones -- unplug all "
                                           "but one", fg=DGRAY)
            elif payload == "SCAN_CRASHED":
                self.log("Scan interrupted -- reconnect the phone and try "
                         "again.")
            else:
                self.status.configure(text="No phone -- connect via USB",
                                      fg=DGRAY)
                self.log("No phone found. Plug it in via USB, enable USB "
                         "debugging, tap Allow, then scan again. "
                         "Click USB GUIDE for the step-by-step.")
        elif kind == "remove_done":
            removed, failed = payload
            self.set_busy(False)
            pdf_path = self._make_customer_report(removed, failed)
            if pdf_path:
                self.last_report_path = pdf_path
                self.print_btn.configure(state="normal")
                if self.autoprint_var.get():
                    self._print_report(pdf_path)
            if failed:
                msg = ("Removal finished, but these could NOT be removed:\n\n"
                       + "\n".join(failed)
                       + "\n\nThey are probably device admins -- turn them "
                         "off in Settings > Security and privacy > "
                         "Device admin apps first.")
                if pdf_path:
                    msg += "\n\nCustomer report saved:\n%s" % pdf_path
                messagebox.showwarning("AdTrapper", msg)
            else:
                msg = ("Removal finished.\n\nReboot the phone and check the "
                       "popups are gone.\n")
                if pdf_path:
                    msg += "\nCustomer report saved:\n%s" % pdf_path
                messagebox.showinfo("AdTrapper", msg)
            self.log("Done. Reboot the phone and check the popups are gone.")
            self.start_scan()
        elif kind == "undo_done":
            self.set_busy(False)
            messagebox.showinfo("AdTrapper", "Restore complete.")
            self._update_undo_btn()
            self.start_scan()

    # ------------------------------------------------------- remove ---
    def _checked(self):
        return [(pkg, label) for var, pkg, label in self.row_vars
                if var.get()]

    # ------------------------------------------------- guided clean ---
    def _guided_dialog(self, sections, ask):
        """The Guided Clean color guide (issue #49).

        A real window, not a messagebox: every app line is WRITTEN in
        its pile color -- RED = take it off, GREEN = it stays, YELLOW
        = not sure, ask first -- with its scan number in front, on the
        guide's original background (no color blocks: the owner found
        solid bands wash the words out). Staff and customers follow
        the guide by color alone. Returns True only on explicit YES."""
        answer = {"ok": False}
        win = tk.Toplevel(self.root)
        win.title("AdTrapper -- Guided Clean")
        win.configure(bg=DBG)
        try:
            win.minsize(760, 480)
        except Exception:
            pass
        tk.Label(win, text="GUIDED CLEAN", font=(DFONT, 14, "bold"),
                 fg="white", bg=DBG).pack(anchor="w", padx=16,
                                          pady=(14, 2))
        tk.Label(win, text="Follow the colors. Red comes off. Green "
                           "stays. Yellow -- leave it and ask first.",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     anchor="w", padx=16, pady=(0, 8))
        legend = tk.Frame(win, bg=DBG)
        legend.pack(fill="x", padx=16, pady=(0, 10))
        for key, word in (("remove", "RED = REMOVE IT"),
                          ("keep", "GREEN = IT STAYS"),
                          ("ask", "YELLOW = NOT SURE -- ASK FIRST")):
            tk.Label(legend, text="  %s  " % word,
                     font=(DFONT, 11, "bold"),
                     fg=GUIDE_PILE_STYLE[key],
                     bg=DBG).pack(side="left", padx=(0, 8))
        body = tk.Frame(win, bg=DBG)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        txt = tk.Text(body, font=(DFONT, 11), bg=DBAR, fg=DTEXT,
                      relief="flat", bd=0, wrap="none", height=22,
                      width=86, highlightthickness=0)
        ysb = tk.Scrollbar(body, orient="vertical", command=txt.yview)
        xsb = tk.Scrollbar(body, orient="horizontal",
                           command=txt.xview)
        txt.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        txt.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        for key, color in GUIDE_PILE_STYLE.items():
            txt.tag_configure(key, foreground=color,
                              font=(DFONT, 12, "bold"))
            txt.tag_configure("hdr_" + key, foreground=color,
                              font=(DFONT, 13, "bold"))
        lineno = 1
        for key, header, lines in sections:
            txt.insert("end", header + "\n")
            txt.tag_add("hdr_" + key, "%d.0" % lineno,
                        "%d.0" % (lineno + 1))
            lineno += 1
            if not lines:
                txt.insert("end", "(none)\n")
                lineno += 1
            for num, name, _row in lines:
                start = "%d.0" % lineno
                txt.insert("end", "%d. %s\n" % (num, name))
                txt.tag_add(key, start, "%d.0" % (lineno + 1))
                lineno += 1
            txt.insert("end", "\n")
            lineno += 1
        txt.configure(state="disabled")
        btns = tk.Frame(win, bg=DBG)
        btns.pack(fill="x", padx=16, pady=(4, 14))
        if ask:
            tk.Label(btns, text="Remove the junk (the red ones) now?",
                     font=(DFONT, 11, "bold"), fg=DTEXT,
                     bg=DBG).pack(side="left")

            def _yes():
                answer["ok"] = True
                win.destroy()

            tk.Button(btns, text="YES, REMOVE",
                      font=(DFONT, 11, "bold"), fg="white", bg=DRED,
                      activebackground="#a81f1f",
                      activeforeground="white", relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2",
                      command=_yes).pack(side="right")
            tk.Button(btns, text="NO", font=(DFONT, 11, "bold"),
                      fg=DTEXT, bg=DBAR, activebackground=DBAR,
                      activeforeground="white", relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2",
                      command=win.destroy).pack(side="right",
                                                padx=(0, 10))
        else:
            tk.Label(btns, text="Nothing in the junk pile -- nothing "
                                "to remove.",
                     font=(DFONT, 11, "bold"), fg=DTEXT,
                     bg=DBG).pack(side="left")
            tk.Button(btns, text="CLOSE", font=(DFONT, 11, "bold"),
                      fg="white", bg=DCYAN, activebackground="#0090b3",
                      activeforeground="white", relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2",
                      command=win.destroy).pack(side="right")
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass
        win.wait_window()
        return answer["ok"]

    def guided_clean(self):
        """Beginner mode: sort the flagged list into junk / yours / ask
        and show the COLOR guide (issue #49): red lines are removed,
        green lines are never touched, yellow lines stay on the phone
        for a human. Numbers in the guide are the main-list scan
        numbers (issue #46). Removes ONLY the junk pile, and only
        after an explicit YES. The automatic re-scan after removal
        reports the final verdict."""
        if self.busy:
            return
        if not self.scan_data:
            self.log("Guided Clean: no scan yet -- scanning first. "
                     "Press GUIDED CLEAN again when the list appears.")
            self.start_scan()
            return
        sections = guided_sections(self.scan_data)
        rows = {k: [r for _n, _name, r in lines]
                for k, _h, lines in sections}
        if not rows["remove"]:
            self._guided_dialog(sections, ask=False)
            return
        if not self._guided_dialog(sections, ask=True):
            return
        targets = [(r[0], r[1] or r[0]) for r in rows["remove"]]
        self._guided_pending = True
        self._guided_ask = [(r[1] or r[0]) for r in rows["ask"]]
        self.set_busy(True)
        threading.Thread(target=self._do_remove, args=(targets,),
                         daemon=True).start()

    def remove_all(self):
        if self.busy:
            return
        targets = self._checked()
        if not targets:
            messagebox.showinfo("AdTrapper", "Nothing checkmarked.")
            return
        names = "\n".join(l for _, l in targets)
        if not messagebox.askyesno(
                "AdTrapper",
                "Remove %d app(s)?\n\n%s\n\nApps are backed up first -- "
                "UNDO restores them." % (len(targets), names)):
            return
        self.set_busy(True)
        threading.Thread(target=self._do_remove, args=(targets,),
                         daemon=True).start()

    def _do_remove(self, targets):
        failed, removed = [], []
        bdir = self._backup_dir()
        for pkg, label in targets:
            self.q.put(("log", "Backing up %s ..." % label))
            apk = backup_apk(pkg, bdir)
            if not apk:
                self.q.put(("log", "  [!] Warning: Backup failed for %s (APK pull failed; undo will not be available)" % label))
            self.q.put(("log", "Removing %s ..." % label))
            result = uninstall_core(pkg)
            self.q.put(("log", "  %s: %s" % (label, result)))
            if result.startswith("COULD NOT REMOVE"):
                failed.append(label)
            else:
                removed.append({"pkg": pkg, "label": label, "apk": apk,
                                "result": result})
                _save_local_bad([pkg])
                LEARNED_BAD.add(pkg)
        if removed:
            self._write_undo_manifest(removed)
        self.q.put(("remove_done", (removed, failed)))

    # ------------------------------------------------------- undo ---
    def _update_undo_btn(self):
        try:
            self.undo_btn.configure(
                state="normal" if self._read_undo_manifest()
                else "disabled")
        except Exception:
            pass

    def undo_last(self):
        man = self._read_undo_manifest()
        if self.busy or not man:
            return
        apps = man.get("apps", [])
        names = "\n".join(a["label"] for a in apps)
        if not messagebox.askyesno(
                "AdTrapper",
                "Restore %d app(s)?\n\n%s" % (len(apps), names)):
            return
        self.set_busy(True)
        threading.Thread(target=self._do_undo, args=(apps,),
                         daemon=True).start()

    def _do_undo(self, apps):
        man = self._read_undo_manifest() or {"apps": []}
        remaining = [a for a in man.get("apps", [])
                     if a["pkg"] not in {x["pkg"] for x in apps}]
        for a in apps:
            pkg, label, apk = a["pkg"], a["label"], a.get("apk")
            self.q.put(("log", "Restoring %s ..." % label))
            ok = False
            if apk and Path(apk).is_file():
                ok = "Success" in adb_cmd("install", "-r", apk)
            if not ok:
                ok = "Success" in adb_cmd("shell", "pm",
                                          "install-existing", pkg)
            self.q.put(("log", "  %s: %s"
                                % (label,
                                   "restored" if ok else "COULD NOT RESTORE")))
        if remaining:
            man["apps"] = remaining
            try:
                self._undo_manifest_path().write_text(json.dumps(man))
            except Exception:
                pass
        else:
            self._clear_undo_manifest()
        self.q.put(("undo_done", ""))

    # ------------------------------------------------- report details ---
    def _ask_report_details(self):
        """Ask once per phone session for the customer name + POS ticket
        number printed on the cleanup report (the bank-proof paper)."""
        if self._details_asked:
            return
        self._details_asked = True
        dlg = tk.Toplevel(self.root)
        dlg.title("Report details")
        dlg.configure(bg=DBG)
        dlg.transient(self.root)
        tk.Label(dlg, text="Who is this report for?",
                 font=(DFONT, 13, "bold"), fg=DTEXT, bg=DBG).pack(
                     padx=18, pady=(14, 4), anchor="w")
        tk.Label(dlg, text="Customer name:", font=(DFONT, 11),
                 fg=DTEXT, bg=DBG).pack(padx=18, anchor="w")
        name_e = tk.Entry(dlg, font=(DFONT, 13), width=28)
        name_e.insert(0, self.report_customer)
        name_e.pack(padx=18, pady=(0, 8))
        tk.Label(dlg, text="Ticket number (like R-1378):",
                 font=(DFONT, 11), fg=DTEXT, bg=DBG).pack(padx=18, anchor="w")
        tick_e = tk.Entry(dlg, font=(DFONT, 13), width=28)
        tick_e.insert(0, self.report_ticket)
        tick_e.pack(padx=18, pady=(0, 8))
        tk.Label(dlg, text="Technician (printed on the report):",
                 font=(DFONT, 11), fg=DTEXT, bg=DBG).pack(padx=18,
                                                          anchor="w")
        tech_e = tk.Entry(dlg, font=(DFONT, 13), width=28)
        tech_e.insert(0, self.report_technician)
        tech_e.pack(padx=18, pady=(0, 10))

        def _ok():
            self.report_customer = name_e.get().strip()
            self.report_ticket = tick_e.get().strip()
            self.report_technician = tech_e.get().strip()
            dlg.destroy()

        brow = tk.Frame(dlg, bg=DBG)
        brow.pack(pady=(0, 14))
        tk.Button(brow, text="OK", font=(DFONT, 12, "bold"), fg="white",
                  bg=DGREEN, relief="flat", bd=0, padx=26, pady=8,
                  cursor="hand2", command=_ok).pack(side="left")
        tk.Button(brow, text="Skip", font=(DFONT, 12), fg=DTEXT,
                  bg="#2a2a35", relief="flat", bd=0, padx=20, pady=8,
                  cursor="hand2", command=dlg.destroy).pack(
                      side="left", padx=(10, 0))
        name_e.focus_set()
        try:
            dlg.grab_set()
        except Exception:
            pass
        self.root.wait_window(dlg)

    def _make_inspection_report(self):
        """Cleanup report for a phone that scanned CLEAN -- the bank
        proof that we looked at the phone and nothing was found."""
        try:
            self._ask_report_details()
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            ver = adb_cmd("shell", "getprop",
                          "ro.build.version.release").strip()
            serial = adb_cmd("shell", "getprop",
                             "ro.serialno").strip()
            device_info = {"model": model or "Unknown",
                           "android": ver or "Unknown",
                           "serial": serial or "Unknown",
                           "customer": self.report_customer,
                           "ticket": self.report_ticket,
                           "technician": self.report_technician}

            def _kw(*kws):
                n = 0
                for t in self.scan_data:
                    r = str(t[3]).lower()
                    if any(k in r for k in kws):
                        n += 1
                return n

            scan_summary = {
                "apps": len(self.scan_data),
                "threat_count": len(KNOWN_BAD),
                "overlay": _kw("overlay", "draw over", "popup permission"),
                "admin": _kw("device admin"),
                "a11y": _kw("accessibility"),
            }
            reports_dir = self._script_dir() / "CustomerReports"
            path = generate_customer_report(
                device_info, [], [], self.sites, scan_summary,
                str(reports_dir))
            if path:
                self.log("Inspection report: %s" % path)
            return path
        except Exception as e:
            self.log("Inspection report failed: %s" % e)
            return None

    # ------------------------------------------------------- print ---
    def _printer_names(self):
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Printer | ForEach-Object { $_.Name }"],
                capture_output=True, text=True, timeout=25,
                creationflags=0x08000000).stdout
            return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception:
            return []

    def _print_report(self, path=None):
        path = path or self.last_report_path
        if not path and self._scan_completed:
            n_flag = sum(1 for t in self.scan_data
                         if t[4] in ("remove", "review"))
            if n_flag == 0:
                p = self._make_inspection_report()
                if p:
                    self.last_report_path = p
                    path = p
            else:
                self.log("This phone still has %d flagged app(s) - run "
                         "the clean first; the report is made when the "
                         "clean finishes." % n_flag)
                return
        if not path:
            # no report this session: use the newest saved one
            try:
                folder = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "CustomerReports")
                pdfs = [os.path.join(folder, f) for f in os.listdir(folder)
                        if f.lower().endswith(".pdf")]
                if pdfs:
                    path = max(pdfs, key=os.path.getmtime)
                    self.last_report_path = path
            except Exception:
                pass
        if not path:
            self.log("No report to print yet - do a cleanup first.")
            return
        if sys.platform != "win32":
            self.log("Printing works on the shop PC (Windows) only.")
            return
        target = None
        for n in self._printer_names():
            if "laserjet" in n.lower():
                target = n
                break
        if target:
            try:
                subprocess.run(
                    ["rundll32", "printui.dll,PrintUIEntry", "/y",
                     "/n", target],
                    timeout=25, capture_output=True,
                    creationflags=0x08000000)
                self.log("Printing to: %s" % target)
            except Exception as e:
                self.log("Note: Could not switch default printer to %s (%s)" % (target, e))
        else:
            self.log("No LaserJet found - using the default printer.")
        try:
            os.startfile(path, "print")
            self.log("Report sent to the printer: %s"
                     % os.path.basename(path))
        except Exception as e:
            self.log("Auto-print failed (%s) - opening the report so "
                     "you can print it from there." % e)
            try:
                os.startfile(path)
            except Exception:
                pass

    # ------------------------------------------------------- report ---
    def _make_customer_report(self, removed, failed):
        try:
            self._ask_report_details()
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            ver = adb_cmd("shell", "getprop",
                          "ro.build.version.release").strip()
            serial = adb_cmd("shell", "getprop",
                             "ro.serialno").strip()
            device_info = {"model": model or "Unknown",
                           "android": ver or "Unknown",
                           "serial": serial or "Unknown",
                           "customer": self.report_customer,
                           "ticket": self.report_ticket,
                           "technician": self.report_technician}
            pkg_to_threat = {}
            for t in self.scan_data:
                # scan_core 9-tuple:
                # (pkg, label, score, reasons, verdict, source_cat,
                #  privacy, threat_type, boot_hit)
                pkg_to_threat[t[0]] = (t[1], t[0], t[3], t[4])

            def _kw_count(*kws):
                n = 0
                for t in self.scan_data:
                    r = str(t[3]).lower()
                    if any(k in r for k in kws):
                        n += 1
                return n

            scan_summary = {
                "apps": len(self.scan_data),
                "threat_count": len(KNOWN_BAD),
                "overlay": _kw_count("overlay", "draw over",
                                     "popup permission"),
                "admin": _kw_count("device admin"),
                "a11y": _kw_count("accessibility"),
            }
            threats, actions = [], []
            for r in removed:
                pkg, label = r["pkg"], r["label"]
                result = r.get("result", "removed")
                if pkg in pkg_to_threat:
                    threats.append(pkg_to_threat[pkg])
                else:
                    threats.append((label, pkg, "flagged by scan", "remove"))
                actions.append((label, result))
            for lbl in failed:
                actions.append((lbl, "Could not remove"))
            reports_dir = self._script_dir() / "CustomerReports"
            path = generate_customer_report(
                device_info, threats, actions, self.sites, scan_summary,
                str(reports_dir))
            if path:
                self.log("Customer report: %s" % path)
            else:
                self.log("Customer report could not be generated (PDF generator returned empty)")
            return path
        except Exception as e:
            self.log("Report failed: %s" % e)
            return None


def main():
    root = tk.Tk()
    PopupBlockerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
