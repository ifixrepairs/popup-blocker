"""PrintMyTexts v1.7.1 — standalone Windows transcript tool (Python 3.10+).

v1.7.1 (owner order, 2026-11-08 — button contrast fix): the owner
photographed v1.7 on his Mac — 'Read USB phone', 'Browse Files', and
'View Transcript' rendered as near-white boxes with unreadable text,
because macOS Tk/Aqua ignores a tk.Button's custom colors. Those
three buttons are BLACK buttons now (black background, white bold
text), readable in every state — normal and disabled alike — and
drawn on a canvas so Mac and Windows look the same. Every other
action button keeps its colors; only its disabled text changed, to
a clearly readable color for its background. Same pass, also on
the owner's word: the sidebar 'robot' and 'apple' symbols are
ChatGPT-drawn images embedded in this file — the full Android
robot for Import from Phone and the bitten apple for Import
from iPhone. The owner rejected the code-drawn versions
("That's ugly") and ordered ChatGPT's artwork pasted in
instead (owner order, 2026-11-08); the embedded PNGs below are
that artwork, trimmed and downscaled, decoded at runtime. If an
embedded image ever fails to decode, the previous code-drawn
symbol is the fallback — never a blank button. Nothing else
changes: parsing, documents, emoji, and the update machinery
are v1.7's.

v1.7 (owner orders, 2026-11-08): the sidebar navigation is refaced to
the owner's picture — big rounded COLORED buttons with a white symbol
and white bold label (green Import from Phone, purple Import XML File
with the plain-words line 'Opens a saved backup file' under the name,
bright-blue Import from iPhone, orange Print / Export, slate Settings,
solid blue UPDATE bar). The Home and Message Transcript tabs are gone
by the owner's word: Home is reached by tapping the app title, and a
finished import already lands on the open conversation. Grok's
upgrades from the three-bot ideas harvest ride along: quick date
presets (Last 7 days / Last 30 days / This month / All time),
conversation search by name or digits, the preview page count shown
before printing, plain-text (.txt) export beside the PDF, and
print-all / multi-select printing. Everything else — parsing, the
bubble paper layout, the letterhead-free documents with the one-line
(c) footer, the update machinery, the privacy spine — is the v1.6
build unchanged.

v1.6 is the owner's fix pass on v1.5 (owner order, 2026-11-08): the paper
transcript is laid out like the on-screen chat — the other person on the
LEFT, the phone owner on the RIGHT, in tinted bubbles — instead of flat
full-width lines; opening a conversation lands on the bubble view;
documents no longer carry the shop name/address/phone letterhead and say
the times are the phone's time; 'Import XML File' is renamed 'Import
from a Backup File'; a finished import lands straight on the messages;
the phone page always says in plain words what it is waiting for; and
Settings explains every button in one plain line each. The v1.5 Light
Professional face (owner order, 2026-10-26) is unchanged: white and very
light gray surfaces, thin light borders, dark navy text, plain text
labels, no decorative glyph icons, 1200x700 default window with
remembered size/position.

No third-party modules. ADB is an external USB-only executable. Importing this
file does not start the GUI; parsers/layout are independently testable.
"""
from __future__ import annotations

import atexit
import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, replace
from datetime import datetime, date, timedelta
import hashlib
import html
import json
import os
from pathlib import Path
import queue
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unicodedata
import urllib.request
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import zlib

VERSION = '1.7.1'
UPDATE_MANIFEST_URL = ('https://raw.githubusercontent.com/ifixrepairs/'
                       'popup-blocker/main/printmytexts-version.json')
UPDATE_ALIVE_SECONDS = 10
UPDATE_STABLE_ALIAS = 'PrintMyTexts-PC.pyw'

SHOP = 'iFixx Repairs'
ADDRESS = '2828 S McCall Rd Unit 346, Englewood, FL 34224'
PHONE = '(941) 875-7511'
NOTICE = 'Processed locally on this computer — nothing leaves this computer.'
COPYRIGHT_LINE = '© 2026 iFixx Repairs. All rights reserved.'
COPYRIGHT_PRIVATE = '© 2026 PrintMyTexts. All rights reserved.'
# Light Professional palette (v1.5 restyle, owner order 2026-10-26).
# Screen-only theme: printed pages stay black on white, exactly as shipped.
# Token values mirror AdTrapper's owner-crowned Light Professional face:
# white / very light gray surfaces, thin light borders, dark navy text,
# soft meaning-colors only, no decorative glyph icons.
LP_BG = '#F2F4F7'            # app ground
LP_SURFACE = '#FFFFFF'       # sidebar, cards, panels
LP_BORDER = '#D8DEE7'        # thin light borders / dividers
LP_INK = '#152A44'           # dark navy text
LP_SECONDARY = '#48596C'     # supporting text
LP_MUTED = '#8593A5'         # metadata / captions
LP_DOOR_BG = '#E9EDF2'       # neutral buttons / doors
LP_DOOR_HOVER = '#D9E1EA'
LP_PANEL_BG = '#EEF1F5'      # inset panels, fields, status bar
LP_SEL_BG = '#EAF2FD'        # selected-row calm tint
# Legacy constant names (kept for the existing code, token-driven):
BG_APP = LP_BG              # root window
BG_SIDEBAR = LP_SURFACE     # navigation sidebar
BG_TOPBAR = LP_PANEL_BG     # header / status bar
BG_PANEL = LP_SURFACE       # standard panel
BG_PANEL_ALT = LP_DOOR_BG   # neutral buttons / inset panels
BG_INPUT = LP_PANEL_BG      # input fields
BG_HOVER = LP_DOOR_HOVER    # hovered rows/cards
NAV_SELECTED = LP_SEL_BG    # selected navigation row
BORDER = LP_BORDER
BORDER_STRONG = '#B7C2CF'
TEXT_PRIMARY = LP_INK
TEXT_SECONDARY = LP_SECONDARY
TEXT_MUTED = LP_MUTED
TEXT_DISABLED = '#A9B4C0'
ACCENT = '#1F5FA6'          # primary buttons (professional navy blue)
ACCENT_HOVER = '#2B74C2'
ACCENT_PRESSED = '#17497F'
FOCUS_RING = '#7FB3E0'
NAV_INDICATOR = ACCENT      # selected-row accent
TOOL_PHONE = '#2E86AB'      # Import from Phone accent (muted steel blue)
TOOL_XML = '#4A6FA5'        # Import from a Backup File accent (muted slate blue)
TOOL_XML_PRIMARY = '#3D5A80'
TOOL_TRANSCRIPT = ACCENT    # Message Transcript accent
TOOL_EXPORT = '#2E7D4F'     # Print / Export accent (muted green)
EXPORT_CONFIRM = '#256B43'
CLEAR_RED = '#B42318'
STATUS_OK = '#1E8E4F'
STATUS_WORK = ACCENT
STATUS_WARN = '#B25E09'
STATUS_ERROR = '#B42318'
# On-screen chat (light timeline in the light shell).
CHAT_BG = '#FFFFFF'
BUBBLE_CUSTOMER = '#E7EDF3'        # contact, LEFT
BUBBLE_CUSTOMER_TEXT = LP_INK
BUBBLE_CUSTOMER_META = LP_SECONDARY
BUBBLE_CUSTOMER_TIME = LP_MUTED
BUBBLE_OWNER = ACCENT               # phone owner, RIGHT — strong blue (owner 2026-10-26:
                                    # the two sides must be unmistakably different colors)
BUBBLE_OWNER_TEXT = '#FFFFFF'       # white on the strong-blue sent bubble
BUBBLE_OWNER_META = '#2E5A88'
BUBBLE_OWNER_TIME = LP_SECONDARY
BUBBLE_UNKNOWN = '#E2E8EF'
DATE_SEP_BG = '#E2E8EF'
DATE_SEP_FG = LP_SECONDARY
PREVIEW_BG = '#D9E1EA'             # paper preview surround
COLORS = {
    'bg_app': BG_APP, 'bg_sidebar': BG_SIDEBAR, 'bg_topbar': BG_TOPBAR,
    'bg_panel': BG_PANEL, 'bg_panel_alt': BG_PANEL_ALT, 'bg_input': BG_INPUT,
    'bg_hover': BG_HOVER, 'border': BORDER, 'border_strong': BORDER_STRONG,
    'text_primary': TEXT_PRIMARY, 'text_secondary': TEXT_SECONDARY,
    'text_muted': TEXT_MUTED, 'text_disabled': TEXT_DISABLED,
    'primary': ACCENT, 'primary_hover': ACCENT_HOVER,
    'primary_pressed': ACCENT_PRESSED, 'focus': FOCUS_RING,
    'phone': TOOL_PHONE, 'xml': TOOL_XML, 'transcript': TOOL_TRANSCRIPT,
    'export': TOOL_EXPORT, 'success': STATUS_OK, 'warning': STATUS_WARN,
    'error': STATUS_ERROR, 'chat_background': CHAT_BG,
    'bubble_customer': BUBBLE_CUSTOMER, 'bubble_owner': BUBBLE_OWNER,
    'bubble_text': BUBBLE_CUSTOMER_TEXT,
    'pdf_customer': '#F0F2F5', 'pdf_owner': '#E9F1F9',
}
# v1.7 sidebar faces (owner's picture, 2026-11-08): each navigation
# button is a big rounded gradient button with a white symbol and a
# white bold label. Gradient stops sampled from the owner's photo.
NAV_GREEN = ('#63B84E', '#3E8A2C')        # Import from Phone
NAV_PURPLE = ('#7E63B8', '#5B4395')       # Import XML File
NAV_BLUE = ('#3590F0', '#1668DC')         # Import from iPhone
NAV_ORANGE = ('#F39A35', '#E07B12')       # Print / Export
NAV_SETTINGS = ('#506A8E', '#38536F')     # Settings
UPDATE_BLUE = '#1270D8'                   # the UPDATE bar under the tabs
UPDATE_BLUE_HOVER = '#0F62BE'
# v1.7.1 (owner order, 2026-11-08): the owner's black action style —
# Read USB phone / Browse Files / View Transcript wear it in EVERY
# state, normal and disabled, so they can always be read.
BTN_BLACK_BG = '#000000'                  # black action buttons
BTN_BLACK_FG = '#FFFFFF'                  # white bold text on the black
BTN_BLACK_DISABLED_FG = '#FFFFFF'         # disabled keeps white — never pale
PRIVATE_NOTICE = 'Processed locally — no data leaves this computer.'
FONT_FACE = 'Verdana'  # wide, high-legibility print face (owner readability request)
BODY_FONT_SIZE = 18
UI_NOTICE = 'Processed locally at iFixx Repairs — nothing leaves this computer.'
# Settings help (v1.6, owner order 2026-11-08): every sidebar item and
# button explained in ONE plain line — simple words, no jargon.
HELP_LINES = (
    ('Home', 'The start page. Pick how you want to bring your messages in.'),
    ('Import from Phone', 'Reads messages from an Android phone plugged in with a cable.'),
    ('Import XML File', 'Opens a backup file you saved earlier from a phone.'),
    ('Import from iPhone', 'An iPhone cannot be read with a cable. Save a backup of its messages first, then open that backup file here.'),
    ('Message Transcript', 'Shows your conversations. Tap one to read it like a text chat.'),
    ('Print', 'Prints the conversation you have open, on paper.'),
    ('Export', 'Saves the conversation you have open as a PDF file you can keep.'),
    ('Settings', 'This page — app information, update checks, and this help.'),
    ('Update', 'The UPDATE button gets the newest PrintMyTexts when one is ready. Nothing about your messages is ever sent anywhere.'),
    ('Connect phone', 'Takes you to the Import from Phone page.'),
    ('Choose backup file', 'Opens the file picker so you can pick a backup file straight away.'),
    ('Open transcript', 'Opens the conversation page — the Print / Export button on the left opens that same page.'),
    ('Read USB phone', 'Starts reading the messages from the phone plugged in with a cable.'),
    ('Browse Files', 'Opens the file picker so you can pick the backup file on this computer.'),
    ('Back', 'Goes back to the Home page.'),
    ('View Transcript', 'Takes you to the Message Transcript page to read the conversations.'),
    ('Chat view', 'Shows the conversation as text-message bubbles.'),
    ('Paper view', 'Shows the conversation the way the printed page will look.'),
    ('Previous page (◀)', 'Shows the page before this one.'),
    ('Next page (▶)', 'Shows the page after this one.'),
    ('Apply / preview', 'Puts the name and dates you typed onto the conversation and shows it again.'),
    ('Search conversations', 'Finds a conversation by the name or the number.'),
    ('Last 7 days', 'Shows only the messages from the last 7 days.'),
    ('Last 30 days', 'Shows only the messages from the last 30 days.'),
    ('This month', 'Shows only the messages from this month.'),
    ('All time', 'Shows every message, with no date limits.'),
    ('Print all conversations', 'Prints or saves every conversation at once, each one starting on its own page.'),
    ('Hide the phone number (private print)', 'When this is ticked, the phone number is left off the print and the PDF.'),
    ('Check for updates', 'Checks if a newer PrintMyTexts is ready — the same check as the UPDATE button.'),
)
PICTURE = '[Picture message]'
UNREADABLE = '[Unreadable message]'
PAGE_W, PAGE_H = 850, 1100  # fixed US Letter layout at 100 pixels/inch
MARGIN, BODY_TOP, BODY_BOTTOM = 45, 170, 1010
LINE_HEIGHT = 20


@dataclass(frozen=True)
class Message:
    address: str
    timestamp: int | None  # epoch milliseconds; None is explicitly unreadable
    direction: str         # received, sent, unreadable
    body: str
    thread_id: str = ''
    contact_name: str = ''
    kind: str = 'sms'


@dataclass
class ReadResult:
    messages: list[Message]
    warnings: list[str]


def timestamp(value, seconds=False):
    try:
        result = int(value) * (1000 if seconds else 1)
        datetime.fromtimestamp(result / 1000)
        return result
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def clean(value):
    return '' if value is None or value == 'null' else str(value)


def parse_content_rows(output, columns):
    """Decode Android's unescaped display format, preserving commas/newlines.

    Use projections with free text LAST. Metadata delimiters are then consumed
    only before that field. Arbitrary default-order body output is inherently
    ambiguous; reject an ambiguous row rather than guess a message's contents.
    Returns (rows, warnings), including partial rows so they remain visible.
    """
    rows, warnings = [], []
    starts = list(re.finditer(r'(?m)^Row: \d+\s+', output))
    if not starts:
        if output.strip() and 'No result found' not in output:
            warnings.append('Provider output was unreadable; import from a backup file instead.')
        return rows, warnings
    for index, start in enumerate(starts):
        raw = output[start.end():starts[index + 1].start() if index + 1 < len(starts) else len(output)]
        raw = raw.removesuffix('\n').removesuffix('\r')
        row, pos, bad = {}, 0, False
        for field in columns[:-1]:
            match = re.match(re.escape(field) + r'=(.*?), (?=' + re.escape(columns[len(row) + 1]) + r'=)', raw[pos:], re.S)
            if not match:
                bad = True
                break
            row[field] = match.group(1)
            pos += match.end()
        final = columns[-1] + '='
        if not bad and raw[pos:].startswith(final):
            row[columns[-1]] = raw[pos + len(final):]
        else:
            warnings.append(f'Row {index + 1} has unreadable fields; retained as unreadable.')
            # Recover only individually unambiguous metadata, never body text.
            for field in columns[:-1]:
                found = re.findall(r'(?:^|, )' + re.escape(field) + r'=([^,\n]*)', raw)
                if len(found) == 1:
                    row[field] = found[0]
            row[columns[-1]] = None
        rows.append(row)
    return rows, warnings


SMS_COLUMNS = ('_id', 'thread_id', 'address', 'date', 'type', 'body')
MMS_COLUMNS = ('_id', 'thread_id', 'date', 'msg_box')
PART_COLUMNS = ('_id', 'ct', 'text')
ADDR_COLUMNS = ('type', 'address')
CONTACT_COLUMNS = ('data1', 'display_name')


def parse_sms(output):
    rows, warnings = parse_content_rows(output, SMS_COLUMNS)
    messages = []
    for row in rows:
        stamp = timestamp(row.get('date'))
        direction = {'1': 'received', '2': 'sent'}.get(row.get('type'), 'unreadable')
        if stamp is None or direction == 'unreadable':
            warnings.append('An SMS has an unreadable date or direction; not guessed.')
        messages.append(Message(clean(row.get('address')) or '[Unreadable number]', stamp,
                                direction, UNREADABLE if row.get('body') is None or row.get('body') == 'null' else row['body'],
                                clean(row.get('thread_id'))))
    return ReadResult(messages, warnings)


def mms_body(parts):
    texts = [clean(p.get('text')) for p in parts if p.get('ct') == 'text/plain' and clean(p.get('text'))]
    pictures = any(clean(p.get('ct')).startswith(('image/', 'video/', 'audio/')) for p in parts)
    unreadable = any(p.get('ct') == 'text/plain' and not clean(p.get('text')) for p in parts)
    if pictures or not parts:
        texts.append(PICTURE)
    if unreadable or (parts and not texts):
        texts.append(UNREADABLE)
    return '\n'.join(texts)


def parse_mms(output, parts_by_id, addresses_by_id):
    rows, warnings = parse_content_rows(output, MMS_COLUMNS)
    messages = []
    for row in rows:
        ident = clean(row.get('_id'))
        direction = {'1': 'received', '2': 'sent'}.get(row.get('msg_box'), 'unreadable')
        addr_rows, addr_warnings = parse_content_rows(addresses_by_id.get(ident, ''), ADDR_COLUMNS)
        parts, part_warnings = parse_content_rows(parts_by_id.get(ident, ''), PART_COLUMNS)
        warnings.extend(addr_warnings + part_warnings)
        addr_type = '137' if direction == 'received' else '151'
        addresses = list(dict.fromkeys(clean(a.get('address')) for a in addr_rows
                                       if a.get('type') == addr_type and clean(a.get('address'))
                                       and a.get('address') != 'insert-address-token'))
        address = '; '.join(addresses) or '[Unreadable number]'
        stamp = timestamp(row.get('date'), seconds=True)
        if stamp is None or direction == 'unreadable' or not addresses:
            warnings.append('An MMS has unreadable metadata; use a backup file to verify completeness.')
        messages.append(Message(address, stamp, direction, mms_body(parts),
                                clean(row.get('thread_id')), kind='mms'))
    return ReadResult(messages, warnings)


def parse_xml(path):
    """SMS Backup & Restore SMS/MMS -> the same Message shape as ADB.

    DTD/entity declarations are rejected; binary MMS data is never decoded.
    Source files are read only and are not copied into the working directory.
    """
    if Path(path).stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Backup exceeds the 128 MB import limit.')
    data = Path(path).read_bytes()
    # Reject declarations even in UTF-16/32 inputs.
    if re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', data.replace(b'\0', b''), re.I):
        raise ValueError('Declarations inside the backup file are not supported.')
    root = ET.fromstring(data)
    if root.tag != 'smses':
        raise ValueError('Choose a backup file from the SMS Backup & Restore app.')
    messages, warnings = [], []
    for node in root:
        if node.tag not in ('sms', 'mms'):
            warnings.append('Unsupported backup record was not imported.')
            continue
        attrs = node.attrib
        direction = {'1': 'received', '2': 'sent'}.get(attrs.get('type' if node.tag == 'sms' else 'msg_box'), 'unreadable')
        # SMS Backup & Restore writes SMS dates in milliseconds, MMS dates in seconds.
        stamp = timestamp(attrs.get('date'), seconds=node.tag == 'mms')
        address = clean(attrs.get('address')) or '[Unreadable number]'
        if node.tag == 'sms':
            body = attrs.get('body')
            body = UNREADABLE if body is None or body == 'null' else body
        else:
            body = mms_body([p.attrib for p in node.findall('./parts/part')])
            addr_type = '137' if direction == 'received' else '151'
            addresses = list(dict.fromkeys(clean(a.get('address')) for a in node.findall('./addrs/addr')
                                           if a.get('type') == addr_type and clean(a.get('address'))
                                           and a.get('address') != 'insert-address-token'))
            if addresses:
                address = '; '.join(addresses)
        if stamp is None or direction == 'unreadable' or address == '[Unreadable number]':
            warnings.append('A backup message has unreadable metadata; not guessed.')
        name = clean(attrs.get('contact_name'))
        if name == '(Unknown)':
            name = ''
        messages.append(Message(address, stamp, direction, body, clean(attrs.get('thread_id')), name, node.tag))
    return ReadResult(messages, warnings)


def number_key(number):
    # Do not equate different country codes or group recipients by last digits.
    return re.sub(r'[\s().-]', '', number)


def conversation_key(message):
    # XML has no reliable thread IDs. Prefer the actual participant address.
    if message.address == '[Unreadable number]' and message.thread_id:
        return 'unreadable-thread:' + message.thread_id
    return number_key(message.address)


def conversations(messages):
    grouped = {}
    for message in messages:
        grouped.setdefault(conversation_key(message), []).append(message)
    return grouped


def ordered(messages):
    # Unknown timestamps go last and stay explicitly unknown, stable on ties.
    return sorted(messages, key=lambda m: (m.timestamp is None, m.timestamp or 0))


def filter_dates(messages, start='', end=''):
    low = date.fromisoformat(start) if start else None
    high = date.fromisoformat(end) if end else None
    if low and high and low > high:
        raise ValueError('Start date must not be after end date.')
    result = []
    for m in messages:
        if m.timestamp is None:
            result.append(m)  # cannot safely exclude an unknown date
        else:
            day = datetime.fromtimestamp(m.timestamp / 1000).date()
            if (low is None or day >= low) and (high is None or day <= high):
                result.append(m)
    return ordered(result)


def format_date(stamp):
    if stamp is None:
        return '[Unreadable date/time]'
    dt = datetime.fromtimestamp(stamp / 1000)
    weekdays = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
    months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
    return f'{weekdays[dt.weekday()]}, {months[dt.month-1]} {dt.day}, {dt.year}, {dt.hour % 12 or 12}:{dt.minute:02d} {"AM" if dt.hour < 12 else "PM"}'


def format_time(stamp):
    """Time of day only — the chat timeline shows the date on separators."""
    if stamp is None:
        return '[Unreadable date/time]'
    dt = datetime.fromtimestamp(stamp / 1000)
    return f'{dt.hour % 12 or 12}:{dt.minute:02d} {"AM" if dt.hour < 12 else "PM"}'


def format_day(stamp):
    """Long date for chat date separators, e.g. 'October 12, 2026'."""
    if stamp is None:
        return '[Unreadable date/time]'
    dt = datetime.fromtimestamp(stamp / 1000)
    months = ('January', 'February', 'March', 'April', 'May', 'June', 'July',
              'August', 'September', 'October', 'November', 'December')
    return f'{months[dt.month - 1]} {dt.day}, {dt.year}'


def message_text(message, name):
    label = {'sent': 'YOU', 'received': name.strip() or 'THEM'}.get(message.direction, '[Unreadable direction]')
    stamp = format_date(message.timestamp)
    return f'{stamp if message.timestamp is None else "[" + stamp + "]"} {label}: {message.body}'


def transcript_header(messages, name, number, printed, private=False):
    dates = [m.timestamp for m in ordered(messages) if m.timestamp is not None]
    covered = f'{format_date(dates[0])} — {format_date(dates[-1])}' if dates else '[Unreadable date range]'
    if any(m.timestamp is None for m in messages):
        covered += ' (also contains unreadable dates)'
    if private:
        # Owner-requested privacy mode: phone number hidden.
        # Message text itself is never altered — a transcript is a record.
        return ['PrintMyTexts', f'Text message conversation with: {name.strip() or "THEM"} (number hidden)',
                'Date range covered: ' + covered, 'Printed ' + printed.strftime('%Y-%m-%d') + " • Times shown are the phone's time"]
    # v1.6 (owner order 2026-11-08): no shop name/address/phone letterhead
    # on documents — the transcript carries the conversation, not the shop.
    return ['PrintMyTexts', f'Text message conversation with: {name.strip() or "THEM"} ({number})',
            'Date range covered: ' + covered, 'Printed ' + printed.strftime('%Y-%m-%d') + " • Times shown are the phone's time"]


def render_html(messages, name, number, printed=None, private=False):
    """Escaped, offline HTML representation, also useful for renderer tests.

    v1.6: the body is bubble-style like the paper layout — the other
    person on the LEFT, the phone owner on the RIGHT — not flat lines."""
    printed = printed or datetime.now()
    header = ''.join('<div>' + html.escape(t) + '</div>' for t in transcript_header(messages, name, number, printed, private))
    display = name.strip() or 'THEM'
    blocks = []
    for m in ordered(messages):
        if m.direction == 'sent':
            side, label = 'sent', 'YOU'
        elif m.direction == 'received':
            side, label = 'received', display
        else:
            side, label = 'unknown', ''
        meta = (label + ' · ' if label else '— ') + format_date(m.timestamp) + ('' if label else ' —')
        blocks.append('<div class="msg ' + side + '"><div class="meta">' + html.escape(meta)
                      + '</div><div class="bubble">' + html.escape(m.body) + '</div></div>')
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<style>@page {size:letter; margin:0.5in; @bottom-center {content:"Page " counter(page) " of " counter(pages)}}'
            '.msg {margin:0 0 10px; break-inside:avoid} .msg.sent {text-align:right} .msg.unknown {text-align:center}'
            '.meta {font-size:12px; color:#555; margin-bottom:2px}'
            '.bubble {display:inline-block; max-width:70%; padding:8px 12px; border-radius:14px;'
            ' white-space:pre-wrap; overflow-wrap:anywhere; text-align:left}'
            '.received .bubble {background:#F0F2F5} .sent .bubble {background:#E9F1F9}'
            ' .unknown .bubble {background:#E2E8EF} footer {position:fixed;bottom:0}</style>'
            '</head><body><header>' + header + '</header>' + ''.join(blocks)
            + '<footer>' + html.escape(PRIVATE_NOTICE if private else NOTICE) + '</footer></body></html>')


def find_adb():
    found = shutil.which('adb')
    if found:
        return found
    home = Path.home()
    candidates = [Path(__file__).resolve().parent / 'platform-tools/adb.exe', Path.cwd() / 'platform-tools/adb.exe',
                  home / 'Downloads/platform-tools-latest-windows/platform-tools/adb.exe',
                  home / 'Downloads/platform-tools/adb.exe', home / 'platform-tools/adb.exe',
                  Path('C:/platform-tools/adb.exe'), home / 'AppData/Local/Android/Sdk/platform-tools/adb.exe']
    return next((str(p) for p in candidates if p.is_file()), None)


class AdbReader:
    def __init__(self, executable=None, cancelled=None, on_stage=None):
        self.cancelled = cancelled or threading.Event()
        # Optional progress callback (v1.6): called with 'reading' once
        # the phone has answered, so the UI can say plainly what it is
        # doing instead of sitting on one vague status.
        self.on_stage = on_stage
        self.executable = executable or find_adb()
        self.serial = None
        if not self.executable:
            raise ValueError('ADB was not found. Install Android platform-tools on PATH or place platform-tools beside PrintMyTexts. You can import from a backup file instead — that works without ADB.')

    def run(self, *args):
        if self.cancelled.is_set():
            raise ValueError('Read cancelled while closing.')
        # Select USB transports only; never use adb connect, tcpip or downloads.
        selection = ['-s', self.serial] if self.serial else ['-d']
        command = [self.executable, *selection, *args]
        result = subprocess.run(command, capture_output=True, encoding='utf-8', errors='replace', timeout=60,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        output = result.stdout
        if result.returncode or re.search(r'SecurityException|Permission Denial|Error while accessing provider|Exception occurred', output + result.stderr, re.I):
            raise ValueError('Android denied or failed the read. Unlock the phone, authorize USB debugging, or import a backup file from the SMS Backup & Restore app.')
        return output

    def query(self, uri, columns):
        return self.run('shell', 'content', 'query', '--uri', uri, '--projection', ':'.join(columns))

    def read(self):
        # '-d' rejects multiple USB phones and does not select a Wi-Fi device.
        self.serial = self.run('get-serialno').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', self.serial) or self.serial in ('unknown', 'error'):
            raise ValueError('Connect exactly one authorized USB Android phone, then retry.')
        if self.on_stage:
            self.on_stage('reading')
        messages, warnings = [], []
        try:
            sms = parse_sms(self.query('content://sms', SMS_COLUMNS))
            messages.extend(sms.messages)
            warnings.extend(sms.warnings)
        except ValueError:
            # Plain words only (fix 7): the warning is shown on screen,
            # so it must not carry the raw tool error with it.
            warnings.append('Text messages were denied by the phone; use a backup file to verify completeness.')
        try:
            output = self.query('content://mms', MMS_COLUMNS)
            rows, row_warnings = parse_content_rows(output, MMS_COLUMNS)
            warnings.extend(row_warnings)
            parts, addresses = {}, {}
            for row in rows:
                ident = row.get('_id', '')
                if not re.fullmatch(r'\d+', ident):
                    warnings.append('An MMS ID is unreadable; its content cannot be queried.')
                    continue
                for target, uri, columns in ((parts, f'content://mms/{ident}/part', PART_COLUMNS),
                                             (addresses, f'content://mms/{ident}/addr', ADDR_COLUMNS)):
                    try:
                        target[ident] = self.query(uri, columns)
                    except ValueError:
                        warnings.append('Some MMS parts/addresses were denied; use a backup file to verify completeness.')
            mms = parse_mms(output, parts, addresses)
            messages.extend(mms.messages)
            warnings.extend(mms.warnings)
        except ValueError:
            warnings.append('MMS provider was denied; MMS completeness requires a backup-file import or phone verification.')
        try:
            contacts, errors = parse_content_rows(self.query('content://com.android.contacts/data/phones', CONTACT_COLUMNS), CONTACT_COLUMNS)
            warnings.extend(errors)
            names = {}
            for row in contacts:
                key, name = number_key(clean(row.get('data1'))), clean(row.get('display_name'))
                if key and name:
                    names.setdefault(key, set()).add(name)
            messages = [replace(m, contact_name=next(iter(names[number_key(m.address)])))
                        if len(names.get(number_key(m.address), ())) == 1 else m for m in messages]
        except ValueError:
            warnings.append('Contact names are unavailable; type the customer-confirmed name if needed.')
        if not messages:
            raise ValueError('No readable SMS/MMS returned. Import a backup file from SMS Backup & Restore instead.')
        return ReadResult(messages, list(dict.fromkeys(warnings)))


def plain_phone_error(text):
    """Translate a phone-read failure into one plain sentence (fix 7).

    AdbReader and the subprocess layer speak in tool names ('ADB',
    'platform-tools', 'PATH', 'USB debugging', timeout dumps). Those
    strings stay in the exceptions for anyone debugging, but the phone
    page and the status bar only ever show the plain versions made
    here. Text that is already plain passes through unchanged.
    """
    raw = str(text)
    lowered = raw.lower()
    if 'timed out' in lowered:
        # A timeout dump quotes the tool's own file path, which would
        # otherwise trip the missing-tools wording below.
        return ('Something went wrong reading the phone. Check the cable '
                'and that the phone is unlocked, then try again.')
    if 'adb was not found' in lowered or 'platform-tools' in lowered:
        return ('The phone tools are missing on this computer. You can import '
                'from a backup file instead — that works without them.')
    if 'denied or failed the read' in lowered or 'usb debugging' in lowered:
        return ('The phone would not let the computer read it. Unlock the '
                'phone, and tap Allow on the phone if it asks, then try again.')
    if 'exactly one' in lowered:
        return ('The phone did not answer. Connect just one phone with a '
                'cable, unlock it, and tap Allow on the phone if it asks, '
                'then try again.')
    if 'no readable' in lowered:
        return ('No messages could be read from the phone. Import a backup '
                'file from the SMS Backup & Restore app instead.')
    jargon = ('adb', 'platform-tools', 'path', 'usb debugging', 'winerror',
              'errno', '.exe', 'timed out', 'traceback', 'subprocess')
    if not raw.strip() or any(token in lowered for token in jargon):
        return ('Something went wrong reading the phone. Check the cable '
                'and that the phone is unlocked, then try again.')
    return raw


@dataclass(frozen=True)
class DrawLine:
    x: int
    y: int
    text: str
    size: int = BODY_FONT_SIZE


@dataclass(frozen=True)
class DrawRect:
    """A filled rectangle behind text — the paper chat bubbles (v1.6)."""
    x: int
    y: int
    width: int
    height: int
    color: str = '#F0F2F5'


BUBBLE_MAX_W = 500   # widest paper bubble, padding included
BUBBLE_PAD_X = 12    # text inset inside a paper bubble


def safe_display(text):
    # GDI is not a markup renderer. Replace controls it cannot display visibly.
    return ''.join(c if c in '\n\t' or unicodedata.category(c) != 'Cc' else '\uFFFD' for c in text)


def wrap_text(text, measure, width):
    """Pixel-based wrapping, preserves explicit blank lines and long words."""
    lines = []
    for paragraph in safe_display(text).expandtabs(4).split('\n'):
        if not paragraph:
            lines.append('')
            continue
        while paragraph:
            low, high = 1, len(paragraph)
            while low < high:
                mid = (low + high + 1) // 2
                if measure(paragraph[:mid]) <= width:
                    low = mid
                else:
                    high = mid - 1
            count = low
            if count < len(paragraph):
                space = paragraph.rfind(' ', 0, count + 1)
                if space > 0:
                    count = space + 1
            lines.append(paragraph[:count])
            paragraph = paragraph[count:]
    return lines


def layout_pages(messages, name, number, measure, printed=None, private=False):
    """One shared layout for bitmap preview, Windows printing and PDF.

    v1.6 (owner order 2026-11-08): the body is laid out like the
    on-screen chat — the other person on the LEFT, the phone owner on
    the RIGHT — each message a tinted bubble (DrawRect + its text
    lines) with a small name-and-date line above it, instead of flat
    full-width lines."""
    header = transcript_header(messages, name, number, printed or datetime.now(), private)
    header_lines = []
    for index, text in enumerate(header):
        header_lines.extend((line, 22 if index == 0 else 14) for line in wrap_text(text, measure, PAGE_W - 2 * MARGIN))
    body_top = max(BODY_TOP, MARGIN + len(header_lines) * LINE_HEIGHT + 15)
    if body_top > BODY_BOTTOM - LINE_HEIGHT * 3:
        raise ValueError('The contact name/number is too long to fit the page header. Shorten the display name.')
    capacity = (BODY_BOTTOM - body_top) // LINE_HEIGHT
    display = name.strip() or 'THEM'
    pages, current, y = [], [], body_top

    def new_page():
        nonlocal current, y
        pages.append(current)
        current, y = [], body_top

    for message in ordered(messages):
        if message.direction == 'sent':
            label, tint = 'YOU', COLORS['pdf_owner']
        elif message.direction == 'received':
            label, tint = display, COLORS['pdf_customer']
        else:
            label, tint = '', BUBBLE_UNKNOWN
        meta = (label + ' · ' if label else '— ') + format_date(message.timestamp) + ('' if label else ' —')
        body_lines = wrap_text(message.body, measure, BUBBLE_MAX_W - 2 * BUBBLE_PAD_X)
        widest = max([measure(line) for line in body_lines] + [1])
        bubble_w = min(BUBBLE_MAX_W, widest + 2 * BUBBLE_PAD_X)
        if message.direction == 'sent':
            bubble_x = PAGE_W - MARGIN - bubble_w
            meta_x = PAGE_W - MARGIN - measure(meta)
        elif message.direction == 'received':
            bubble_x, meta_x = MARGIN, MARGIN
        else:
            bubble_x = (PAGE_W - bubble_w) // 2
            meta_x = (PAGE_W - measure(meta)) // 2
        # meta line + body lines + one trailing gap line (bubble padding
        # is absorbed by the gap).
        block_lines = 1 + len(body_lines) + 1
        if block_lines <= capacity and block_lines > (BODY_BOTTOM - y) // LINE_HEIGHT and current:
            new_page()
        current.append(DrawLine(meta_x, y, meta, 14))
        y += LINE_HEIGHT
        pending = list(body_lines)
        seg_first_y = y
        seg = []

        def emit_segment():
            if not seg:
                return
            top = seg_first_y - 6
            current.append(DrawRect(bubble_x, top, bubble_w,
                                    seg[-1][0] + LINE_HEIGHT + 4 - top, tint))
            for line_y, line_text in seg:
                current.append(DrawLine(bubble_x + BUBBLE_PAD_X, line_y, line_text))

        while pending:
            if y + LINE_HEIGHT > BODY_BOTTOM:
                emit_segment()
                seg = []
                new_page()
                current.append(DrawLine(MARGIN, y, '[Message continued]', 14))
                y += LINE_HEIGHT
                seg_first_y = y
            seg.append((y, pending.pop(0)))
            y += LINE_HEIGHT
        emit_segment()
        y += LINE_HEIGHT
    pages.append(current)
    result = []
    for index, body in enumerate(pages, 1):
        top = [DrawLine(MARGIN, MARGIN + i * LINE_HEIGHT, text, size) for i, (text, size) in enumerate(header_lines)]
        footer = [DrawLine(MARGIN, 1028, f'PrintMyTexts — Page {index} of {len(pages)}', 14), DrawLine(MARGIN, 1048, PRIVATE_NOTICE if private else NOTICE, 14), DrawLine(MARGIN, 1066, COPYRIGHT_PRIVATE if private else COPYRIGHT_LINE, 12)]
        result.append(top + body + footer)
    return result


class WindowsPages:
    """Offline GDI rasterization. The identical RGB page is previewed/exported/printed.

    No browser, HTML handler, network library, or external PDF process is used.
    """
    def __init__(self):
        if os.name != 'nt':
            raise ValueError('Printing and PDF export require Windows. Backup-file parsing tests run on any OS.')
        self.gdi = ctypes.WinDLL('gdi32', use_last_error=True)
        # Explicit pointer-sized handles are essential on 64-bit Windows.
        self.gdi.GdiFlush.argtypes, self.gdi.GdiFlush.restype = [], wintypes.BOOL
        signatures = {
            'CreateCompatibleDC': (wintypes.HDC, [wintypes.HDC]),
            'CreateDIBSection': (wintypes.HBITMAP, [wintypes.HDC, ctypes.c_void_p, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD]),
            'SelectObject': (wintypes.HANDLE, [wintypes.HDC, wintypes.HANDLE]),
            'CreateFontW': (wintypes.HANDLE, [ctypes.c_int] * 5 + [wintypes.DWORD] * 8 + [wintypes.LPCWSTR]),
            'DeleteObject': (wintypes.BOOL, [wintypes.HANDLE]), 'DeleteDC': (wintypes.BOOL, [wintypes.HDC]),
            'TextOutW': (wintypes.BOOL, [wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int]),
            'GetTextExtentPoint32W': (wintypes.BOOL, [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p]),
            'SetBkMode': (ctypes.c_int, [wintypes.HDC, ctypes.c_int]),
            'SetTextColor': (wintypes.DWORD, [wintypes.HDC, wintypes.DWORD]),
            'GetDeviceCaps': (ctypes.c_int, [wintypes.HDC, ctypes.c_int]),
            'StretchDIBits': (ctypes.c_int, [wintypes.HDC] + [ctypes.c_int] * 8 + [ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT, wintypes.DWORD]),
            'StartDocW': (ctypes.c_int, [wintypes.HDC, ctypes.c_void_p]),
            'StartPage': (ctypes.c_int, [wintypes.HDC]), 'EndPage': (ctypes.c_int, [wintypes.HDC]),
            'EndDoc': (ctypes.c_int, [wintypes.HDC]), 'AbortDoc': (ctypes.c_int, [wintypes.HDC])}
        for name, (restype, argtypes) in signatures.items():
            fn = getattr(self.gdi, name)
            fn.restype, fn.argtypes = restype, argtypes
        self.dc = self.gdi.CreateCompatibleDC(None)
        if not self.dc:
            raise OSError('Cannot create Windows drawing context.')
        self.fonts = {}
        self.old_font = self.gdi.SelectObject(self.dc, self.font(BODY_FONT_SIZE))
        self.gdi.SetBkMode(self.dc, 1)
        self.gdi.SetTextColor(self.dc, 0)

    def font(self, size):
        if size not in self.fonts:
            handle = self.gdi.CreateFontW(-size, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, FONT_FACE)
            if not handle:
                raise OSError('Cannot create Windows transcript font.')
            self.fonts[size] = handle
        return self.fonts[size]

    def measure(self, text):
        self.gdi.SelectObject(self.dc, self.font(BODY_FONT_SIZE))
        size = (ctypes.c_long * 2)()
        if not self.gdi.GetTextExtentPoint32W(self.dc, text, len(text.encode('utf-16-le')) // 2, size):
            raise OSError('Cannot measure transcript text.')
        return size[0]

    @staticmethod
    def bitmap_info():
        return struct.pack('<IiiHHIIiiII', 40, PAGE_W, -PAGE_H, 1, 32, 0, PAGE_W * PAGE_H * 4, 0, 0, 0, 0)

    def raster(self, page):  # page bitmap stays black-on-white: it is a paper page

        info = ctypes.create_string_buffer(self.bitmap_info())
        bits = ctypes.c_void_p()
        bitmap = self.gdi.CreateDIBSection(self.dc, info, 0, ctypes.byref(bits), None, 0)
        if not bitmap:
            raise OSError('Cannot allocate transcript page.')
        old = self.gdi.SelectObject(self.dc, bitmap)
        try:
            ctypes.memset(bits, 255, PAGE_W * PAGE_H * 4)
            rects = [item for item in page if isinstance(item, DrawRect)]
            if rects:
                # Paper chat bubbles (v1.6): fill the tint rectangles in
                # the BGRA buffer before any text is drawn over them.
                raw = bytearray(ctypes.string_at(bits, PAGE_W * PAGE_H * 4))
                for rect in rects:
                    red, green, blue = (int(rect.color[i:i + 2], 16) for i in (1, 3, 5))
                    x0, x1 = max(0, rect.x), min(PAGE_W, rect.x + rect.width)
                    if x1 <= x0:
                        continue
                    fill = bytes((blue, green, red, 255)) * (x1 - x0)
                    for row_y in range(max(0, rect.y), min(PAGE_H, rect.y + rect.height)):
                        start = (row_y * PAGE_W + x0) * 4
                        raw[start:start + len(fill)] = fill
                ctypes.memmove(bits, bytes(raw), len(raw))
            for line in page:
                if isinstance(line, DrawRect):
                    continue
                self.gdi.SelectObject(self.dc, self.font(line.size))
                if not self.gdi.TextOutW(self.dc, line.x, line.y, line.text, len(line.text.encode('utf-16-le')) // 2):
                    raise OSError('Cannot draw transcript text.')
            self.gdi.GdiFlush()
            raw = ctypes.string_at(bits, PAGE_W * PAGE_H * 4)
            rgb = bytearray(PAGE_W * PAGE_H * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = raw[2::4], raw[1::4], raw[0::4]
            return bytes(rgb)
        finally:
            self.gdi.SelectObject(self.dc, old)
            self.gdi.DeleteObject(bitmap)

    def close(self):
        if self.dc:
            self.gdi.SelectObject(self.dc, self.old_font)
            for font in self.fonts.values():
                self.gdi.DeleteObject(font)
            self.gdi.DeleteDC(self.dc)
            self.dc = None

    def print_pages(self, pages):
        class PRINTDLG(ctypes.Structure):
            if ctypes.sizeof(ctypes.c_void_p) == 4:
                _pack_ = 1  # commdlg.h packs PRINTDLG on 32-bit Windows
            _fields_ = [('lStructSize', wintypes.DWORD), ('hwndOwner', wintypes.HWND),
                        ('hDevMode', wintypes.HGLOBAL), ('hDevNames', wintypes.HGLOBAL), ('hDC', wintypes.HDC),
                        ('Flags', wintypes.DWORD), ('nFromPage', wintypes.WORD), ('nToPage', wintypes.WORD),
                        ('nMinPage', wintypes.WORD), ('nMaxPage', wintypes.WORD), ('nCopies', wintypes.WORD),
                        ('hInstance', wintypes.HINSTANCE), ('lCustData', ctypes.c_ssize_t),
                        ('lpfnPrintHook', ctypes.c_void_p), ('lpfnSetupHook', ctypes.c_void_p),
                        ('lpPrintTemplateName', wintypes.LPCWSTR), ('lpSetupTemplateName', wintypes.LPCWSTR),
                        ('hPrintTemplate', wintypes.HGLOBAL), ('hSetupTemplate', wintypes.HGLOBAL)]
        class DOCINFO(ctypes.Structure):
            _fields_ = [('cbSize', ctypes.c_int), ('lpszDocName', wintypes.LPCWSTR),
                        ('lpszOutput', wintypes.LPCWSTR), ('lpszDatatype', wintypes.LPCWSTR), ('fwType', wintypes.DWORD)]
        dialog = PRINTDLG()
        dialog.lStructSize, dialog.Flags, dialog.nCopies = ctypes.sizeof(dialog), 0x100 | 0x4 | 0x8, 1  # RETURNDC, no selection/page subset
        dialog.nMinPage, dialog.nMaxPage = 1, len(pages)
        comdlg = ctypes.WinDLL('comdlg32', use_last_error=True)
        comdlg.PrintDlgW.argtypes, comdlg.PrintDlgW.restype = [ctypes.POINTER(PRINTDLG)], wintypes.BOOL
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GlobalFree.argtypes, kernel.GlobalFree.restype = [wintypes.HGLOBAL], wintypes.HGLOBAL
        started = False
        try:
            if not comdlg.PrintDlgW(ctypes.byref(dialog)):
                if comdlg.CommDlgExtendedError():
                    raise OSError('Windows could not open the print dialog.')
                return False
            dc = dialog.hDC
            doc = DOCINFO(ctypes.sizeof(DOCINFO), 'iFixx Repairs PrintMyTexts', None, None, 0)
            if self.gdi.StartDocW(dc, ctypes.byref(doc)) <= 0:
                raise OSError('Printer did not start the job.')
            started = True
            width, height = self.gdi.GetDeviceCaps(dc, 8), self.gdi.GetDeviceCaps(dc, 10)
            scale = min(width / PAGE_W, height / PAGE_H)
            dest_w, dest_h = int(PAGE_W * scale), int(PAGE_H * scale)
            info = ctypes.create_string_buffer(self.bitmap_info())
            for _ in range(max(1, dialog.nCopies)):
                for page in pages:
                    if self.gdi.StartPage(dc) <= 0:
                        raise OSError('Printer could not start a page.')
                    rgb = self.raster(page)
                    bgra = bytearray(PAGE_W * PAGE_H * 4)
                    bgra[0::4], bgra[1::4], bgra[2::4] = rgb[2::3], rgb[1::3], rgb[0::3]
                    pixels = ctypes.create_string_buffer(bytes(bgra))
                    if self.gdi.StretchDIBits(dc, (width-dest_w)//2, (height-dest_h)//2, dest_w, dest_h,
                                             0, 0, PAGE_W, PAGE_H, pixels, info, 0, 0x00CC0020) <= 0:
                        raise OSError('Printer rejected a page image.')
                    if self.gdi.EndPage(dc) <= 0:
                        raise OSError('Printer did not finish a page.')
            if self.gdi.EndDoc(dc) <= 0:
                raise OSError('Printer did not finish the job.')
            started = False
            return True
        finally:
            if started:
                self.gdi.AbortDoc(dialog.hDC)
            if dialog.hDC:
                self.gdi.DeleteDC(dialog.hDC)
            for handle in (dialog.hDevMode, dialog.hDevNames):
                if handle:
                    kernel.GlobalFree(handle)


def png_bytes(rgb):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    stride = PAGE_W * 3
    raw = b''.join(b'\0' + rgb[y*stride:(y+1)*stride] for y in range(PAGE_H))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', PAGE_W, PAGE_H, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


def write_pdf(path, pages, raster):
    """Self-contained image PDF preserves the exact preview, including Unicode.

    Explicit user-saved output is retained; no customer data enters metadata.
    Stream pages to disk so long threads do not require all bitmaps in memory.
    """
    count = len(pages)
    offsets = [0] * (3 + 3 * count)
    with open(path, 'wb') as stream:
        stream.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        def obj(number, data):
            offsets[number] = stream.tell()
            stream.write(f'{number} 0 obj\n'.encode() + data + b'\nendobj\n')
        obj(1, b'<< /Type /Catalog /Pages 2 0 R >>')
        kids = ' '.join(f'{3+3*i} 0 R' for i in range(count))
        obj(2, f'<< /Type /Pages /Count {count} /Kids [{kids}] >>'.encode())
        for i, page in enumerate(pages):
            p, image_id, content_id = 3 + 3 * i, 4 + 3 * i, 5 + 3 * i
            obj(p, f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 {image_id} 0 R >> >> /Contents {content_id} 0 R >>'.encode())
            data = zlib.compress(raster(page))
            obj(image_id, f'<< /Type /XObject /Subtype /Image /Width {PAGE_W} /Height {PAGE_H} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {len(data)} >>\nstream\n'.encode() + data + b'\nendstream')
            commands = b'q 612 0 0 792 0 0 cm /Im0 Do Q\n'
            obj(content_id, f'<< /Length {len(commands)} >>\nstream\n'.encode() + commands + b'endstream')
        position = stream.tell()
        stream.write(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
        for offset in offsets[1:]:
            stream.write(f'{offset:010d} 00000 n \n'.encode())
        stream.write(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{position}\n%%EOF\n'.encode())


class WorkingData:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ifixx-printmytexts-')
        self.path = Path(self.temp.name)
        atexit.register(self.close)

    def close(self):
        # Logical deletion, not a claim of secure erasure on SSDs/OS spoolers.
        self.temp.cleanup()


UPDATE_HELPER_SRC = """import json, os, shutil, subprocess, sys, time

def pid_alive(pid):
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def main():
    (wait_pid, current, downloaded, backup, result_path,
     python_exe, alive_secs, from_v, to_v) = sys.argv[1:10]
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
        os.replace(downloaded, current)
        proc = subprocess.Popen([python_exe, current])
        time.sleep(alive_secs)
        if proc.poll() is not None:
            outcome = "rolled_back"
            try:
                os.remove(current)
            except OSError:
                pass
            shutil.copy2(backup, current)
            subprocess.Popen([python_exe, current])
    except Exception:
        outcome = "rolled_back"
        try:
            if not os.path.exists(current) and os.path.exists(backup):
                shutil.copy2(backup, current)
                subprocess.Popen([python_exe, current])
        except Exception:
            pass
    try:
        temp_result = result_path + ".tmp"
        with open(temp_result, "w") as result:
            json.dump({"outcome": outcome, "from_version": from_v,
                       "to_version": to_v}, result)
        os.replace(temp_result, result_path)
    except Exception:
        pass

main()
"""


def _version_tuple(value):
    return tuple(int(part) for part in str(value).split('.'))


def _version_newer(remote, local):
    remote_parts, local_parts = _version_tuple(remote), _version_tuple(local)
    width = max(len(remote_parts), len(local_parts))
    return (remote_parts + (0,) * (width - len(remote_parts))
            > local_parts + (0,) * (width - len(local_parts)))


def _default_fetch_bytes(url, timeout=20):
    request = urllib.request.Request(
        url, headers={'User-Agent': 'PrintMyTexts-PC-Updater'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def parse_update_manifest(raw):
    try:
        data = json.loads(raw.decode('utf-8'))
        version = str(data['version']).strip()
        url = str(data['url']).strip()
        sha256 = str(data['sha256']).strip().lower()
        size = int(data['size'])
        notes = str(data.get('notes', ''))
    except Exception:
        return None
    if (not re.fullmatch(r'\d+(?:\.\d+)*', version)
            or len(sha256) != 64
            or not re.fullmatch(r'[0-9a-f]{64}', sha256)
            or size <= 0):
        return None
    parsed_url = urlparse(url)
    if (parsed_url.scheme != 'https'
            or not (parsed_url.hostname == 'github.com'
                    or (parsed_url.hostname or '').endswith('.githubusercontent.com'))):
        return None
    return {'version': version, 'url': url, 'sha256': sha256,
            'size': size, 'notes': notes}


def check_for_update(fetch_bytes=None):
    fetch = fetch_bytes or _default_fetch_bytes
    try:
        info = parse_update_manifest(fetch(UPDATE_MANIFEST_URL))
    except Exception:
        return None
    return info if info and _version_newer(info['version'], VERSION) else None


def verify_update_file(path, expected_size, expected_sha256):
    try:
        file_path = Path(path)
        if file_path.stat().st_size != int(expected_size):
            return False
        digest = hashlib.sha256()
        with file_path.open('rb') as update_file:
            for chunk in iter(lambda: update_file.read(65536), b''):
                digest.update(chunk)
        return digest.hexdigest() == str(expected_sha256).lower()
    except Exception:
        return False


def download_update(manifest, dest_dir, fetch_bytes=None):
    fetch = fetch_bytes or _default_fetch_bytes
    dest = Path(dest_dir) / ('PrintMyTexts-PC-v%s.download'
                             % manifest['version'])
    try:
        dest.write_bytes(fetch(manifest['url'], timeout=120))
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return None, 'download failed (%s)' % exc
    if not verify_update_file(dest, manifest['size'], manifest['sha256']):
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return None, 'the downloaded file failed its safety check ' \
                     '(size/hash mismatch) and was discarded'
    return dest, None


def updater_guard_reason(busy, messages_loaded=False):
    if messages_loaded:
        return ('Messages are loaded — print/save them, then close and reopen '
                'before updating.')
    if busy:
        return 'a phone read or import is in progress — finish it before updating'
    return None


def ensure_stable_alias(script_path=None):
    script = Path(script_path or sys.argv[0]).resolve()
    alias = script.parent / UPDATE_STABLE_ALIAS
    if script != alias and not alias.exists():
        try:
            shutil.copy2(script, alias)
        except OSError:
            try:
                alias.unlink(missing_ok=True)
            except OSError:
                pass
            return script
    return alias


WINDOW_DEFAULT_W, WINDOW_DEFAULT_H = 1200, 700
WINDOW_MIN_W, WINDOW_MIN_H = 1000, 620
WINDOW_SMALL_DEFAULT_W, WINDOW_SMALL_DEFAULT_H = 880, 600
WINDOW_SMALL_MIN_W, WINDOW_SMALL_MIN_H = 860, 560
SETTINGS_FILENAME = 'printmytexts-settings.json'
_GEOMETRY_RE = re.compile(r'^(\d+)x(\d+)\+(-?\d+)\+(-?\d+)$')


def _settings_path():
    return Path(__file__).resolve().parent / SETTINGS_FILENAME


def load_window_geometry():
    """The remembered window geometry string, or None on first run."""
    try:
        data = json.loads(_settings_path().read_text(encoding='utf-8'))
        value = data.get('window_geometry')
        return value if isinstance(value, str) else None
    except Exception:
        return None


def save_window_geometry(value):
    """Persist the window geometry beside the app (best effort)."""
    try:
        path = _settings_path()
        data = {}
        try:
            existing = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(existing, dict):
                data = existing
        except Exception:
            pass
        data['window_geometry'] = value
        path.write_text(json.dumps(data, indent=1), encoding='utf-8')
    except OSError:
        pass


def _small_screen(screen_w, screen_h):
    """A small screen: the window gets the compact size class — an
    880x600 default and an 860x560 minimum — instead of the full-size
    default that spans a laptop display edge to edge (owner finding
    on the 1152x720 MacBook Pro, 2026-10-26: the screen-fit clamp
    still read as "too big", wall to wall)."""
    return screen_w < 1400 or screen_h < 900


def _window_default(screen_w, screen_h):
    """The first-run window size for this screen's size class."""
    if _small_screen(screen_w, screen_h):
        return WINDOW_SMALL_DEFAULT_W, WINDOW_SMALL_DEFAULT_H
    return WINDOW_DEFAULT_W, WINDOW_DEFAULT_H


def _window_plan(screen_w, screen_h):
    """The (min_w, min_h, max_w, max_h) a window may take on this screen.

    Normally the window keeps its class minimum (1000x620, or
    860x560 on a small screen) and stays inside the screen with a
    40px width / 80px height margin. A screen smaller than the
    minimum plus margin cannot honor either, so the window — and
    the minimum, which must never exceed the window — fit the
    screen itself (-20/-60) instead of spanning it edge to edge."""
    if _small_screen(screen_w, screen_h):
        min_w, min_h = WINDOW_SMALL_MIN_W, WINDOW_SMALL_MIN_H
    else:
        min_w, min_h = WINDOW_MIN_W, WINDOW_MIN_H
    if screen_w < min_w + 40 or screen_h < min_h + 80:
        fit_w, fit_h = max(1, screen_w - 20), max(1, screen_h - 60)
        return fit_w, fit_h, fit_w, fit_h
    return min_w, min_h, screen_w - 40, screen_h - 80


def clamp_window_geometry(value, screen_w, screen_h):
    """A valid on-screen geometry: the remembered one shrunk to fit
    this screen and re-centered when it no longer fits, or the
    class default — 1200x700, 880x600 on a small screen — clamped
    the same way, centered when there is none. A remembered size
    beyond 85% of the screen width or 88% of its height is a
    legacy full-bleed save, not a real choice, so it is replaced
    by the class default, centered."""
    min_w, min_h, max_w, max_h = _window_plan(screen_w, screen_h)
    def_w, def_h = _window_default(screen_w, screen_h)
    match = _GEOMETRY_RE.match(value or '')
    if match:
        w, h, x, y = (int(part) for part in match.groups())
        if w > 0.85 * screen_w or h > 0.88 * screen_h:
            w = max(min_w, min(def_w, max_w))
            h = max(min_h, min(def_h, max_h))
            return '%dx%d+%d+%d' % (w, h, max(0, (screen_w - w) // 2),
                                    max(0, (screen_h - h) // 3))
        oversize = w > max_w or h > max_h
        w = max(min_w, min(w, max_w))
        h = max(min_h, min(h, max_h))
        if oversize:
            x = max(0, (screen_w - w) // 2)
            y = max(0, (screen_h - h) // 3)
        else:
            x = min(max(x, -w + 160), max(0, screen_w - 80))
            y = min(max(y, 0), max(0, screen_h - 48))
        return '%dx%d+%d+%d' % (w, h, x, y)
    w = max(min_w, min(def_w, max_w))
    h = max(min_h, min(def_h, max_h))
    return '%dx%d+%d+%d' % (w, h, max(0, (screen_w - w) // 2),
                            max(0, (screen_h - h) // 3))


def begin_update(current_path, downloaded_path, new_version, from_version,
                 wait_pid=None, alive_seconds=UPDATE_ALIVE_SECONDS):
    current = Path(current_path).resolve()
    folder = current.parent
    backup = folder / ('PrintMyTexts-PC-v%s-backup.pyw' % from_version)
    result_path = folder / 'update_result.json'
    helper = folder / 'printmytexts_update_helper.py'
    helper.write_text(UPDATE_HELPER_SRC, encoding='utf-8')
    if wait_pid is None:
        wait_pid = os.getpid()
    args = [sys.executable, str(helper), str(wait_pid), str(current),
            str(Path(downloaded_path).resolve()), str(backup),
            str(result_path), sys.executable, str(alive_seconds),
            str(from_version), str(new_version)]
    kwargs = {'creationflags': 0x00000008 | 0x00000200} if os.name == 'nt' \
        else {'start_new_session': True}
    return subprocess.Popen(args, **kwargs)


# ---------- v1.7 sidebar: big rounded colored nav buttons ----------
# Most symbols are drawn with Tk canvas primitives — vector shapes
# in the app's own code. The 'robot' and 'apple' symbols are the
# exception (v1.7.1, owner order above): ChatGPT-drawn PNG artwork
# embedded in this file as base64, decoded at runtime.

def _mix_hex(hex_a, hex_b, frac):
    """Blend two '#RRGGBB' colors; frac 0 = a, 1 = b."""
    a = [int(hex_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(hex_b[i:i + 2], 16) for i in (1, 3, 5)]
    return '#%02X%02X%02X' % tuple(round(x + (y - x) * frac) for x, y in zip(a, b))


def _shade_hex(hex_color, factor):
    parts = [max(0, min(255, round(int(hex_color[i:i + 2], 16) * factor)))
             for i in (1, 3, 5)]
    return '#%02X%02X%02X' % tuple(parts)


def _rrect(canvas, x1, y1, x2, y2, radius, fill):
    """A filled rounded rectangle built from arc points."""
    import math
    points = []
    for cx, cy, start in ((x2 - radius, y1 + radius, -90), (x2 - radius, y2 - radius, 0),
                          (x1 + radius, y2 - radius, 90), (x1 + radius, y1 + radius, 180)):
        for step in range(0, 91, 15):
            ang = math.radians(start + step)
            points += [cx + radius * math.cos(ang), cy + radius * math.sin(ang)]
    canvas.create_polygon(points, fill=fill, outline=fill)


# ---------- v1.7.1 sidebar symbol images (ChatGPT-drawn) ----------
# Provenance (owner order, 2026-11-08 — he rejected the code-drawn
# robot/apple as ugly and ordered ChatGPT's symbols pasted in):
# drawn by ChatGPT in the conversation 'Improve App Design' as
# white-on-transparent 1024x1024 PNGs, zoom-verified by Lucy on
# button-color composites, and kept for provenance under assets/
# in the build tree:
#   robot: Android_Robot_White_Transparent_With_Eyes.png
#          25,952 bytes, sha256 d647af735846daeb09676a83d9c2b8b09c29be
#          34a01d2e8f60e15280bac87b3b
#   apple: Apple_Silhouette_White_Transparent.png
#          27,995 bytes, sha256 79e99f5304dd775c60f177de398113b579c
#          390193b5f8ba10c492210a94946fd
# For embedding, each was cropped to its alpha bounding box and
# downscaled losslessly (flat silhouettes; shapes/edges unchanged)
# to fit 252 px on the long side — robot 235x252, 7,196 bytes;
# apple 225x252, 7,614 bytes — then base64-encoded below. At
# runtime the PNG is decoded with tk.PhotoImage (Tk 8.6 reads PNG
# natively) and subsampled by NAV_SYMBOL_IMAGE_SUBSAMPLE, so it
# displays 34x36 (robot) / 33x36 (apple) px — the same symbol box
# the code-drawn symbols occupied (centered at (36, HEIGHT//2),
# ~36 px tall). The single-file shape of the app is unchanged:
# no asset files ship beside the .pyw.
NAV_SYMBOL_IMAGE_SUBSAMPLE = 7
NAV_SYMBOL_PNG_B64 = {
    'robot': (
        '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'
        'x/EAAAAASUVORK5CYII='
    ),
    'apple': (
        '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'
    ),
}
NAV_SYMBOL_DISPLAY_SIZE = {
    'robot': (34, 36),
    'apple': (33, 36),
}
_NAV_SYMBOL_PHOTO_CACHE = {}


def _nav_symbol_photo(canvas, kind):
    """The subsampled tk.PhotoImage for an embedded symbol, cached
    per Tk interpreter. Raises on any failure — the caller falls
    back to the code-drawn symbol."""
    import tkinter as tk
    key = (kind, id(getattr(canvas, 'tk', None)))
    cached = _NAV_SYMBOL_PHOTO_CACHE.get(key)
    if cached is not None:
        return cached[1]
    raw = tk.PhotoImage(master=canvas, data=NAV_SYMBOL_PNG_B64[kind])
    photo = raw.subsample(NAV_SYMBOL_IMAGE_SUBSAMPLE,
                          NAV_SYMBOL_IMAGE_SUBSAMPLE)
    # Keep BOTH alive: a PhotoImage that loses its last Python
    # reference is deleted from the interpreter.
    _NAV_SYMBOL_PHOTO_CACHE[key] = (raw, photo)
    return photo


def _try_draw_nav_symbol_image(canvas, kind, cx, cy):
    """Draw the embedded ChatGPT symbol centered at (cx, cy).
    Returns True on success; False (never raises) when the image
    cannot be used — no create_image on the canvas, a decode
    failure, anything — so the caller falls back to drawing."""
    if not hasattr(canvas, 'create_image'):
        return False
    try:
        photo = _nav_symbol_photo(canvas, kind)
        if photo is None:
            return False
        canvas.create_image(cx, cy, image=photo)
    except Exception:
        return False
    try:
        keep = getattr(canvas, '_nav_symbol_photos', None)
        if keep is None:
            canvas._nav_symbol_photos = keep = []
        keep.append(photo)
    except Exception:
        pass
    return True


def _draw_nav_symbol(canvas, kind, cx, cy, fill, hole_at):
    """One white symbol, centered at (cx, cy). `hole_at(y)` returns
    the button's gradient color at that row, for punched details.

    'robot' and 'apple' are the embedded ChatGPT-drawn images
    (above) whenever they decode; the canvas-drawn shapes below
    are their fallback, and the only path for every other kind."""
    import math
    if kind in NAV_SYMBOL_PNG_B64 and \
            _try_draw_nav_symbol_image(canvas, kind, cx, cy):
        return
    if kind == 'robot':
        # v1.7.1 (owner order, 2026-11-08): a RECOGNIZABLE Android
        # robot — the classic mascot silhouette, not just a head:
        # rounded dome head with a flat bottom, two antennae angled
        # outward with ball tips, two punched eyes, then a BODY
        # below the head with two arms and two legs.
        head_cy = cy - 5
        for sx in (-1, 1):
            canvas.create_line(cx + sx * 5, head_cy - 7, cx + sx * 9,
                               head_cy - 12, fill=fill, width=3)
            canvas.create_oval(cx + sx * 9 - 2.2, head_cy - 14.2,
                               cx + sx * 9 + 2.2, head_cy - 9.8,
                               fill=fill, outline=fill)
        pts = []
        for step in range(0, 181, 12):
            ang = math.radians(180 - step)
            pts += [cx + 10.5 * math.cos(ang),
                    head_cy - 9 * math.sin(ang)]
        pts += [cx + 10.5, head_cy, cx - 10.5, head_cy]
        canvas.create_polygon(pts, fill=fill, outline=fill)
        for sx in (-1, 1):
            canvas.create_oval(cx + sx * 4.5 - 1.7, head_cy - 4.7,
                               cx + sx * 4.5 + 1.7, head_cy - 1.3,
                               fill=hole_at(head_cy - 3),
                               outline=hole_at(head_cy - 3))
        # Body, arms, legs — the mascot below the head. The arms
        # hug the body (1 px gap, like the real mascot): canvas
        # item coordinates land on whole pixels, so a wider gap
        # would read as detached pieces at this size.
        _rrect(canvas, cx - 9, cy - 2, cx + 9, cy + 10, 3, fill)
        _rrect(canvas, cx - 13, cy - 1, cx - 10, cy + 8, 1.5, fill)
        _rrect(canvas, cx + 10, cy - 1, cx + 13, cy + 8, 1.5, fill)
        _rrect(canvas, cx - 7, cy + 10, cx - 2, cy + 17, 2, fill)
        _rrect(canvas, cx + 2, cy + 10, cx + 7, cy + 17, 2, fill)
    elif kind == 'doc':
        canvas.create_polygon(cx - 9, cy - 13, cx + 3, cy - 13, cx + 9, cy - 7,
                              cx + 9, cy + 13, cx - 9, cy + 13,
                              fill='', outline=fill, width=3)
        canvas.create_line(cx + 3, cy - 13, cx + 3, cy - 7, cx + 9, cy - 7,
                           fill=fill, width=2)
        canvas.create_text(cx, cy + 3, text='</>', fill=fill,
                           font=('Consolas', 10, 'bold'))
    elif kind == 'apple':
        # v1.7.1 (owner order, 2026-11-08): a RECOGNIZABLE apple.
        # The v1.7 outline was one polygon with smooth=1, which
        # melted it into a plain blob — no bite, no leaf. This one
        # is built from overlapping ovals (smooth by construction,
        # no smooth=1 anywhere), with the top dip and the BITE
        # punched out in the background color (the hole_at
        # technique), then the stem and leaf drawn on top — the
        # bite is a real cut-out, so it survives every renderer.
        canvas.create_oval(cx - 12, cy - 9, cx + 2, cy + 13,
                           fill=fill, outline=fill)
        canvas.create_oval(cx - 2, cy - 9, cx + 12, cy + 13,
                           fill=fill, outline=fill)
        # A soft bottom cleft, punched like the classic silhouette.
        canvas.create_oval(cx - 3, cy + 10, cx + 3, cy + 17,
                           fill=hole_at(cy + 13), outline=hole_at(cy + 13))
        # The dip at the top, punched.
        canvas.create_oval(cx - 6, cy - 15, cx + 6, cy - 6,
                           fill=hole_at(cy - 10), outline=hole_at(cy - 10))
        # THE BITE, punched out of the right side.
        canvas.create_oval(cx + 6, cy - 2, cx + 16, cy + 7,
                           fill=hole_at(cy + 2), outline=hole_at(cy + 2))
        # Stem and leaf, drawn after the punches.
        canvas.create_line(cx, cy - 10, cx + 2, cy - 16, fill=fill, width=3)
        canvas.create_polygon(cx + 2, cy - 16, cx + 10, cy - 17,
                              cx + 11, cy - 13, cx + 4, cy - 12,
                              fill=fill, outline=fill)
    elif kind == 'bubbles':
        _rrect(canvas, cx + 2, cy + 1, cx + 15, cy + 11, 4, fill)
        canvas.create_polygon(cx + 10, cy + 10, cx + 14, cy + 10, cx + 10, cy + 15,
                              fill=fill, outline=fill)
        _rrect(canvas, cx - 14, cy - 12, cx + 8, cy + 6, 6, fill)
        canvas.create_polygon(cx - 9, cy + 5, cx - 4, cy + 5, cx - 10, cy + 12,
                              fill=fill, outline=fill)
        for dx in (-9, -3, 3):
            canvas.create_oval(cx + dx - 1.7, cy - 3 - 1.7, cx + dx + 1.7, cy - 3 + 1.7,
                               fill=hole_at(cy - 3), outline=hole_at(cy - 3))
    elif kind == 'printer':
        canvas.create_rectangle(cx - 7, cy - 13, cx + 7, cy - 5,
                                fill='', outline=fill, width=3)
        _rrect(canvas, cx - 13, cy - 4, cx + 13, cy + 7, 3, fill)
        canvas.create_rectangle(cx - 8, cy + 1, cx + 8, cy + 13, fill=fill, outline=fill)
        canvas.create_oval(cx + 8.5, cy - 1.5, cx + 11, cy + 1,
                           fill=hole_at(cy), outline=hole_at(cy))
        for dy in (5, 8.5):
            canvas.create_rectangle(cx - 5, cy + dy, cx + 5, cy + dy + 1.6,
                                    fill=hole_at(cy + dy + 1),
                                    outline=hole_at(cy + dy + 1))
    elif kind == 'gear':
        for k in range(8):
            ang = k * math.pi / 4
            dx, dy = math.cos(ang), math.sin(ang)
            px, py = -dy, dx
            canvas.create_polygon(
                cx + dx * 8 + px * 3.2, cy + dy * 8 + py * 3.2,
                cx + dx * 13.5 + px * 2.2, cy + dy * 13.5 + py * 2.2,
                cx + dx * 13.5 - px * 2.2, cy + dy * 13.5 - py * 2.2,
                cx + dx * 8 - px * 3.2, cy + dy * 8 - py * 3.2,
                fill=fill, outline=fill)
        canvas.create_oval(cx - 9.5, cy - 9.5, cx + 9.5, cy + 9.5,
                           fill=fill, outline=fill)
        canvas.create_oval(cx - 3.8, cy - 3.8, cx + 3.8, cy + 3.8,
                           fill=hole_at(cy), outline=hole_at(cy))


def _make_nav_button(tk, parent, label, subtitle, stops, symbol, command):
    """One v1.7 sidebar tab: a canvas-drawn rounded gradient button
    with a white symbol and a white bold label. It speaks the small
    slice of the tk.Button API the app uses (cget('text'),
    cget('state'), configure(state=...)) so navigation code treats
    it like the old flat buttons."""

    class NavButton(tk.Canvas):
        WIDTH, HEIGHT, RADIUS = 252, 58, 16

        def __init__(self):
            self._label, self._subtitle = label, subtitle
            self._stops, self._symbol = stops, symbol
            self._command = command
            self._enabled, self._selected, self._hover = True, False, False
            super().__init__(parent, width=self.WIDTH, height=self.HEIGHT,
                             background=BG_SIDEBAR, highlightthickness=0, bd=0,
                             takefocus=1, cursor='hand2')
            self.bind('<Button-1>', self._click)
            self.bind('<Enter>', lambda _e: self._set_hover(True))
            self.bind('<Leave>', lambda _e: self._set_hover(False))
            self.bind('<space>', self._click)
            self.bind('<Return>', self._click)
            self._redraw()

        def cget(self, key):
            if key == 'text':
                return self._label + (('\n' + self._subtitle) if self._subtitle else '')
            if key == 'state':
                return 'normal' if self._enabled else 'disabled'
            return super().cget(key)

        def configure(self, cnf=None, **kw):
            merged = {}
            if isinstance(cnf, dict):
                merged.update(cnf)
            merged.update(kw)
            if 'state' in merged:
                self.set_enabled(merged.pop('state') == 'normal')
            if merged:
                return super().configure(merged)
            return None

        config = configure

        def set_enabled(self, value):
            self._enabled = bool(value)
            super().configure(cursor='hand2' if self._enabled else 'arrow')
            self._redraw()

        def set_selected(self, value):
            self._selected = bool(value)
            self._redraw()

        def _set_hover(self, on):
            self._hover = bool(on)
            self._redraw()

        def _click(self, *_):
            if self._enabled:
                self._command()

        def _stops_now(self):
            top, bottom = self._stops
            if not self._enabled:
                return _mix_hex(top, '#B9C2CC', .55), _mix_hex(bottom, '#B9C2CC', .55)
            if self._selected:
                return _shade_hex(top, .8), _shade_hex(bottom, .8)
            if self._hover:
                return _shade_hex(top, 1.12), _shade_hex(bottom, 1.12)
            return top, bottom

        def _color_at(self, y):
            top, bottom = self._stops_now()
            return _mix_hex(top, bottom, y / max(1, self.HEIGHT - 1))

        def _redraw(self):
            self.delete('all')
            top, bottom = self._stops_now()
            radius = self.RADIUS
            for y in range(self.HEIGHT):
                color = _mix_hex(top, bottom, y / (self.HEIGHT - 1))
                yy = y + .5
                inset = 0.0
                if yy < radius:
                    d = radius - yy
                    inset = radius - (radius * radius - d * d) ** .5
                elif yy > self.HEIGHT - radius:
                    d = yy - (self.HEIGHT - radius)
                    inset = radius - (radius * radius - d * d) ** .5
                self.create_rectangle(inset, y, self.WIDTH - inset, y + 1,
                                      fill=color, outline=color)
            fill = '#FFFFFF' if self._enabled else '#EDF1F5'
            _draw_nav_symbol(self, self._symbol, 36, self.HEIGHT // 2,
                             fill, self._color_at)
            if self._subtitle:
                self.create_text(62, 21, text=self._label, anchor='w', fill=fill,
                                 font=('Segoe UI', 13, 'bold'))
                self.create_text(62, 40, text=self._subtitle, anchor='w',
                                 fill='#DCE7F5' if self._enabled else '#EDF1F5',
                                 font=('Segoe UI', 9))
            else:
                self.create_text(62, self.HEIGHT // 2, text=self._label, anchor='w',
                                 fill=fill, font=('Segoe UI', 13, 'bold'))
            if self._selected:
                self.create_rectangle(0, 10, 4, self.HEIGHT - 10,
                                      fill='#FFFFFF', outline='#FFFFFF')

    return NavButton()


def _make_black_button(tk, parent, text, command):
    """One v1.7.1 black action button (owner order, 2026-11-08).

    A canvas-drawn rounded black rectangle with white bold centered
    text — NOT a tk.Button, because macOS Tk/Aqua ignores a
    tk.Button's custom background/foreground and rendered these
    buttons as near-white boxes with unreadable white-ish text on
    the owner's Mac. Canvas drawing is identical on Mac and Windows.

    The button is BLACK with WHITE text in BOTH states: disabled
    keeps the same black fill and white text (never the pale
    disabled gray) — it still looks like a real button, it just
    does not fire. It speaks the slice of the tk.Button API the app
    uses — cget('text'), cget('state'), cget('background'),
    cget('foreground'), cget('disabledforeground'),
    configure(state=...), set_enabled(bool), invoke() — so callers
    treat it like the buttons it replaces. Sizing mirrors the old
    _action_button: Segoe UI 12 bold, padx=16, pady=9.
    """
    import tkinter.font as tkfont

    class BlackButton(tk.Canvas):
        RADIUS = 8
        PADX, PADY = 16, 9
        FONT = ('Segoe UI', 12, 'bold')

        def __init__(self):
            self._text = text
            self._command = command
            self._enabled = True
            try:
                measure_font = tkfont.Font(
                    family='Segoe UI', size=12, weight='bold')
                text_w = measure_font.measure(text)
                text_h = measure_font.metrics('linespace')
            except Exception:
                text_w, text_h = len(text) * 9, 17
            self._width = int(text_w) + 2 * self.PADX
            self._height = int(text_h) + 2 * self.PADY
            try:
                ground = parent.cget('background')
            except Exception:
                ground = BG_APP
            super().__init__(parent, width=self._width, height=self._height,
                             background=ground, highlightthickness=0, bd=0,
                             takefocus=1, cursor='hand2')
            self.bind('<Button-1>', self._click)
            self.bind('<space>', self._click)
            self.bind('<Return>', self._click)
            self._redraw()

        # -- the tk.Button slice the app uses --
        def cget(self, key):
            if key == 'text':
                return self._text
            if key == 'state':
                return 'normal' if self._enabled else 'disabled'
            if key in ('background', 'bg'):
                return BTN_BLACK_BG
            if key in ('foreground', 'fg'):
                return BTN_BLACK_FG
            if key == 'disabledforeground':
                return BTN_BLACK_DISABLED_FG
            if key == 'font':
                return self.FONT
            return super().cget(key)

        def configure(self, cnf=None, **kw):
            merged = {}
            if isinstance(cnf, dict):
                merged.update(cnf)
            merged.update(kw)
            if 'state' in merged:
                self.set_enabled(merged.pop('state') == 'normal')
            if 'text' in merged:
                self._text = str(merged.pop('text'))
                self._redraw()
            # Colors are the owner's black style: background /
            # foreground / disabledforeground changes are accepted
            # and ignored, so the button can never drift off black.
            for color_key in ('background', 'bg', 'foreground', 'fg',
                              'disabledforeground', 'activebackground',
                              'activeforeground'):
                merged.pop(color_key, None)
            if merged:
                return super().configure(merged)
            return None

        config = configure

        def set_enabled(self, value):
            self._enabled = bool(value)
            super().configure(cursor='hand2' if self._enabled else 'arrow')
            self._redraw()

        def invoke(self):
            if self._enabled:
                self._command()

        def _click(self, *_):
            if self._enabled:
                self._command()

        def _redraw(self):
            self.delete('all')
            # Black in every state — enabled and disabled alike.
            _rrect(self, 1, 1, self._width - 1, self._height - 1,
                   self.RADIUS, BTN_BLACK_BG)
            self.create_text(self._width // 2, self._height // 2,
                             text=self._text, fill=BTN_BLACK_FG,
                             font=self.FONT, anchor='center')

    return BlackButton()


class PrintMyTextsApp:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk, self.root = tk, ttk, root
        self.work = WorkingData()
        self.messages, self.groups, self.pages = [], {}, []
        self.engine, self.photo, self.worker = None, None, None
        self.results = queue.Queue()
        self.stages = queue.Queue()
        self._import_source = None
        self.update_results = queue.Queue()
        self.update_worker = None
        self.update_info = None
        self.update_busy = False
        self.update_installing = False
        self.update_path = ensure_stable_alias()
        self.update_result_reported = False
        self.closing = False
        self.cancelled = threading.Event()
        self.page_index = 0
        self.view = 'chat'
        self._chat_summary = 'Select a conversation'
        root.title('PrintMyTexts v%s — iFixx Repairs' % VERSION)
        self.apply_theme(root)
        root.protocol('WM_DELETE_WINDOW', self.close)
        self._saved_geometry = None
        self._geometry_after = None
        self._restore_window_geometry()
        self.status = tk.StringVar(value='Ready — import from a phone or a backup file to begin.')
        # The phone page has its own plain-language status (fix 7): it
        # always says what the app is waiting for or doing.
        self.phone_status = tk.StringVar(
            value='Plug in the phone with a cable and unlock it, then tap Read USB phone below.')
        self.xml_name = tk.StringVar(value='No file selected')
        # ---- bottom status bar (present on every screen) ----
        statusbar = tk.Frame(root, background=BG_TOPBAR, height=36)
        statusbar.pack(side='bottom', fill='x')
        statusbar.pack_propagate(False)
        self.status_label = tk.Label(statusbar, textvariable=self.status, wraplength=1050,
                                     background=BG_TOPBAR, foreground=TEXT_SECONDARY,
                                     font=('Segoe UI', 10), anchor='w', justify='left')
        self.status_label.pack(side='left', fill='x', expand=True, padx=12)
        tk.Label(statusbar, text='Local-only processing', background=BG_TOPBAR,
                 foreground=STATUS_OK, font=('Segoe UI', 10, 'bold')).pack(side='right', padx=12)
        self._wrap_w = 0
        root.bind('<Configure>', self._fit_status)
        root.bind('<Configure>', self._track_geometry, add='+')
        # ---- body: navigation sidebar + content ----
        body = tk.Frame(root, background=BG_APP)
        body.pack(fill='both', expand=True)
        sidebar = tk.Frame(body, background=BG_SIDEBAR, width=272)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        self.content = tk.Frame(body, background=BG_APP)
        self.content.pack(side='left', fill='both', expand=True)
        # v1.7 (owner's tab-set ruling): there is no Home tab — the
        # app title IS the Home door. Tapping it always comes back
        # to the start page, so Home is never a dead end.
        self.title_label = tk.Label(sidebar, text='PrintMyTexts', background=BG_SIDEBAR,
                                    foreground=TEXT_PRIMARY, font=('Segoe UI', 20, 'bold'),
                                    cursor='hand2')
        self.title_label.pack(anchor='w', padx=16, pady=(18, 0))
        self.title_label.bind('<Button-1>', lambda _e: self.show_screen('home'))
        subtitle_label = tk.Label(sidebar, text='Text message transcripts',
                                  background=BG_SIDEBAR, foreground=TEXT_MUTED,
                                  font=('Segoe UI', 10), cursor='hand2')
        subtitle_label.pack(anchor='w', padx=16, pady=(0, 14))
        subtitle_label.bind('<Button-1>', lambda _e: self.show_screen('home'))
        self.nav_buttons = {}
        # v1.7.1: both 'View Transcript' black buttons (phone + XML
        # screens), kept so their style/state can be checked.
        self.view_transcript_buttons = []
        self._nav_key = 'home'
        self._screen = 'home'
        # v1.7 tabs (owner's picture + tab-set ruling, 2026-11-08):
        # big rounded colored buttons, white symbol + white bold
        # label. No Home tab (the title above is that door) and no
        # Message Transcript tab (a finished import already lands
        # on the open conversation).
        for key, label, subtitle, stops, symbol in (
                ('phone', 'Import from Phone', '', NAV_GREEN, 'robot'),
                ('xml', 'Import XML File', 'Opens a saved backup file', NAV_PURPLE, 'doc'),
                ('iphone', 'Import from iPhone', '', NAV_BLUE, 'apple'),
                ('print', 'Print / Export', '', NAV_ORANGE, 'printer'),
                ('settings', 'Settings', '', NAV_SETTINGS, 'gear')):
            btn = _make_nav_button(tk, sidebar, label=label, subtitle=subtitle,
                                   stops=stops, symbol=symbol,
                                   command=lambda k=key: self.show_screen(k))
            btn.pack(fill='x', padx=10, pady=5)
            self.nav_buttons[key] = btn
        # Print / Export needs loaded messages first (design spec s.1).
        self.nav_buttons['print'].set_enabled(False)
        bottom = tk.Frame(sidebar, background=BG_SIDEBAR)
        bottom.pack(side='bottom', fill='x', padx=8, pady=10)
        self.update_button = ttk.Button(bottom, text='UPDATE', style='Update.TButton',
                                        command=self.start_update)
        self.update_button.pack(fill='x')
        tk.Label(bottom, text='Local-only processing', background=BG_SIDEBAR,
                 foreground=STATUS_OK, font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(10, 0))
        tk.Label(bottom, text='Version %s — iFixx Repairs' % VERSION, background=BG_SIDEBAR,
                 foreground=TEXT_MUTED, font=('Segoe UI', 9)).pack(anchor='w')
        # ---- screens ----
        self.screens = {}
        for key in ('home', 'phone', 'xml', 'transcript', 'settings'):
            self.screens[key] = tk.Frame(self.content, background=BG_APP)
        self._build_home(self.screens['home'])
        self._build_phone_screen(self.screens['phone'])
        self._build_xml_screen(self.screens['xml'])
        self._build_workspace(self.screens['transcript'])
        self._build_settings(self.screens['settings'])
        self._paint_nav()
        self.screens['home'].pack(fill='both', expand=True)
        self._report_update_result()
        root.after(100, self.poll)
        root.after(1500, self._quiet_update_check)

    # ---------- window geometry: calm default + remembered size ------
    def _restore_window_geometry(self):
        root = self.root
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        min_w, min_h, _max_w, _max_h = _window_plan(sw, sh)
        root.minsize(min_w, min_h)
        root.geometry(clamp_window_geometry(load_window_geometry(), sw, sh))

    def _track_geometry(self, event):
        if event.widget is not self.root or self.closing:
            return
        if self._geometry_after is not None:
            try:
                self.root.after_cancel(self._geometry_after)
            except Exception:
                pass
            self._geometry_after = None
        self._geometry_after = self.root.after(500, self._save_geometry)

    def _save_geometry(self):
        self._geometry_after = None
        try:
            current = self.root.geometry()
        except Exception:
            return
        if current and current != self._saved_geometry:
            self._saved_geometry = current
            save_window_geometry(current)

    # ---------- Light Professional shell: navigation + screens -------

    def _paint_nav(self):
        for name, btn in self.nav_buttons.items():
            btn.set_selected(name == self._nav_key)

    def show_screen(self, key):
        if key == 'print':
            # Print / Export is the same workspace in paper view — the preview
            # is the exact page the PDF/print pipeline produces (no second
            # renderer), with the settings column beside it.
            self.set_view('paper')
            target = 'transcript'
        elif key == 'transcript':
            # Opening the Message Transcript area always lands on the
            # bubble chat view (fix 2) — never the flat paper text.
            self.set_view('chat')
            target = key
        elif key == 'iphone':
            # An iPhone cannot be read with a cable, so its tab opens
            # the backup-file page — the same door the help list
            # explains ('Import from iPhone').
            target = 'xml'
        else:
            target = key
        for name, frame in self.screens.items():
            if name == target:
                frame.pack(fill='both', expand=True)
            else:
                frame.pack_forget()
        self._screen = target
        self._nav_key = key
        self._paint_nav()

    def _enable_workspace(self):
        self.nav_buttons['print'].set_enabled(True)
        self._paint_nav()

    def _fit_wrap(self, host, label, inset):
        """Glue `label`'s wraplength to the real inner width of `host`
        (host width minus `inset` for padding/border/margin) and keep it
        glued on every resize. A fixed wraplength wider than the box the
        label actually gets makes Tk center the unwrapped line and clip
        BOTH edges in any font; a bound wraplength wraps the text inside
        the box instead, so it can never clip."""
        def _apply(event):
            if event.widget is not host:
                return
            width = event.width - inset
            if width >= 40 and int(label.cget('wraplength')) != width:
                label.configure(wraplength=width)
        host.bind('<Configure>', _apply, add='+')

    def _screen_banner(self, parent, title, subtitle):
        tk = self.tk
        banner = tk.Frame(parent, background=BG_PANEL, highlightbackground=BORDER,
                          highlightthickness=1)
        banner.pack(fill='x', padx=28, pady=(24, 12))
        texts = tk.Frame(banner, background=BG_PANEL)
        texts.pack(side='left', fill='x', expand=True, padx=16, pady=10)
        title_label = tk.Label(texts, text=title, background=BG_PANEL,
                               foreground=TEXT_PRIMARY, font=('Segoe UI', 18, 'bold'),
                               wraplength=400, justify='left')
        title_label.pack(anchor='w', fill='x')
        subtitle_label = tk.Label(texts, text=subtitle, background=BG_PANEL,
                                  foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                  wraplength=400, justify='left')
        subtitle_label.pack(anchor='w', fill='x')
        self._fit_wrap(texts, title_label, 8)
        self._fit_wrap(texts, subtitle_label, 8)
        return banner

    def _action_button(self, parent, text, command, background):
        if background == BG_PANEL_ALT:
            # Neutral door on the light face: dark text on light gray.
            foreground = TEXT_PRIMARY
            active_bg, active_fg = BG_HOVER, TEXT_PRIMARY
            # v1.7.1: disabled text stays DARK on the light door —
            # the old pale TEXT_DISABLED was unreadable.
            disabled_fg = TEXT_PRIMARY
        else:
            foreground = '#FFFFFF'
            active_bg, active_fg = ACCENT_HOVER, '#FFFFFF'
            # v1.7.1: on a colored door the disabled text stays
            # WHITE — readable on the color, never the pale gray.
            disabled_fg = '#FFFFFF'
        btn = self.tk.Button(parent, text=text, command=command, background=background,
                             foreground=foreground, activebackground=active_bg,
                             activeforeground=active_fg, disabledforeground=disabled_fg,
                             relief='flat', bd=0, font=('Segoe UI', 12, 'bold'),
                             padx=16, pady=9, highlightthickness=0)
        return btn

    def _black_button(self, parent, text, command):
        """A v1.7.1 black action button (see _make_black_button):
        black background, white bold text, in every state."""
        return _make_black_button(self.tk, parent, text, command)

    def _build_home(self, parent):
        tk = self.tk
        hero = tk.Frame(parent, background=BG_APP)
        hero.pack(fill='x', padx=28, pady=(26, 4))
        tk.Label(hero, text='PrintMyTexts', background=BG_APP, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 30, 'bold')).pack(anchor='w')
        tk.Label(hero, text='Turn text messages into a clean, printable transcript.',
                 background=BG_APP, foreground=TEXT_SECONDARY,
                 font=('Segoe UI', 13)).pack(anchor='w', pady=(2, 0))
        tk.Label(hero, text=UI_NOTICE, background=BG_APP, foreground=TEXT_MUTED,
                 font=('Segoe UI', 10)).pack(anchor='w', pady=(2, 0))
        info = tk.Frame(parent, background=BG_APP)
        info.pack(fill='x', padx=20, pady=(18, 6))
        for col in range(3):
            info.columnconfigure(col, weight=1)
        self._info_panel(info, 0, 'Local processing', 'No internet connection required.')
        self._info_panel(info, 1, 'Automatic cleanup', 'Session data is removed when the app closes.')
        self._info_panel(info, 2, 'Professional PDF', 'Clean transcripts, ready to print or save.')
        home_status = tk.Label(parent, textvariable=self.status, background=BG_APP,
                               foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                               wraplength=640, justify='left')
        home_status.pack(anchor='w', fill='x', padx=28, pady=12)
        self._fit_wrap(parent, home_status, 62)

    def _info_panel(self, parent, col, title, text):
        tk = self.tk
        panel = tk.Frame(parent, background=BG_PANEL_ALT, padx=14, pady=10,
                       highlightbackground=BORDER, highlightthickness=1)
        panel.grid(row=0, column=col, sticky='nsew', padx=8)
        title_label = tk.Label(panel, text=title, background=BG_PANEL_ALT,
                               foreground=TEXT_PRIMARY, font=('Segoe UI', 12, 'bold'),
                               wraplength=140, justify='left')
        title_label.pack(anchor='w', fill='x')
        text_label = tk.Label(panel, text=text, background=BG_PANEL_ALT,
                              foreground=TEXT_SECONDARY, font=('Segoe UI', 10),
                              wraplength=140, justify='left')
        text_label.pack(anchor='w', fill='x')
        # Panel inner width = panel width - 2*14 padding - 2*1 border;
        # wraplength rides 6 px under it, glued on every resize.
        self._fit_wrap(panel, title_label, 36)
        self._fit_wrap(panel, text_label, 36)

    def _build_phone_screen(self, parent):
        tk = self.tk
        self._screen_banner(parent, 'Import from Phone',
                            'Connect one unlocked Android phone with a cable.')
        panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill='x', padx=28, pady=6)
        tk.Label(panel, text='Device connection', background=BG_PANEL,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        phone_status = tk.Label(panel, textvariable=self.phone_status, background=BG_PANEL,
                                foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                wraplength=640, justify='left')
        phone_status.pack(anchor='w', fill='x', pady=(4, 10))
        self._fit_wrap(panel, phone_status, 48)
        self.read_button = self._black_button(panel, 'Read USB phone', self.read_phone)
        self.read_button.pack(anchor='w')
        nav = tk.Frame(parent, background=BG_APP)
        nav.pack(fill='x', padx=28, pady=14)
        self._action_button(nav, 'Back', lambda: self.show_screen('home'), BG_PANEL_ALT).pack(side='left')
        phone_view = self._black_button(nav, 'View Transcript',
                                        lambda: self.show_screen('transcript'))
        phone_view.pack(side='right')
        self.view_transcript_buttons.append(phone_view)

    def _build_xml_screen(self, parent):
        tk = self.tk
        self._screen_banner(parent, 'Import from a Backup File',
                            'Select a backup file from the SMS Backup & Restore app.')
        panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill='x', padx=28, pady=6)
        tk.Label(panel, text='File', background=BG_PANEL, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        row = tk.Frame(panel, background=BG_PANEL)
        row.pack(fill='x', pady=(6, 4))
        tk.Label(row, textvariable=self.xml_name, background=BG_INPUT,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 11),
                 anchor='w', padx=10, pady=8).pack(side='left', fill='x', expand=True)
        self.import_button = self._black_button(row, 'Browse Files', self.import_xml)
        self.import_button.pack(side='right', padx=(10, 0))
        for label, value in (('Type', 'Backup file (SMS Backup & Restore)'),):
            tk.Label(panel, text='%s:  %s' % (label, value), background=BG_PANEL,
                     foreground=TEXT_SECONDARY, font=('Segoe UI', 11)).pack(anchor='w', pady=2)
        xml_status = tk.Label(panel, textvariable=self.status, background=BG_PANEL,
                              foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                              wraplength=640, justify='left')
        xml_status.pack(anchor='w', fill='x', pady=(6, 0))
        self._fit_wrap(panel, xml_status, 48)
        nav = tk.Frame(parent, background=BG_APP)
        nav.pack(fill='x', padx=28, pady=14)
        self._action_button(nav, 'Back', lambda: self.show_screen('home'), BG_PANEL_ALT).pack(side='left')
        xml_view = self._black_button(nav, 'View Transcript',
                                      lambda: self.show_screen('transcript'))
        xml_view.pack(side='right')
        self.view_transcript_buttons.append(xml_view)

    def _build_workspace(self, parent):
        tk, ttk = self.tk, self.ttk
        split = tk.PanedWindow(parent, orient='horizontal', background=BG_APP,
                               sashwidth=6, bd=0, opaqueresize=True)
        split.pack(fill='both', expand=True, padx=12, pady=12)
        self.split = split
        left, right = ttk.Frame(split), ttk.Frame(split)
        # On a small screen the panes narrow with the window's size
        # class, so the compact window never squeezes them past
        # their minimums.
        if _small_screen(parent.winfo_screenwidth(),
                         parent.winfo_screenheight()):
            side_min, content_min = 270, 460
        else:
            side_min, content_min = 320, 520
        split.add(left, minsize=side_min, stretch='always')
        split.add(right, minsize=content_min, stretch='always')
        tk.Label(left, text='Conversations', background=BG_APP, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 14, 'bold')).pack(anchor='w', pady=(0, 6))
        # v1.7 (Grok upgrade): find a conversation by name or digits.
        ttk.Label(left, text='Search conversations').pack(anchor='w')
        self.search = tk.StringVar()
        ttk.Entry(left, textvariable=self.search).pack(fill='x', pady=(0, 6))
        self.search.trace_add('write', lambda *_: self._refresh_tree())
        self.tree = ttk.Treeview(left, columns=('count', 'recent'), show='tree headings',
                                 height=10, selectmode='extended')
        self.tree.heading('#0', text='Contact / number')
        self.tree.heading('count', text='Count')
        self.tree.heading('recent', text='Latest date')
        self.tree.column('#0', width=240, minwidth=180, stretch=True)
        self.tree.column('count', width=64, stretch=False)
        self.tree.column('recent', width=105, stretch=False)
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.select)
        self.name, self.start, self.end = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, variable in (('Contact name (editable)', self.name), ('From YYYY-MM-DD (optional)', self.start), ('Through YYYY-MM-DD (optional)', self.end)):
            ttk.Label(left, text=label).pack(anchor='w', pady=(8, 0))
            ttk.Entry(left, textvariable=variable).pack(fill='x')
            variable.trace_add('write', self.invalidate)
        # v1.7 (Grok upgrade): one-tap date ranges — they fill the
        # two date boxes above, so the boxes always show the truth.
        preset_row = tk.Frame(left, background=BG_APP)
        preset_row.pack(fill='x', pady=(8, 0))
        for i, (preset_label, preset_kind) in enumerate((
                ('Last 7 days', '7'), ('Last 30 days', '30'),
                ('This month', 'month'), ('All time', 'all'))):
            preset_btn = ttk.Button(preset_row, text=preset_label,
                                    command=lambda k=preset_kind: self.apply_preset(k))
            preset_btn.grid(row=i // 2, column=i % 2, sticky='ew',
                            padx=(0, 4) if i % 2 == 0 else (4, 0), pady=2)
        preset_row.columnconfigure(0, weight=1)
        preset_row.columnconfigure(1, weight=1)
        ttk.Button(left, text='Apply / preview', command=self.preview).pack(fill='x', pady=8)
        # v1.7 (Grok+Gemini upgrade): every conversation at once —
        # or Ctrl/Shift-click several rows, then Apply / preview.
        ttk.Button(left, text='Print all conversations', command=self.print_all).pack(fill='x', pady=(0, 8))
        self.private = tk.BooleanVar(value=False)
        self.private.trace_add('write', self.invalidate)
        ttk.Checkbutton(left, text='Hide the phone number (private print)', variable=self.private).pack(anchor='w', pady=(0, 8))
        ttk.Label(left, text='Transcripts never carry shop information. Private print also hides the phone number. Message text is never changed.', wraplength=300).pack(anchor='w')
        action = tk.Frame(right, background=BG_APP)
        action.pack(fill='x', pady=(0, 8))
        self.chat_btn = self._action_button(action, 'Chat view', lambda: self.set_view('chat'), BG_PANEL_ALT)
        self.chat_btn.pack(side='left')
        self.paper_btn = self._action_button(action, 'Paper view', lambda: self.set_view('paper'), BG_PANEL_ALT)
        self.paper_btn.pack(side='left', padx=(6, 10))
        self._action_button(action, '\u25C0', lambda: self.show_page(-1), BG_PANEL_ALT).pack(side='left')
        self._action_button(action, '\u25B6', lambda: self.show_page(1), BG_PANEL_ALT).pack(side='left', padx=(4, 0))
        self.page_label = tk.Label(action, text='Select a conversation', background=BG_APP,
                                   foreground=TEXT_SECONDARY, font=('Segoe UI', 11))
        self.page_label.pack(side='left', padx=8)
        # v1.7: the print/export buttons get their own row — with
        # Save TXT added, the single v1.6 row overflowed the pane at
        # the default window size and clipped the export buttons.
        export_row = tk.Frame(right, background=BG_APP)
        export_row.pack(fill='x', pady=(0, 8))
        self.print_button = self._action_button(export_row, 'PRINT', self.print_transcript, ACCENT)
        self.print_button.configure(state='disabled')
        self.print_button.pack(side='right')
        self.pdf_button = self._action_button(export_row, 'Save PDF', self.save_pdf, EXPORT_CONFIRM)
        self.pdf_button.configure(state='disabled')
        self.pdf_button.pack(side='right', padx=8)
        # v1.7 (Grok upgrade): the same transcript as a plain-text
        # file, beside the PDF.
        self.txt_button = self._action_button(export_row, 'Save TXT', self.save_txt, EXPORT_CONFIRM)
        self.txt_button.configure(state='disabled')
        self.txt_button.pack(side='right')
        self.paper_frame = tk.Frame(right, background=PREVIEW_BG)
        self.canvas = tk.Canvas(self.paper_frame, background=PREVIEW_BG, highlightthickness=0)
        scroll = ttk.Scrollbar(self.paper_frame, orient='vertical', command=self.canvas.yview)
        scroll.pack(side='right', fill='y')
        horizontal = ttk.Scrollbar(self.paper_frame, orient='horizontal', command=self.canvas.xview)
        horizontal.pack(side='bottom', fill='x')
        self.canvas.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        self.canvas.pack(fill='both', expand=True)
        self.chat_frame = tk.Frame(right, background=CHAT_BG)
        self.chat_canvas = tk.Canvas(self.chat_frame, background=CHAT_BG, highlightthickness=0)
        chat_scroll = ttk.Scrollbar(self.chat_frame, orient='vertical', command=self.chat_canvas.yview)
        chat_scroll.pack(side='right', fill='y')
        self.chat_canvas.configure(yscrollcommand=chat_scroll.set)
        self.chat_canvas.pack(fill='both', expand=True)
        self.chat_inner = tk.Frame(self.chat_canvas, background=CHAT_BG)
        self.chat_window = self.chat_canvas.create_window((0, 0), window=self.chat_inner, anchor='nw')
        self.chat_inner.bind('<Configure>', lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox('all')))
        self.chat_canvas.bind('<Configure>', lambda e: self.chat_canvas.itemconfigure(self.chat_window, width=e.width))
        self.set_view('chat')

    def _build_settings(self, parent):
        tk = self.tk
        # The stacked settings panels — the full help list above all —
        # outgrow the window height, so the page scrolls (same canvas
        # pattern as the transcript panes); otherwise the last help
        # lines are packed past the bottom edge and can never be read.
        outer = parent
        canvas = tk.Canvas(outer, background=BG_APP, highlightthickness=0)
        vscroll = self.ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        vscroll.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        canvas.configure(yscrollcommand=vscroll.set)
        parent = tk.Frame(canvas, background=BG_APP)
        window = canvas.create_window((0, 0), window=parent, anchor='nw')
        parent.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(window, width=e.width))
        self.settings_canvas = canvas
        tk.Label(parent, text='Settings', background=BG_APP, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 24, 'bold')).pack(anchor='w', padx=28, pady=(24, 8))
        panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill='x', padx=28, pady=6)
        tk.Label(panel, text='Version', background=BG_PANEL, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        tk.Label(panel, text='PrintMyTexts v%s — iFixx Repairs' % VERSION, background=BG_PANEL,
                 foreground=TEXT_SECONDARY, font=('Segoe UI', 11)).pack(anchor='w', pady=(2, 10))
        self.settings_update_button = self._action_button(panel, 'Check for updates',
                                                          self.start_update, ACCENT)
        self.settings_update_button.pack(anchor='w')
        privacy = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        privacy.pack(fill='x', padx=28, pady=6)
        tk.Label(privacy, text='Privacy', background=BG_PANEL, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        notice_label = tk.Label(privacy, text=UI_NOTICE, background=BG_PANEL,
                                foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                wraplength=640, justify='left')
        notice_label.pack(anchor='w', fill='x', pady=(2, 0))
        times_label = tk.Label(privacy, text='Times are shown the way the phone recorded them. Only received/sent are labeled YOU/THEM; other directions stay unreadable. Session data is removed when the app closes.',
                               background=BG_PANEL, foreground=TEXT_SECONDARY,
                               font=('Segoe UI', 11), wraplength=640, justify='left')
        times_label.pack(anchor='w', fill='x', pady=(2, 0))
        self._fit_wrap(privacy, notice_label, 48)
        self._fit_wrap(privacy, times_label, 48)
        # Plain-language help (fix 8): what every button does, one line each.
        help_panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                      highlightbackground=BORDER, highlightthickness=1)
        help_panel.pack(fill='x', padx=28, pady=6)
        tk.Label(help_panel, text='What everything does', background=BG_PANEL,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        for help_title, help_line in HELP_LINES:
            row = tk.Frame(help_panel, background=BG_PANEL)
            row.pack(fill='x', pady=(8, 0))
            tk.Label(row, text=help_title, background=BG_PANEL, foreground=TEXT_PRIMARY,
                     font=('Segoe UI', 11, 'bold')).pack(anchor='w')
            line_label = tk.Label(row, text=help_line, background=BG_PANEL,
                                  foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                  wraplength=640, justify='left')
            line_label.pack(anchor='w', fill='x')
            self._fit_wrap(row, line_label, 8)

    def apply_theme(self, root):
        # Light Professional shell + large, wide screen fonts (owner
        # readability). Printed pages are unaffected (paper stays black on
        # white, rendered by the unchanged layout pipeline).
        tk, ttk = self.tk, self.ttk
        root.configure(background=BG_APP)
        root.option_add('*Font', ('Segoe UI', 12))
        style = ttk.Style(root)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('.', background=BG_APP, foreground=TEXT_PRIMARY, font=('Segoe UI', 12))
        style.configure('TFrame', background=BG_APP)
        style.configure('TLabelframe', background=BG_APP, foreground=TEXT_PRIMARY)
        style.configure('TLabel', background=BG_APP, foreground=TEXT_PRIMARY, font=('Segoe UI', 12))
        style.configure('TButton', background=BG_PANEL_ALT, foreground=TEXT_PRIMARY,
                        font=('Segoe UI', 12, 'bold'), padding=6)
        style.map('TButton', background=[('active', BG_HOVER), ('disabled', '#C3CEDA')],
                  foreground=[('disabled', TEXT_DISABLED)])
        style.configure('Update.TButton', background=UPDATE_BLUE, foreground='#ffffff',
                        font=('Segoe UI', 12, 'bold'), padding=6)
        style.map('Update.TButton', background=[('active', UPDATE_BLUE_HOVER), ('disabled', '#C3CEDA')],
                  # v1.7.1: disabled UPDATE text is the DARK primary
                  # color on its light disabled background — clearly
                  # readable, never the old pale TEXT_DISABLED.
                  foreground=[('disabled', TEXT_PRIMARY)])
        style.configure('TCheckbutton', background=BG_APP, foreground=TEXT_PRIMARY, font=('Segoe UI', 12))
        style.configure('TEntry', fieldbackground=BG_INPUT, foreground=TEXT_PRIMARY,
                        font=('Verdana', 12), padding=4)
        style.configure('Treeview', background=LP_SURFACE, fieldbackground=LP_SURFACE,
                        foreground=TEXT_PRIMARY, font=('Verdana', 12), rowheight=32)
        style.configure('Treeview.Heading', background=BG_PANEL_ALT, foreground=TEXT_PRIMARY,
                        font=('Segoe UI', 12, 'bold'))
        style.map('Treeview', background=[('selected', NAV_SELECTED)],
                  foreground=[('selected', TEXT_PRIMARY)])
        style.configure('TScrollbar', background=BG_PANEL_ALT, troughcolor=BG_PANEL)
        style.configure('TPanedwindow', background=BG_APP)

    def set_view(self, view):
        self.view = view
        if view == 'chat':
            self.paper_frame.pack_forget()
            self.chat_frame.pack(fill='both', expand=True)
            self.page_label.configure(text=self._chat_summary)
        else:
            self.chat_frame.pack_forget()
            self.paper_frame.pack(fill='both', expand=True)
            if self.pages:
                self.show_page()
            else:
                self.page_label.configure(text='Select a conversation')
        self._paint_view_buttons()

    def _paint_view_buttons(self):
        if not hasattr(self, 'chat_btn'):
            return
        for btn, active in ((self.chat_btn, self.view == 'chat'),
                            (self.paper_btn, self.view == 'paper')):
            btn.configure(background=ACCENT if active else BG_PANEL_ALT,
                          foreground='#FFFFFF' if active else TEXT_SECONDARY)

    def _chat_bubble(self, row, body, fill, foreground, anchor, padx, justify):
        """One rounded chat bubble (screen only): the wrapped message text on
        a small canvas, over a rounded rectangle built from corner ovals and
        cross rectangles — primitive shapes only, so the corners draw
        identically on Windows Tk and Aqua Tk. Padding matches the old flat
        labels (12 x 8); the wrap width is 430 wherever the pane leaves
        room for it (see below)."""
        tk = self.tk
        pad_x, pad_y, radius = 12, 8, 14
        # Wrap at 430 like the old flat labels, but never wider than the
        # row leaves room for: in a narrow pane the packer would shrink a
        # max-width bubble and clip its text at the bubble's edge. The
        # update_idletasks settles the pack layout first, so the row width
        # is real even when a render is triggered before the window's
        # first full update.
        row.update_idletasks()
        wrap = 430
        row_width = row.winfo_width()
        if row_width > 1:
            wrap = max(160, min(430, row_width - (padx[0] + padx[1]) - 2 * pad_x))
        canvas = tk.Canvas(row, background=CHAT_BG, highlightthickness=0,
                           borderwidth=0)
        text_id = canvas.create_text(pad_x, pad_y, text=body,
                                     font=('Verdana', 12), fill=foreground,
                                     width=wrap, anchor='nw', justify=justify)
        canvas.update_idletasks()
        box = canvas.bbox(text_id) or (pad_x, pad_y, pad_x + 10, pad_y + 10)
        x0, y0 = box[0] - pad_x, box[1] - pad_y
        x1, y1 = box[2] + pad_x, box[3] + pad_y
        r = max(2, min(radius, (x1 - x0) // 2, (y1 - y0) // 2))
        shapes = [
            canvas.create_rectangle(x0 + r, y0, x1 - r, y1,
                                    fill=fill, outline=fill),
            canvas.create_rectangle(x0, y0 + r, x1, y1 - r,
                                    fill=fill, outline=fill),
        ]
        for cx, cy in ((x0, y0), (x1 - 2 * r, y0),
                       (x0, y1 - 2 * r), (x1 - 2 * r, y1 - 2 * r)):
            shapes.append(canvas.create_oval(cx, cy, cx + 2 * r, cy + 2 * r,
                                             fill=fill, outline=fill))
        for shape in shapes:
            canvas.tag_lower(shape, text_id)
        canvas.configure(width=x1 - x0, height=y1 - y0)
        canvas.pack(anchor=anchor, padx=padx)

    def render_chat(self, messages, name):
        """Phone-style bubble view (screen only): rounded bubbles — contact
        on the LEFT in light #E7EDF3, the phone owner (sent) on the RIGHT in
        strong ACCENT blue with white text (owner 2026-10-26: one side one
        color, the other side a different color), on a light timeline, with
        date separators. Message text is shown exactly as stored; the paper
        transcript remains the labeled record (YOU / contact name / THEM,
        unchanged)."""
        tk = self.tk
        for child in self.chat_inner.winfo_children():
            child.destroy()
        display = (name or '').strip() or 'THEM'
        count = 0
        last_day = None
        for message in ordered(messages):
            count += 1
            day = format_day(message.timestamp)
            if day != last_day:
                last_day = day
                sep = tk.Frame(self.chat_inner, background=CHAT_BG)
                sep.pack(fill='x', pady=(12, 2))
                tk.Label(sep, text=day, font=('Segoe UI', 9, 'bold'),
                         foreground=DATE_SEP_FG, background=DATE_SEP_BG,
                         padx=12, pady=3).pack(anchor='center')
            row = tk.Frame(self.chat_inner, background=CHAT_BG)
            row.pack(fill='x', padx=10, pady=(5, 0))
            body = safe_display(message.body or '')
            if message.direction == 'sent':
                tk.Label(row, text='YOU · ' + format_time(message.timestamp), font=('Verdana', 9),
                         foreground=BUBBLE_OWNER_META, background=CHAT_BG).pack(anchor='e')
                self._chat_bubble(row, body, BUBBLE_OWNER, BUBBLE_OWNER_TEXT,
                                  'e', (140, 0), 'left')
            elif message.direction == 'received':
                tk.Label(row, text=display + ' · ' + format_time(message.timestamp), font=('Verdana', 9),
                         foreground=BUBBLE_CUSTOMER_META, background=CHAT_BG).pack(anchor='w')
                self._chat_bubble(row, body, BUBBLE_CUSTOMER, BUBBLE_CUSTOMER_TEXT,
                                  'w', (0, 140), 'left')
            else:
                tk.Label(row, text='— ' + format_date(message.timestamp) + ' —', font=('Verdana', 9),
                         foreground=BUBBLE_CUSTOMER_META, background=CHAT_BG).pack(anchor='center')
                self._chat_bubble(row, body, BUBBLE_UNKNOWN, BUBBLE_CUSTOMER_TEXT,
                                  'center', (0, 0), 'center')
        self._chat_summary = '%s — %d messages' % (display, count)
        if self.view == 'chat':
            self.page_label.configure(text=self._chat_summary)
        self.chat_canvas.yview_moveto(0)

    def _fit_status(self, event):
        # The status line wraps to the real window width, not a fixed 1050.
        if event.widget is not self.root:
            return
        width = max(420, event.width - 40)
        if abs(width - self._wrap_w) > 8:
            self._wrap_w = width
            self.status_label.configure(wraplength=width)

    def invalidate(self, *_):
        self.pages.clear()
        self.photo = None
        self.canvas.delete('all')
        for child in self.chat_inner.winfo_children():
            child.destroy()
        self._chat_summary = 'Apply / preview to refresh'
        self.print_button.configure(state='disabled')
        self.pdf_button.configure(state='disabled')
        self.txt_button.configure(state='disabled')
        self.page_label.configure(text='Apply / preview to refresh')

    def busy(self, value):
        state = 'disabled' if value else 'normal'
        self.read_button.configure(state=state)
        self.import_button.configure(state=state)
        if hasattr(self, 'settings_update_button'):
            self.settings_update_button.configure(state=state)
        if hasattr(self, 'update_button'):
            self.update_button.configure(
                state='disabled' if value or self.update_busy else 'normal')

    def load_async(self, loader, working_text='Reading your messages…'):
        if self.worker and self.worker.is_alive():
            return
        self.invalidate()
        self.messages.clear()
        self.groups.clear()
        self.tree.delete(*self.tree.get_children())
        self.busy(True)
        # Plain words only (fix 7): the status always says what the app
        # is doing — never a vague 'Reading locally…'.
        self.status.set(working_text)
        def task():
            try:
                result = loader()
            except Exception as exc:
                result = str(exc)
            self.results.put(result)
        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    def _stage(self, stage):
        # Worker-thread progress (e.g. the phone answered and the read
        # has begun) — drained by poll() on the UI thread.
        self.stages.put(stage)

    def read_phone(self):
        self._import_source = 'phone'
        self.phone_status.set('Waiting for the phone… unlock it, and tap Allow on the phone if it asks.')
        self.load_async(lambda: AdbReader(cancelled=self.cancelled, on_stage=self._stage).read(),
                        working_text='Waiting for the phone…')

    def import_xml(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title='SMS Backup & Restore backup file', filetypes=[('Backup file', '*.xml')])
        if path:
            self._import_source = 'backup'
            self.xml_name.set(path)
            self.show_screen('xml')
            self.load_async(lambda: parse_xml(path))

    def poll(self):
        if self.closing:
            if ((self.worker and self.worker.is_alive())
                    or (self.update_worker and self.update_worker.is_alive())):
                self.root.after(100, self.poll)
                return
            self.finish_close()
            return
        try:
            while True:
                stage = self.stages.get_nowait()
                if stage == 'reading':
                    self.phone_status.set('Reading your messages… keep the phone plugged in and unlocked.')
        except queue.Empty:
            pass
        try:
            result = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy(False)
            if isinstance(result, str):
                if self._import_source == 'phone':
                    # Phone-read failures reach the screen only as plain
                    # sentences (fix 7) — never the raw tool wording.
                    result = plain_phone_error(result)
                    self.phone_status.set(result)
                self.status.set(result)
            else:
                self.messages = result.messages
                self.groups = conversations(self.messages)
                self._refresh_tree()
                warning = ' '.join(result.warnings)
                self.status.set(f'{len(self.messages)} messages loaded. {warning}' if self.messages else 'No messages in this backup.')
                if self._import_source == 'phone':
                    self.phone_status.set('Done — here are your conversations.' if self.messages
                                          else 'Done — no messages were found on the phone.')
                if self.messages:
                    self._enable_workspace()
                    self.show_screen('transcript')
                    # Land straight on the messages (fix 6): open the
                    # first conversation so its bubbles are on screen —
                    # no separate 'Message Transcript' tap needed.
                    self.tree.selection_set('0')
                    self.select()
        try:
            kind, payload = self.update_results.get_nowait()
        except queue.Empty:
            pass
        else:
            self._handle_update_result(kind, payload)
        self.root.after(100, self.poll)

    def start_update(self):
        if self.closing or self.update_busy:
            return
        reason = updater_guard_reason(
            bool(self.worker and self.worker.is_alive()), bool(self.messages))
        if reason:
            self.status.set(reason)
            return
        self.update_busy = True
        self.update_button.configure(state='disabled')
        self.status.set('Checking the update feed…')
        self.update_worker = threading.Thread(
            target=self._check_update, daemon=True)
        self.update_worker.start()

    def _check_update(self):
        info = check_for_update()
        self.update_results.put(('checked', info))

    def _quiet_update_check(self):
        if self.closing:
            return
        worker = threading.Thread(target=self._check_update_quietly, daemon=True)
        worker.start()

    def _check_update_quietly(self):
        info = check_for_update()
        if info:
            self.update_results.put(('startup_available', info))

    def _handle_update_result(self, kind, payload):
        if kind == 'startup_available':
            if payload:
                self.update_info = payload
                self.update_button.configure(
                    text='⬆ UPDATE: v%s' % payload['version'])
        elif kind == 'checked':
            from tkinter import messagebox
            self.update_busy = False
            self.update_button.configure(state='normal')
            if not payload:
                self.status.set('No newer update found, or the update feed could not be reached.')
                return
            self.update_info = payload
            if not messagebox.askyesno(
                    'PrintMyTexts update',
                    'PrintMyTexts v%s is available (you have v%s).\\n\\n%s\\n\\n'
                    'Download and install it now? PrintMyTexts will restart.'
                    % (payload['version'], VERSION, payload.get('notes') or '')):
                self.status.set('Update cancelled. You are still using v%s.' % VERSION)
                return
            self.update_busy = True
            self.update_button.configure(state='disabled')
            self.status.set('Downloading and verifying PrintMyTexts v%s…'
                            % payload['version'])
            self.update_worker = threading.Thread(
                target=self._download_update, args=(payload,), daemon=True)
            self.update_worker.start()
        elif kind == 'downloaded':
            info, path, error = payload
            if error:
                self.update_busy = False
                self.update_button.configure(state='normal')
                self.status.set('Update not installed: %s. Still using v%s.'
                                % (error, VERSION))
                return
            reason = updater_guard_reason(
                bool(self.worker and self.worker.is_alive()),
                bool(self.messages))
            if reason:
                Path(path).unlink(missing_ok=True)
                self.update_busy = False
                self.update_button.configure(state='normal')
                self.status.set(reason)
                return
            self.status.set('Installing v%s and restarting…' % info['version'])
            try:
                begin_update(self.update_path, path, info['version'], VERSION)
            except Exception as exc:
                Path(path).unlink(missing_ok=True)
                self.update_busy = False
                self.update_button.configure(state='normal')
                self.status.set('Update could not start (%s). Still using v%s.'
                                % (exc, VERSION))
                return
            self.update_installing = True
            self.root.after(400, self.close)

    def _download_update(self, info):
        path, error = download_update(info, self.update_path.parent)
        self.update_results.put(('downloaded', (info, path, error)))

    def _report_update_result(self):
        if self.update_result_reported or self.closing:
            return
        result_path = self.update_path.parent / 'update_result.json'
        try:
            if not result_path.is_file():
                self.root.after(1000, self._report_update_result)
                return
            result = json.loads(result_path.read_text(encoding='utf-8'))
            result_path.unlink(missing_ok=True)
            self.update_result_reported = True
            if result.get('outcome') == 'rolled_back':
                self.status.set('Update did not start; restored PrintMyTexts v%s.'
                                % result.get('from_version', VERSION))
            elif result.get('outcome') == 'updated':
                self.status.set('Updated to PrintMyTexts v%s.'
                                % result.get('to_version', VERSION))
        except Exception:
            self.status.set('The last update result could not be read.')

    def selected(self):
        selection = self.tree.selection()
        if not selection:
            raise ValueError('Pick a conversation first.')
        return list(self.groups.values())[int(selection[0])]

    def select(self, _event=None):
        try:
            group = self.selected()
            self.name.set(next((m.contact_name for m in group if m.contact_name), ''))
            self.preview()
        except ValueError:
            pass

    def preview(self):
        from tkinter import messagebox
        self.invalidate()
        try:
            selection = self.tree.selection()
            if not selection:
                raise ValueError('Pick a conversation first.')
            indexes = sorted(int(item) for item in selection)
            groups = list(self.groups.values())
            if self.engine is None:
                self.engine = WindowsPages()
            # v1.7: one conversation previews exactly as before;
            # several selected conversations lay out back to back,
            # each starting on its own page with its own header —
            # one combined document for Print / PDF / TXT.
            all_pages = []
            primary = None
            for position, index in enumerate(indexes):
                group = groups[index]
                messages = filter_dates(group, self.start.get().strip(),
                                        self.end.get().strip())
                if not messages:
                    continue
                if position == 0:
                    shown_name = self.name.get()
                else:
                    shown_name = next((m.contact_name for m in group
                                       if m.contact_name), '')
                all_pages += layout_pages(messages, shown_name, group[0].address,
                                          self.engine.measure,
                                          private=self.private.get())
                if primary is None:
                    primary = (messages, self.name.get())
            if primary is None:
                raise ValueError('No messages in that date range.')
            self.pages = all_pages
            self.page_index = 0
            self.show_page()
            self.render_chat(primary[0], primary[1])
            if len(indexes) > 1:
                # The page count for the whole combined document is
                # on screen before any print dialog (Grok upgrade).
                self._chat_summary += (f' · {len(self.pages)} pages for '
                                       f'{len(indexes)} conversations')
                if self.view == 'chat':
                    self.page_label.configure(text=self._chat_summary)
            self.print_button.configure(state='normal')
            self.pdf_button.configure(state='normal')
            self.txt_button.configure(state='normal')
        except Exception as exc:
            messagebox.showerror('PrintMyTexts', str(exc))

    def show_page(self, delta=0):
        if not self.pages:
            return
        self.page_index = max(0, min(len(self.pages)-1, self.page_index + delta))
        # Pixel-identical page at 100% with scrolling; no browser caches.
        self.photo = self.tk.PhotoImage(data=png_bytes(self.engine.raster(self.pages[self.page_index])))
        self.canvas.delete('all')
        self.canvas.create_image(0, 0, anchor='nw', image=self.photo)
        self.canvas.configure(scrollregion=(0, 0, PAGE_W, PAGE_H))
        self.canvas.yview_moveto(0)
        # v1.7 (Grok upgrade): the page count is on screen in BOTH
        # views, before any print dialog can open.
        self.page_label.configure(text=f'Page {self.page_index + 1} of {len(self.pages)}')

    def print_transcript(self):
        from tkinter import messagebox
        try:
            if self.pages and self.engine.print_pages(self.pages):
                self.status.set('Submitted to the Windows print spooler.')
        except Exception as exc:
            messagebox.showerror('Print failed', str(exc))

    def save_pdf(self):
        from tkinter import filedialog, messagebox
        if not self.pages:
            return
        path = filedialog.asksaveasfilename(title='Save customer PDF copy', defaultextension='.pdf', filetypes=[('PDF', '*.pdf')])
        if not path:
            return
        staged = self.work.path / 'export.pdf'
        try:
            write_pdf(staged, self.pages, self.engine.raster)
            shutil.copyfile(staged, path)
            self.status.set('PDF saved to the location you selected. This requested copy is retained.')
        except Exception as exc:
            messagebox.showerror('PDF export failed', str(exc))
        finally:
            staged.unlink(missing_ok=True)

    def save_txt(self):
        """v1.7 (Grok upgrade): the plain-text twin of Save PDF —
        the exact lines of the laid-out pages, so the .txt always
        matches the printed document word for word."""
        from tkinter import filedialog, messagebox
        if not self.pages:
            return
        path = filedialog.asksaveasfilename(title='Save plain-text transcript',
                                            defaultextension='.txt',
                                            filetypes=[('Text file', '*.txt')])
        if not path:
            return
        staged = self.work.path / 'export.txt'
        try:
            chunks = []
            for page in self.pages:
                chunks.append('\n'.join(item.text for item in page
                                        if isinstance(item, DrawLine)))
            staged.write_text('\n\n'.join(chunks), encoding='utf-8')
            shutil.copyfile(staged, path)
            self.status.set('Text file saved to the location you selected. '
                            'This requested copy is retained.')
        except Exception as exc:
            messagebox.showerror('Text export failed', str(exc))
        finally:
            staged.unlink(missing_ok=True)

    def _refresh_tree(self):
        """(Re)fill the conversation list from self.groups, honoring
        the search box (v1.7): a row shows when the typed words match
        the contact name or the number, or the typed digits match
        the number's digits. Row ids stay the group indexes, so the
        selection mapping never moves."""
        if not hasattr(self, 'tree'):
            return
        query = self.search.get().strip().lower() if hasattr(self, 'search') else ''
        digits = re.sub(r'\D', '', query)
        keep = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for index, group in enumerate(self.groups.values()):
            name = next((m.contact_name for m in group if m.contact_name), '')
            address = group[0].address
            if query:
                if (query not in name.lower() and query not in address.lower()
                        and not (digits and digits in re.sub(r'\D', '', address))):
                    continue
            latest = max((m.timestamp for m in group if m.timestamp is not None),
                         default=None)
            recent = (datetime.fromtimestamp(latest / 1000).strftime('%Y-%m-%d')
                      if latest is not None else 'Unreadable')
            self.tree.insert('', 'end', iid=str(index),
                             text=f'{name + " — " if name else ""}{address}',
                             values=(len(group), recent))
        still_there = [item for item in keep if self.tree.exists(item)]
        if still_there:
            self.tree.selection_set(still_there)

    def apply_preset(self, kind):
        """v1.7 (Grok upgrade): the quick date ranges. They write
        the From/Through boxes, so what is on screen is always the
        range actually in force; with a conversation picked, the
        preview refreshes at once."""
        today = date.today()
        if kind == '7':
            start, end = today - timedelta(days=6), today
        elif kind == '30':
            start, end = today - timedelta(days=29), today
        elif kind == 'month':
            start, end = today.replace(day=1), today
        else:
            start = end = None
        self.start.set(start.isoformat() if start else '')
        self.end.set(end.isoformat() if end else '')
        if self.tree.selection():
            self.preview()

    def print_all(self):
        """v1.7 (Grok+Gemini upgrade): select every conversation in
        the list and preview the combined document — Print, Save
        PDF and Save TXT then cover them all."""
        children = self.tree.get_children()
        if not children:
            return
        self.tree.selection_set(children)
        self.preview()

    def close(self):
        self._save_geometry()
        self.closing = True
        self.cancelled.set()
        self.busy(True)
        self.invalidate()
        self.messages.clear()
        self.groups.clear()
        self.status.set('Closing and clearing working data…')
        if not self.worker or not self.worker.is_alive():
            self.finish_close()
        # poll waits for bounded ADB subprocesses before destroying the process.

    def finish_close(self):
        while not self.results.empty():
            self.results.get_nowait()
        while not self.update_results.empty():
            self.update_results.get_nowait()
        if not self.update_installing:
            for download in self.update_path.parent.glob('PrintMyTexts-PC-v*.download'):
                download.unlink(missing_ok=True)
        if self.engine:
            self.engine.close()
        self.work.close()
        self.root.destroy()


def main():
    import tkinter as tk
    ensure_stable_alias()
    root = tk.Tk()
    PrintMyTextsApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
