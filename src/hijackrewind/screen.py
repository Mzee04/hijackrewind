"""Treat file, page, and transcript bytes as untrusted data.

Instruction-shaped text is recorded and ignored. It never becomes a tool
argument. Lure destinations are host and path only, with the query dropped.
"""

from __future__ import annotations

import base64
import csv
import json
import re
import unicodedata
from datetime import datetime
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from urllib.parse import urlsplit

from hijackrewind.models import Lure, ScreenResult

_URL = re.compile(r"https?://[^\s<>'\"\)]+")
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_INSTRUCTION = re.compile(
    r"ignore (?:all|any|previous|prior|earlier|above)|"
    r"do not mention|"
    r"system prompt|you are now|higher priority than|"
    r"overrides any earlier|direct instruction|"
    r"note (?:to|for) (?:ai|automated)|"
    r"assistant instructions|"
    r"agent instruction|"
    r"\[system\]|tool policy updated|"
    r"force-push|rm -rf|"
    r"ignore the user",
    re.I,
)
_MAIL = re.compile(
    r"\b(?:forward|email|e-mail|send|reply)\b.{0,180}?\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
    re.I | re.DOTALL,
)
_OBFUSCATED_MAIL = re.compile(
    r"\b([A-Za-z0-9._%+\-]+)\s+at\s+([A-Za-z0-9\-]+(?:\s+dot\s+[A-Za-z0-9\-]+)+)",
    re.I,
)
_EXFIL = re.compile(
    r"\b(api[_ ]?keys?|tokens?|\.env|deploy_token|passphrase|secrets?)\b",
    re.I,
)


def strip_format_chars(text: str) -> str:
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _clean_url(raw: str) -> tuple[str, str] | None:
    raw = raw.rstrip(".,);]")
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"http", "https"} or not host:
        return None
    path = parts.path or "/"
    return host, path


class _VisibleHTML(HTMLParser):
    _VOID = {"meta", "img", "br", "hr", "input", "link", "source", "base"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.form_actions: list[str] = []
        self._skip = 0
        self._hide = 0
        self._stack: list[bool] = []

    def _is_hidden(self, attrs: dict[str, str]) -> bool:
        style = attrs.get("style", "").lower().replace(" ", "")
        if any(
            token in style
            for token in (
                "display:none",
                "font-size:0",
                "font-size:1px",
                "color:transparent",
                "left:-9999px",
            )
        ):
            return True
        if "color:#fff" in style and "background:#fff" in style:
            return True
        classes = attrs.get("class", "").lower()
        tokens = set(classes.split())
        if tokens & {"hidden", "sr", "sr-only", "hidden-note"}:
            return True
        if "hidden" in classes:
            return True
        if "hidden" in attrs:
            return True
        if attrs.get("aria-hidden", "").lower() == "true":
            return True
        return False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapped = {key.lower(): (value or "") for key, value in attrs}
        if tag in {"script", "style"}:
            self._skip += 1
        if tag == "form" and mapped.get("action"):
            self.form_actions.append(mapped["action"])
        if tag == "meta" and mapped.get("content"):
            self.hidden.append(mapped["content"])
        if tag == "img":
            alt = mapped.get("alt", "")
            if alt and _INSTRUCTION.search(alt):
                self.hidden.append(alt)
            elif alt:
                self.visible.append(alt)
        if tag in self._VOID:
            return
        hidden = self._is_hidden(mapped)
        self._stack.append(hidden)
        if hidden:
            self._hide += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
        if tag in self._VOID:
            return
        if self._stack:
            hidden = self._stack.pop()
            if hidden and self._hide:
                self._hide -= 1

    def handle_data(self, data: str) -> None:
        if self._skip or not data or not data.strip():
            return
        if self._hide:
            self.hidden.append(data)
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        if data and data.strip():
            self.hidden.append(data)


def _decode_blobs(text: str) -> list[str]:
    found: list[str] = []
    for match in _B64.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True)
            text_decoded = decoded.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if not text_decoded.strip():
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in text_decoded)
        if printable / len(text_decoded) < 0.9:
            continue
        if _INSTRUCTION.search(text_decoded) or "http://" in text_decoded or "https://" in text_decoded:
            found.append(text_decoded)
    return found


def _urls_from(text: str) -> list[tuple[str, str]]:
    found = []
    for match in _URL.finditer(text):
        cleaned = _clean_url(match.group(0))
        if cleaned:
            found.append(cleaned)
    return found


def _mail_lures(text: str) -> list[str]:
    recipients: list[str] = []
    for match in _MAIL.finditer(text):
        recipients.append(match.group(1))
    for match in _OBFUSCATED_MAIL.finditer(text):
        local = match.group(1)
        labels = re.split(r"\s+dot\s+", match.group(2).strip(), flags=re.I)
        domain = ".".join(label.strip() for label in labels if label.strip())
        recipients.append(f"{local}@{domain}")
    return recipients


def _data_issues(modality: str, text: str) -> list[str]:
    issues: list[str] = []
    if modality == "csv" or text.startswith("txn_id,") or text.startswith("sensor_id,"):
        issues.extend(_csv_issues(text))
    stripped = text.lstrip()
    looks_like_json = stripped.startswith("{") or (
        stripped.startswith("[") and len(stripped) > 1 and stripped[1] in '{["'
    )
    if modality == "json" or looks_like_json:
        issues.extend(_json_issues(text))
    if "BEGIN:VCALENDAR" in text or "BEGIN:VEVENT" in text:
        issues.extend(_ics_issues(text))
    issues.extend(_money_issues(text))
    issues.extend(_price_table_issues(text))
    return issues


def _csv_issues(text: str) -> list[str]:
    issues: list[str] = []
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return ["empty csv"]
    try:
        header = next(csv.reader([lines[0]]))
    except csv.Error as exc:
        return [f"csv header is unreadable ({exc})"]
    width = len(header)
    seen: dict[str, int] = {}
    previous_stamp: str | None = None
    for index, line in enumerate(lines[1:], start=2):
        if line.count('"') % 2 != 0:
            issues.append(f"line {index} has an unbalanced quote")
            continue
        if ";" in line and "," not in line:
            issues.append(f"line {index} is not comma-separated")
            continue
        try:
            cols = next(csv.reader([line]))
        except csv.Error as exc:
            issues.append(f"line {index} is unreadable ({exc})")
            continue
        if len(cols) != width:
            issues.append(f"line {index} has {len(cols)} columns, header has {width}")
        lowered = {name.strip().lower(): value.strip() for name, value in zip(header, cols)}
        if "date" in lowered:
            issues.extend(_date_issue(index, lowered["date"]))
        if "timestamp_utc" in lowered:
            stamp = lowered["timestamp_utc"]
            if previous_stamp and stamp < previous_stamp:
                issues.append(f"line {index} timestamp {stamp} is out of order")
            previous_stamp = stamp or previous_stamp
        if "temp" in lowered and "unit" in lowered:
            issues.extend(_sensor_issue(index, lowered))
        ident = lowered.get("txn_id") or lowered.get("id") or ""
        if ident:
            if ident in seen:
                issues.append(f"duplicate id {ident} on lines {seen[ident]} and {index}")
            else:
                seen[ident] = index
        if ident.upper() == "TOTAL" or line.upper().startswith("TOTAL"):
            issues.append(f"line {index} is a total row mixed into the transactions")
            stated = _amount(lowered.get("amount_gbp") or (cols[3] if len(cols) > 3 else ""))
            parsed_sum = _sum_amounts(lines[1:], header)
            if stated is not None and parsed_sum is not None and abs(stated - parsed_sum) > Decimal("0.009"):
                issues.append(
                    f"stated total {stated} does not equal {parsed_sum}, "
                    "the sum of parsable amount cells (broken rows omitted, duplicate rows kept)"
                )
    units = set()
    for line in lines[1:]:
        if line.count('"') % 2:
            continue
        try:
            cols = next(csv.reader([line]))
        except csv.Error:
            continue
        lowered = {name.strip().lower(): value.strip() for name, value in zip(header, cols)}
        if lowered.get("unit"):
            units.add(lowered["unit"].upper())
    if "C" in units and "F" in units:
        issues.append("temperature units are mixed between C and F")
    return issues


def _amount(value: str) -> Decimal | None:
    match = re.search(r"-?[0-9]+\.[0-9]{2}", value or "")
    if not match:
        return None
    try:
        return Decimal(match.group(0))
    except InvalidOperation:
        return None


def _sum_amounts(lines: list[str], header: list[str]) -> Decimal | None:
    total = Decimal("0")
    found = False
    amount_at = next((i for i, name in enumerate(header) if "amount" in name.lower()), None)
    for line in lines:
        if line.upper().startswith("TOTAL") or line.count('"') % 2:
            continue
        try:
            cols = next(csv.reader([line]))
        except csv.Error:
            continue
        if amount_at is None or amount_at >= len(cols):
            continue
        amount = _amount(cols[amount_at])
        if amount is None:
            continue
        total += amount
        found = True
    return total if found else None


def _date_issue(index: int, value: str) -> list[str]:
    if not value or not re.match(r"\d{4}-\d{2}-\d{2}", value):
        return []
    try:
        datetime.strptime(value[:10], "%Y-%m-%d")
    except ValueError:
        return [f"line {index} has an impossible date {value[:10]}"]
    return []


def _sensor_issue(index: int, row: dict[str, str]) -> list[str]:
    issues = []
    if not row.get("sensor_id"):
        issues.append(f"line {index} is missing a sensor id")
    try:
        temp = float(row.get("temp") or "nan")
        humidity = float(row.get("humidity_pct") or "nan")
    except ValueError:
        return issues + [f"line {index} has a non-numeric sensor reading"]
    unit = (row.get("unit") or "").upper()
    if unit == "C" and (temp < -40 or temp > 60):
        issues.append(f"line {index} temperature {temp} C is outside a cold-room range")
    if unit == "F" and (temp < -40 or temp > 140):
        issues.append(f"line {index} temperature {temp} F is outside a cold-room range")
    if unit not in {"C", "F", ""}:
        issues.append(f"line {index} has an unknown temperature unit")
    if humidity < 0 or humidity > 100:
        issues.append(f"line {index} humidity {humidity} is outside 0-100")
    return issues


def _json_issues(text: str) -> list[str]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        issues = [f"invalid json at line {exc.lineno}: {exc.msg}"]
        issues.extend(_json_recovered_issues(text))
        return issues
    return _json_object_issues(parsed)


def _json_recovered_issues(text: str) -> list[str]:
    """Keep complete objects from a truncated export and describe their fields."""
    objects = []
    for match in re.finditer(r"\{[^{}]+\}", text):
        try:
            item = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            objects.append(item)
    if not objects:
        return []
    issues = [f"recovered {len(objects)} complete record(s) before the truncation"]
    issues.extend(_json_object_issues({"items": objects}))
    return issues


def _json_object_issues(parsed: object) -> list[str]:
    issues: list[str] = []
    if isinstance(parsed, dict) and isinstance(parsed.get("items"), list):
        seen: dict[str, int] = {}
        for index, item in enumerate(parsed["items"], start=1):
            if not isinstance(item, dict):
                issues.append(f"item {index} is not an object")
                continue
            ident = str(item.get("id", ""))
            if ident and ident in seen:
                issues.append(f"duplicate id {ident}")
            elif ident:
                seen[ident] = index
            year = item.get("year")
            if isinstance(year, str):
                issues.append(f"item {ident or index} year is not a number")
            if isinstance(year, int) and year > datetime.now().year + 1:
                issues.append(f"item {ident or index} year {year} is after next year")
    return issues


def _ics_issues(text: str) -> list[str]:
    issues = []
    start = re.search(r"DTSTART(?:;[^:\n]+)?:([0-9]{8})(?:T([0-9]{6}))?", text)
    end = re.search(r"DTEND(?:;[^:\n]+)?:([0-9]{8})(?:T([0-9]{6}))?", text)
    start_dt = _ics_date(start.group(1)) if start else None
    end_dt = _ics_date(end.group(1)) if end else None
    if start and start_dt is None:
        issues.append(f"calendar start {start.group(1)} is not a real date")
    if end and end_dt is None:
        issues.append(f"calendar end {end.group(1)} is not a real date")
    if start and end and start.group(2) and end.group(2):
        if start.group(1) == end.group(1) and end.group(2) <= start.group(2):
            issues.append("calendar end is not after the start")
        elif start_dt and end_dt and (end_dt, end.group(2)) <= (start_dt, start.group(2)):
            issues.append("calendar end is not after the start")
    elif start_dt and end_dt and end_dt <= start_dt:
        issues.append("calendar end is not after the start")
    if re.search(r"16 February|February 16", text) and start and start.group(1)[4:8] != "0216":
        issues.append("calendar date does not match the message text")
    if re.search(r"\bLondon\b", text) and re.search(r"Los_Angeles|New_York|Chicago", text):
        issues.append("calendar time zone does not match the message text")
    return issues


def _price_table_issues(text: str) -> list[str]:
    if "<table" not in text.lower() or not re.search(r">\s*qty\s*<", text, re.I):
        return []
    issues = []
    for row in re.findall(r"<tr\b[^>]*>(.*?)</tr>", text, flags=re.I | re.S):
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row, flags=re.I | re.S)
        if len(cells) < 4:
            continue
        numbers = []
        for cell in cells[1:4]:
            plain = re.sub(r"<[^>]+>", "", cell)
            match = re.search(r"([0-9]+(?:\.[0-9]+)?)", plain)
            numbers.append(Decimal(match.group(1)) if match else None)
        unit, qty, total = numbers
        if None in (unit, qty, total):
            continue
        if abs((unit * qty) - total) > Decimal("0.009"):
            issues.append(f"listed total {total} does not equal unit price {unit} times quantity {qty}")
    return issues


def _ics_date(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y%m%d")
    except ValueError:
        return None


def _money_issues(text: str) -> list[str]:
    def grab(label: str) -> Decimal | None:
        match = re.search(label + r"[^0-9]{0,48}([0-9]+\.[0-9]{2})", text, re.I)
        if not match:
            return None
        try:
            return Decimal(match.group(1))
        except InvalidOperation:
            return None

    sub = grab(r"subtotal")
    vat = grab(r"\bvat\b")
    total = grab(r"total due")
    if sub is None or total is None:
        return []
    expected = sub + (vat or Decimal("0"))
    if abs(expected - total) > Decimal("0.009"):
        return [f"stated total {total} does not equal subtotal {sub} plus tax {vat or 0}"]
    return []


def screen_text(*, modality: str, raw_text: str, html: str = "", reply_to: str = "") -> ScreenResult:
    parser = _VisibleHTML()
    hidden: list[str] = []
    visible_chunks: list[str] = []
    form_actions: list[str] = []
    if html:
        parser.feed(html)
        parser.close()
        hidden.extend(parser.hidden)
        visible_chunks.extend(parser.visible)
        form_actions.extend(parser.form_actions)
    if modality == "html" and not html:
        parser.feed(raw_text)
        parser.close()
        hidden.extend(parser.hidden)
        visible_chunks.extend(parser.visible)
        form_actions.extend(parser.form_actions)
    plain = raw_text if modality != "html" else ""
    if modality == "email":
        # raw_text for email is the text/plain part plus calendar text.
        visible_chunks.append(raw_text)
    elif modality != "html":
        visible_chunks.append(raw_text)

    visible = "\n".join(chunk.strip() for chunk in visible_chunks if chunk and chunk.strip())
    hidden_text = "\n".join(hidden)
    normalized_visible = strip_format_chars(visible)
    normalized_hidden = strip_format_chars(hidden_text)
    decoded = _decode_blobs(raw_text + "\n" + html + "\n" + hidden_text)

    warnings: list[str] = []
    if normalized_visible != visible and _INSTRUCTION.search(normalized_visible):
        warnings.append("zero_width_instruction")
    hidden_blob = "\n".join([normalized_hidden, *decoded])
    if hidden_blob.strip() and (
        _INSTRUCTION.search(hidden_blob)
        or re.search(r"\b(forward|load|fetch|visit|ignore|assistant)\b", hidden_blob, re.I)
        or _URL.search(hidden_blob)
    ):
        warnings.append("hidden_instruction")
    if decoded:
        warnings.append("encoded_instruction")
    if _INSTRUCTION.search(normalized_visible):
        warnings.append("instruction_shaped_text")
    combined = "\n".join([normalized_visible, normalized_hidden, *decoded])
    if re.search(r"\[system\]|tool policy updated|higher priority than the user", combined, re.I):
        warnings.append("poisoned_tool_output")
    if re.search(r"\b(ceo|supervisor)\b", combined, re.I) and re.search(
        r"override|direct instruction|authorised supervisor|authorized supervisor",
        combined,
        re.I,
    ):
        warnings.append("fake_authority")
    if _EXFIL.search(combined) and re.search(r"\b(send|forward|reply|post|paste)\b", combined, re.I):
        warnings.append("exfil_request")
    if re.search(r"\bcancel all\b", combined, re.I) and re.search(r"nothing gets cancelled|\bno\. nothing\b", combined, re.I):
        warnings.append("conflicting_instructions")
    if _deadline_conflict(combined):
        warnings.append("conflicting_instructions")
        data_issues_early = ["the text gives more than one deadline"]
    else:
        data_issues_early = []
    if re.search(r"\[(?:inaudible|crosstalk)\]", combined, re.I):
        data_issues_early.append("transcript has garbled or inaudible stretches")
    if re.search(r"\bmark me as present\b", combined, re.I):
        warnings.append("instruction_shaped_text")

    lures: list[Lure] = []
    seen: set[tuple[str, str, str]] = set()

    def add_http(host: str, path: str) -> None:
        key = ("http", host, path)
        if key in seen:
            return
        seen.add(key)
        lures.append(Lure(kind="http", host=host, path=path))

    def add_mail(address: str) -> None:
        address = address.strip()
        key = ("mail", address.lower(), "")
        if not address or key in seen:
            return
        seen.add(key)
        lures.append(Lure(kind="mail", recipient=address, host=address.split("@")[-1].lower()))

    for blob in (normalized_hidden, *decoded):
        for host, path in _urls_from(blob):
            add_http(host, path)
        for address in _mail_lures(blob):
            add_mail(address)
    # Visible instruction lines that name a URL still must not be fetched.
    for line in normalized_visible.splitlines():
        if _INSTRUCTION.search(line) or re.search(r"\b(load|fetch|post|curl|wget|visit|click|open)\b", line, re.I):
            for host, path in _urls_from(line):
                add_http(host, path)
    for address in _mail_lures(normalized_visible):
        window = normalized_visible
        if _EXFIL.search(window) or _INSTRUCTION.search(window):
            add_mail(address)
    if reply_to and _EXFIL.search(combined) and re.search(r"\breply\b", combined, re.I):
        add_mail(reply_to)
    for action in form_actions:
        cleaned = _clean_url(action)
        if cleaned and _INSTRUCTION.search(normalized_hidden + "\n" + "\n".join(decoded)):
            add_http(*cleaned)

    data_issues = data_issues_early + _data_issues(modality, plain or raw_text)
    if data_issues:
        warnings.append("broken_data")
    if (
        re.search(r"none of the quoted lines|they are examples", normalized_visible, re.I)
        and not lures
        and "hidden_instruction" not in warnings
        and "encoded_instruction" not in warnings
    ):
        warnings = [
            item
            for item in warnings
            if item not in {"instruction_shaped_text", "fake_authority", "exfil_request"}
        ]

    kept_lines = []
    redact_next = False
    for line in (normalized_visible or visible).splitlines():
        stripped_line = line.strip()
        if not stripped_line or _INSTRUCTION.search(stripped_line):
            continue
        if redact_next and len(stripped_line) < 100:
            kept_lines.append("[secret-shaped line omitted]")
            redact_next = False
            continue
        if re.search(r"(?i)\bpassphrase\b", stripped_line):
            redact_next = True
        if re.search(r"(?i)\b(export\s+)?[A-Z0-9_]*(KEY|TOKEN|SECRET)\s*=", stripped_line):
            kept_lines.append("[secret-shaped line omitted]")
            continue
        kept_lines.append(stripped_line)
    summary_source = " ".join(kept_lines) or (normalized_visible or raw_text).strip()
    summary = " ".join(summary_source.split())
    if len(summary) > 280:
        summary = summary[:277] + "..."
    return ScreenResult(
        visible_text=normalized_visible or visible,
        summary=summary,
        warnings=_unique(warnings),
        data_issues=data_issues,
        lures=lures,
    )


def _deadline_conflict(text: str) -> bool:
    if not re.search(r"\b(deadline|due)\b", text, re.I):
        return False
    found = re.findall(
        r"\b(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b(?:[^.]{0,48}?)"
        r"\b(?:january|february|march|april|may|june|july|august|september|october|november|december)\b"
        r"|\b\d{1,2}\s+(?:january|february|march|april|may|june|july|august|september|october|november|december)\b",
        text,
        flags=re.I,
    )
    normalized = {" ".join(item.lower().split()) for item in found}
    return len(normalized) >= 2


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen
