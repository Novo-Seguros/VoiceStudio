"""SIP messages (RFC 3261 §7): parse, build, and frame them on a stream.

Only what an outbound user agent needs. Header names are case-insensitive and
compact forms (``v``, ``f``, ``t``…) are expanded on parse, so lookups always
use the long names.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

_COMPACT = {
    "v": "Via",
    "f": "From",
    "t": "To",
    "i": "Call-ID",
    "m": "Contact",
    "l": "Content-Length",
    "c": "Content-Type",
    "k": "Supported",
    "s": "Subject",
    "e": "Content-Encoding",
}
#: Headers whose comma-separated values are separate entries (RFC 3261 §7.3.1).
_LIST_HEADERS = {"via", "route", "record-route", "contact", "allow", "supported"}
_STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d{3})\s*(.*)$")
_REQUEST_RE = re.compile(r"^([A-Z]+)\s+(\S+)\s+SIP/2\.0$")
#: Generous for signalling; anything bigger is not a call we placed.
MAX_MESSAGE_BYTES = 64 * 1024


class SipParseError(ValueError):
    pass


@dataclass
class SipMessage:
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    method: str = ""  # requests
    uri: str = ""
    status: int = 0  # responses
    reason: str = ""

    @property
    def is_request(self) -> bool:
        return bool(self.method)

    def get(self, name: str, default: str = "") -> str:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        values = []
        for key, value in self.headers:
            if key.lower() == name:
                values.extend(split_list(value) if name in _LIST_HEADERS else [value])
        return values

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self.headers.append((name, value))

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self.headers = [(k, v) for k, v in self.headers if k.lower() != lowered]

    @property
    def cseq(self) -> tuple[int, str]:
        parts = self.get("CSeq").split()
        try:
            return int(parts[0]), parts[1].upper() if len(parts) > 1 else ""
        except (IndexError, ValueError):
            return 0, ""

    def to_bytes(self) -> bytes:
        start = f"{self.method} {self.uri} SIP/2.0" if self.is_request else f"SIP/2.0 {self.status} {self.reason}"
        lines = [start]
        lines += [f"{k}: {v}" for k, v in self.headers if k.lower() != "content-length"]
        lines.append(f"Content-Length: {len(self.body)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + self.body


def split_list(value: str) -> list[str]:
    """Split a comma-separated header value, ignoring commas inside quotes
    and ``<…>`` (a display name or URI parameter may contain one)."""
    parts, current, quoted, angle = [], [], False, False
    for ch in value:
        if ch == '"':
            quoted = not quoted
        elif ch == "<" and not quoted:
            angle = True
        elif ch == ">" and not quoted:
            angle = False
        if ch == "," and not quoted and not angle:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def parse(data: bytes) -> SipMessage:
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SipParseError("headers are not UTF-8") from exc
    lines = text.replace("\r\n", "\n").split("\n")
    start = lines[0].strip()
    msg = SipMessage()
    status = _STATUS_RE.match(start)
    request = _REQUEST_RE.match(start)
    if status:
        msg.status, msg.reason = int(status.group(1)), status.group(2).strip()
    elif request:
        msg.method, msg.uri = request.group(1), request.group(2)
    else:
        raise SipParseError("not a SIP message")
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and msg.headers:  # folded continuation
            key, value = msg.headers[-1]
            msg.headers[-1] = (key, f"{value} {line.strip()}")
            continue
        key, colon, value = line.partition(":")
        if not colon:
            raise SipParseError("malformed header line")
        key = key.strip()
        msg.headers.append((_COMPACT.get(key.lower(), key) if len(key) == 1 else key, value.strip()))
    length = msg.get("Content-Length")
    msg.body = body[: int(length)] if length.isdigit() else body
    return msg


class StreamFramer:
    """Cut a byte stream (SIP over TCP) into messages by ``Content-Length``.

    Bare CRLFs between messages are keep-alives (RFC 5626 §3.5.1) and are
    skipped.
    """

    def __init__(self) -> None:
        self._buf = b""

    def feed(self, data: bytes) -> list[SipMessage]:
        self._buf += data
        out = []
        while True:
            self._buf = self._buf.lstrip(b"\r\n")
            end = self._buf.find(b"\r\n\r\n")
            if end < 0:
                if len(self._buf) > MAX_MESSAGE_BYTES:
                    raise SipParseError("message too large")
                return out
            head = self._buf[:end]
            match = re.search(rb"(?im)^(?:content-length|l)[ \t]*:[ \t]*(\d+)", head)
            length = int(match.group(1)) if match else 0
            if length > MAX_MESSAGE_BYTES:
                raise SipParseError("message too large")
            total = end + 4 + length
            if len(self._buf) < total:
                return out
            out.append(parse(self._buf[:total]))
            self._buf = self._buf[total:]


def header_param(value: str, name: str) -> str | None:
    """``<sip:a@b>;tag=xyz`` → ``xyz`` for ``tag`` (parameters after the URI)."""
    tail = value.rsplit(">", 1)[-1] if ">" in value else value
    for part in tail.split(";")[1:]:
        key, _, val = part.partition("=")
        if key.strip().lower() == name.lower():
            return val.strip().strip('"')
    return None


def name_addr_uri(value: str) -> str:
    """The URI inside a name-addr (``"Bob" <sip:bob@x>;tag=1`` → ``sip:bob@x``)."""
    if "<" in value and ">" in value:
        return value[value.index("<") + 1 : value.index(">")].strip()
    return value.split(";", 1)[0].strip()


def new_tag() -> str:
    return secrets.token_hex(6)


def new_branch() -> str:
    # The magic cookie marks an RFC 3261 branch (§8.1.1.7).
    return "z9hG4bK" + secrets.token_hex(10)


def new_call_id(host: str) -> str:
    return f"{secrets.token_hex(12)}@{host}"


def response_to(request: SipMessage, status: int, reason: str, *, to_tag: str = "") -> SipMessage:
    """A response that echoes the request's transaction headers (§8.2.6.2)."""
    resp = SipMessage(status=status, reason=reason)
    for value in request.get_all("Via"):
        resp.headers.append(("Via", value))
    to = request.get("To")
    if to_tag and header_param(to, "tag") is None:
        to = f"{to};tag={to_tag}"
    resp.headers += [
        ("From", request.get("From")),
        ("To", to),
        ("Call-ID", request.get("Call-ID")),
        ("CSeq", request.get("CSeq")),
    ]
    return resp
