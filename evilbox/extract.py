"""Pull analyst-oriented indicators from deobfuscated (and original) source."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

# hxxp / http(s) / ftp, optional defanging
URL_RE = re.compile(
    r"(?i)\b((?:h(?:xx|tt)ps?|f(?:xx|t)p)://[^\s\"'<>\\]+)",
)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b"
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,24}\b", re.I)
WIN_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\/:*?\"<>|\s]+\\)*[^\\/:*?\"<>|\s]+")
UNC_PATH_RE = re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\s\"']+")
REG_RE = re.compile(r"(?i)\b(?:HKEY_[A-Z_]+|HK[CLU][UM])\\[^\s\"']+")
HOST_IN_QUOTES_RE = re.compile(
    r"[\"']((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})[\"']"
)
FILENAME_RE = re.compile(
    r"(?i)\b([A-Za-z0-9._\-]+\.(?:exe|dll|scr|bat|cmd|com|ps1|vbs|vbe|js|jse|wsf|wsh|hta|msi|jar|php|asp|aspx))\b"
)

FILE_TLDS = {
    "exe",
    "dll",
    "scr",
    "bat",
    "cmd",
    "com",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "msi",
    "jar",
    "php",
    "asp",
    "aspx",
    "png",
    "jpg",
    "gif",
    "css",
    "map",
}

NOISE_HOSTS = {
    "www.w3.org",
    "schema.org",
    "example.com",
    "example.org",
    "localhost",
}

# COM/OLE ProgIDs look like hostnames; do not report them as domains.
PROGID_SUFFIXES = {
    "shell",
    "xmlhttp",
    "stream",
    "filesystemobject",
    "application",
    "object",
    "file",
    "dictionary",
}

API_PATTERNS = (
    ("WScript.Shell", re.compile(r"WScript\.Shell", re.I)),
    ("WScript", re.compile(r"\bWScript\b")),
    ("ActiveXObject", re.compile(r"ActiveXObject")),
    ("MSXML2.XMLHTTP", re.compile(r"MSXML2\.XMLHTTP", re.I)),
    ("XMLHTTP", re.compile(r"XMLHTTP", re.I)),
    ("ADODB.Stream", re.compile(r"ADODB\.Stream", re.I)),
    ("Scripting.FileSystemObject", re.compile(r"Scripting\.FileSystemObject", re.I)),
    ("Shell.Application", re.compile(r"Shell\.Application", re.I)),
    ("cmd.exe", re.compile(r"cmd\.exe", re.I)),
    ("powershell", re.compile(r"\bpowershell(?:\.exe)?\b", re.I)),
    ("bitsadmin", re.compile(r"\bbitsadmin\b", re.I)),
    ("certutil", re.compile(r"\bcertutil\b", re.I)),
    ("mshta", re.compile(r"\bmshta(?:\.exe)?\b", re.I)),
    ("rundll32", re.compile(r"\brundll32(?:\.exe)?\b", re.I)),
    ("regsvr32", re.compile(r"\bregsvr32(?:\.exe)?\b", re.I)),
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ("fromCharCode", re.compile(r"fromCharCode")),
    ("base64_decode", re.compile(r"base64_decode\s*\(")),
    ("gzinflate", re.compile(r"gzinflate\s*\(")),
    ("ShellExecute", re.compile(r"ShellExecute", re.I)),
    ("CreateObject", re.compile(r"CreateObject", re.I)),
)


@dataclass
class Indicators:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    registry: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return asdict(self)

    def is_empty(self) -> bool:
        return not any(getattr(self, name) for name in self.__dataclass_fields__)


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip()
        if not key:
            continue
        folded = key.lower()
        if folded in seen:
            continue
        seen.add(folded)
        out.append(key)
    return out


def _refang_url(url: str) -> str:
    url = url.rstrip(").,;]")
    lower = url.lower()
    if lower.startswith("hxxps://"):
        return "https://" + url[8:]
    if lower.startswith("hxxp://"):
        return "http://" + url[7:]
    if lower.startswith("fxp://"):
        return "ftp://" + url[6:]
    return url


def _host_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in NOISE_HOSTS:
        return None
    if host.count(".") == 0:
        return None
    return host


def _is_domain(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in NOISE_HOSTS or not host or " " in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    if tld in FILE_TLDS or tld.isdigit() or tld in PROGID_SUFFIXES:
        return False
    if len(tld) < 2 or not tld.isalpha():
        return False
    if re.fullmatch(r"[0-9a-f]{8,}", host.replace(".", "")):
        return False
    return True


def extract_indicators(*texts: str, extra_domains: list[str] | None = None) -> Indicators:
    blob = "\n".join(t for t in texts if t)
    urls = [_refang_url(m) for m in URL_RE.findall(blob)]
    urls = [u for u in urls if "://" in u]

    domains: list[str] = []
    for url in urls:
        host = _host_from_url(url)
        if host and _is_domain(host):
            domains.append(host)
    for match in HOST_IN_QUOTES_RE.findall(blob):
        if _is_domain(match):
            domains.append(match.lower())
    if extra_domains:
        for host in extra_domains:
            host = host.lower().rstrip(".")
            if _is_domain(host) or (host.count(".") >= 1 and host not in NOISE_HOSTS):
                if re.fullmatch(r"[0-9a-f]{8,12}", host):
                    continue
                domains.append(host)

    files = [m for m in FILENAME_RE.findall(blob)]
    paths = WIN_PATH_RE.findall(blob) + UNC_PATH_RE.findall(blob)
    apis = [label for label, pattern in API_PATTERNS if pattern.search(blob)]

    return Indicators(
        urls=_unique(urls),
        domains=_unique(domains),
        ipv4=_unique(IPV4_RE.findall(blob)),
        emails=_unique(EMAIL_RE.findall(blob)),
        files=_unique(files),
        paths=_unique(paths),
        registry=_unique(REG_RE.findall(blob)),
        apis=apis,
    )


def locate_indicators(layers: list[tuple[str, str]], extra_domains: list[str] | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for name, text in layers:
        iocs = extract_indicators(text, extra_domains=extra_domains if name in {"inner", "sandbox"} else None)
        for kind, values in iocs.to_dict().items():
            for value in values:
                key = (kind, value.lower(), name)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({"kind": kind, "value": value, "layer": name})
    return rows


def format_indicators(iocs: Indicators) -> str:
    if iocs.is_empty():
        return "indicators: (none)\n"
    lines = ["indicators:"]
    for key, values in iocs.to_dict().items():
        if not values:
            continue
        lines.append(f"  {key}:")
        for value in values:
            lines.append(f"    {value}")
    return "\n".join(lines) + "\n"
