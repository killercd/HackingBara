import ipaddress
import re
import socket
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .config import settings

DEFAULT_PORTS = "1-1024"


def ports(value: str) -> str:
    value = value.strip() or DEFAULT_PORTS
    found = set()
    for part in value.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(-[0-9]{1,5})?", part.strip()):
            raise ValueError("Ports must be numbers or inclusive ranges")
        bounds = [int(x) for x in part.strip().split("-")]
        low, high = bounds[0], bounds[-1]
        if not 1 <= low <= high <= 65535:
            raise ValueError("Ports must be between 1 and 65535")
        new = set(range(low, high + 1))
        if found & new:
            raise ValueError("Duplicate or overlapping ports")
        found |= new
        if len(found) > settings.max_ports:
            raise ValueError("Port count exceeds administrator limit")
    # Compact normalized contiguous ranges.
    ordered = sorted(found)
    groups = []
    low = last = ordered[0]
    for item in ordered[1:] + [65537]:
        if item == last + 1:
            last = item
            continue
        groups.append(str(low) if low == last else f"{low}-{last}")
        low = last = item
    return ",".join(groups)


def port_set(value):
    result = set()
    for part in ports(value).split(","):
        b = list(map(int, part.split("-")))
        result.update(range(b[0], b[-1] + 1))
    return result


def normalize_url(value: str) -> str:
    if len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Unsafe URL characters")
    u = urlsplit(value)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("Use an absolute HTTP(S) URL without credentials or fragments")
    hostname = u.hostname
    try:
        ip = ipaddress.ip_address(hostname)
        hostname = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        hostname = hostname.encode("idna").decode().lower().rstrip(".")
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
            raise ValueError("Invalid hostname")
        if any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in hostname.split(".")):
            raise ValueError("Invalid hostname")
    port = u.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid URL port")
    authority = hostname + (f":{port}" if port and port != (443 if u.scheme == "https" else 80) else "")
    return urlunsplit((u.scheme, authority, u.path or "/", u.query, ""))


def dns_name(value: str, *, dns_labels=False) -> str:
    value = value.strip().rstrip(".").encode("idna").decode().lower()
    allowed_name = r"(?=.{1,253}$)[a-z0-9_.-]+" if dns_labels else r"(?=.{1,253}$)[a-z0-9.-]+"
    if not re.fullmatch(allowed_name, value):
        raise ValueError("Invalid DNS name")
    label_pattern = r"[a-z0-9_-]{1,63}" if dns_labels else r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if any(not re.fullmatch(label_pattern, label) for label in value.split(".")):
        raise ValueError("Invalid DNS label")
    return value


class WordlistImport(BaseModel):
    skipped_invalid: int = Field(default=0, ge=0)
    skipped_comments: int = Field(default=0, ge=0)
    duplicates: int = Field(default=0, ge=0)
    examples: list[str] = Field(default_factory=list, max_length=5)


def import_wordlist(content: str, domain: str):
    """Keep valid candidates without letting one malformed row reject an entire file."""
    report = WordlistImport()
    words = {}
    domain = dns_name(domain)
    for number, line in enumerate(content.splitlines(), 1):
        value = line.strip().lstrip("\ufeff")
        if not value:
            continue
        if value.startswith(("#", ";", "//")):
            report.skipped_comments += 1
            continue
        try:
            value = dns_name(value, dns_labels=True)
            if value.endswith(f".{domain}"):
                value = value[: -(len(domain) + 1)]
            elif value == domain:
                raise ValueError("Base domain is not a subdomain")
            if len(f"{value}.{domain}") > 253:
                raise ValueError("Candidate exceeds the DNS name length limit")
        except ValueError as exc:
            report.skipped_invalid += 1
            if len(report.examples) < 5:
                report.examples.append(f"Line {number}: {line[:80]!r} — {exc}")
            continue
        if value in words:
            report.duplicates += 1
        words[value] = None
    return list(words), report


class ScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    mode: Literal["network", "subdomain"] = "network"
    domain: str = Field(default="", max_length=253)
    wordlist_filename: str = Field(default="", max_length=200)
    wordlist_import: WordlistImport | None = None
    subdomains: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list, max_length=256)
    ports: str = ""
    urls: list[str] = Field(default_factory=list, max_length=256)
    credential_ids: list[str] = Field(default_factory=list, max_length=10)
    password_spray: bool = False
    credential_endpoints: list[str] = Field(default_factory=list, max_length=10)
    screenshots: bool = False
    # Retained for old configurations; no longer used as a scanner deadline.
    timeout: int = Field(default=120, ge=5, le=600, exclude=True)
    request_timeout: float = Field(default=2, ge=0.001, le=300, allow_inf_nan=False)
    max_threads: int = Field(default=10, ge=1, le=1024)
    network_timing: int = Field(default=3, ge=0, le=5)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, value):
        if not value.strip():
            return ""
        value = dns_name(value)
        if "." not in value:
            raise ValueError("Provide a fully qualified base domain")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        raise ValueError("Provide a domain, not an IP address")

    @field_validator("subdomains")
    @classmethod
    def clean_subdomains(cls, values):
        result = {}
        for number, value in enumerate(values, 1):
            try:
                result[dns_name(value, dns_labels=True)] = None
            except ValueError:
                raise ValueError(
                    f"Invalid wordlist entry at line {number}: {value[:80]!r}. "
                    "Use relative names such as www or dev.api, without URLs or wildcards."
                ) from None
        return list(result)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value):
        if not value.strip():
            raise ValueError("Name cannot be blank")
        return value.strip()

    @field_validator("targets")
    @classmethod
    def clean_targets(cls, values):
        networks = []
        size = 0
        for value in values:
            net = ipaddress.ip_network(value.strip(), strict=True)
            if (
                net.is_multicast
                or net.is_unspecified
                or (net.version == 6 and net.network_address.ipv4_mapped)
            ):
                raise ValueError("Multicast, unspecified and IPv4-mapped IPv6 targets are unsupported")
            if any(net.version == old.version and net.overlaps(old) for old in networks):
                raise ValueError("Duplicate or overlapping targets")
            size += net.num_addresses
            if size > settings.max_targets:
                raise ValueError(f"Scope exceeds administrator limit of {settings.max_targets} addresses")
            networks.append(net)
        return [str(n) if n.num_addresses > 1 else str(n.network_address) for n in networks]

    @field_validator("ports")
    @classmethod
    def clean_ports(cls, value):
        return ports(value)

    @field_validator("urls", "credential_endpoints")
    @classmethod
    def clean_urls(cls, values):
        return list(dict.fromkeys(normalize_url(v.strip()) for v in values))

    @model_validator(mode="after")
    def check_options(self):
        # Validate defaults too, since validators normally skip default values.
        self.ports = ports(self.ports)
        if self.mode == "subdomain":
            if not self.domain or not self.subdomains:
                raise ValueError("Subdomain scans require a base domain and a subdomain wordlist")
            if any(len(f"{word}.{self.domain}") > 253 for word in self.subdomains):
                raise ValueError("Subdomain exceeds the DNS name length limit")
            if (
                self.targets
                or self.urls
                or self.credential_ids
                or self.password_spray
                or self.credential_endpoints
                or self.screenshots
            ):
                raise ValueError("Subdomain mode supports DNS enumeration only")
            return self
        if not self.targets and not self.urls:
            raise ValueError("Provide at least one IP/CIDR target or HTTP(S) URL")
        if len(set(self.credential_ids)) != len(self.credential_ids):
            raise ValueError("Duplicate credential references")
        if self.password_spray and (not self.credential_ids or not self.credential_endpoints):
            raise ValueError("Credential validation requires credentials and explicit endpoint approval")
        if any(url not in self.urls for url in self.credential_endpoints):
            raise ValueError("Approved credential endpoints must be explicit scan URLs")
        for url in self.urls:
            try:
                ipaddress.ip_address(urlsplit(url).hostname)
            except ValueError:
                continue  # DNS is checked at launch and before every connection.
            if self.targets:
                Scope(self.targets).resolve(url)
            else:
                self.clean_targets([urlsplit(url).hostname])
        return self


class Scope:
    def __init__(self, targets):
        self.networks = [ipaddress.ip_network(t) for t in targets]

    def allows(self, address):
        ip = ipaddress.ip_address(address)
        return not ip.is_multicast and not ip.is_unspecified and any(ip in n for n in self.networks)

    def addresses(self):
        # Include all addresses; this same conservative count is displayed in the UI.
        return [str(ip) for net in self.networks for ip in net]

    def resolve(self, url):
        addresses, port = resolve_url_addresses(url)
        if any(not self.allows(ip) for ip in addresses):
            raise ValueError("URL resolves outside the authorized scope")
        return addresses, port


def resolve_url_addresses(url):
    """Resolve only an explicitly provided URL; callers decide its approved scope."""
    u = urlsplit(normalize_url(url))
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        addresses = [str(ipaddress.ip_address(u.hostname))]
    except ValueError:
        addresses = sorted(
            {
                str(ipaddress.ip_address(r[4][0]))
                for r in socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
            }
        )
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, "URL has no resolved IP addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_multicast or ip.is_unspecified or (ip.version == 6 and (ip.ipv4_mapped or ip.scope_id)):
            raise ValueError("URL resolves to an unsupported IP address")
    return addresses, port


class ScopePreparationError(ValueError):
    def __init__(self, message, issues):
        super().__init__(message)
        self.issues = issues


def prepare_run_config(config: ScanInput, resolution_issues=None) -> ScanInput:
    """Freeze resolvable targets, report individual DNS failures, reject scope violations."""
    if config.mode == "subdomain":
        return config
    issues = resolution_issues if resolution_issues is not None else []
    scope = Scope(config.targets) if config.targets else None
    addresses = set()
    for url in config.urls:
        try:
            resolved, _ = scope.resolve(url) if scope else resolve_url_addresses(url)
        except (socket.gaierror, TimeoutError) as exc:
            temporary = isinstance(exc, TimeoutError) or exc.errno == socket.EAI_AGAIN
            issues.append(
                {
                    "url": url,
                    "code": "dns_resolution_failed",
                    "message": "DNS resolver temporarily unavailable; retry later"
                    if temporary
                    else "DNS resolution failed: no IP address is currently available",
                }
            )
            continue
        except ValueError as exc:
            raise ScopePreparationError(
                str(exc), [{"url": url, "code": "scope_rejected", "message": str(exc)}]
            ) from None
        addresses.update(resolved)
        if not scope and len(addresses) > settings.max_targets:
            raise ScopePreparationError(
                f"URL scope exceeds administrator limit of {settings.max_targets} addresses",
                [
                    {
                        "url": url,
                        "code": "target_limit",
                        "message": "Resolved IP count exceeds the target limit",
                    }
                ],
            )
    if scope:
        return config
    if not addresses:
        raise ScopePreparationError(
            "None of the supplied URLs could be resolved to an IP address. Check DNS records and try again.",
            issues,
        )
    return ScanInput.model_validate({**config.model_dump(), "targets": sorted(addresses)})
