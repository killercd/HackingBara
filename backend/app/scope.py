import ipaddress
import re
import socket
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


class ScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    targets: list[str] = Field(default_factory=list, max_length=256)
    ports: str = ""
    urls: list[str] = Field(default_factory=list, max_length=256)
    credential_ids: list[str] = Field(default_factory=list, max_length=10)
    password_spray: bool = False
    credential_endpoints: list[str] = Field(default_factory=list, max_length=10)
    screenshots: bool = False
    timeout: int = Field(default=120, ge=5, le=600)

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
