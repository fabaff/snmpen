"""Utility functions for various tasks."""

import ipaddress
import re
import socket
from datetime import timedelta

import humanize


def truncate_to_twidth(string, twidth):
    """Truncate a string to a specified width."""
    return str(string)[: twidth - 1]


def number_to_human_size(size_value, unit_value):
    """Convert a size value and unit to a human-readable format."""
    try:
        size = int(str(size_value)) * int(str(unit_value))
    except (TypeError, ValueError):
        return str(size_value)
    return humanize.naturalsize(size, binary=True, format="%.2f")


def value_to_string(value):
    """Convert a value to a string, handling None values."""
    if value is None:
        return ""
    return str(value)


def _pluralize(value, unit):
    """Return a pluralized string for a value and unit."""
    return f"{value} {unit}" if value == 1 else f"{value} {unit}s"


def timeticks_to_seconds(value):
    """Convert SNMP timeticks (1/100 sec) to whole seconds."""
    string = value_to_string(value).strip()
    if not string or is_null(value) or "Null" in string:
        return None

    match = re.search(r"\((\d+)\)", string)
    if match:
        ticks = int(match.group(1))
    elif string.isdigit():
        ticks = int(string)
    else:
        return None

    return ticks / 100


def timeticks_to_dhm(value):
    """Convert SNMP timeticks (1/100 sec) to 'days hours minutes seconds'."""
    total_seconds = timeticks_to_seconds(value)
    if total_seconds is None:
        return "-"

    td = timedelta(seconds=total_seconds)
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(_pluralize(days, "day"))
    if days > 0 or hours > 0:
        parts.append(_pluralize(hours, "hour"))
    parts.append(_pluralize(minutes, "minute"))
    parts.append(_pluralize(seconds, "second"))
    return " ".join(parts)


def is_null(value):
    """Check if a value is considered null or indicates no such instance/object."""
    if value is None:
        return True
    s = str(value)
    return any(x in s for x in ("noSuchInstance", "noSuchObject", "endOfMibView"))


def get_mac_string(raw_value):
    """Convert a raw value to a MAC address string."""
    try:
        mac_bytes = bytes(raw_value)
        return ":".join(f"{b:02x}" for b in mac_bytes[:6])
    except Exception:
        return value_to_string(raw_value)


def extract_job_attr(value):
    """Extract a job attribute from a value."""
    string = value_to_string(value)
    if is_null(value):
        return "-"
    match = re.match(r"^JobAcct\d+=(.*)", string)
    if match:
        result = match.group(1)
        return result if result else "-"
    return "-"


def get_ip_string(raw_value):
    """Convert a raw binary value to an IP address string (dotted decimal)."""
    try:
        ip_bytes = bytes(raw_value)
        if len(ip_bytes) == 4:
            return ".".join(str(b) for b in ip_bytes)
        return value_to_string(raw_value)
    except Exception:
        return value_to_string(raw_value)


def format_endpoint(target, port):
    """Format an IP endpoint, adding brackets for IPv6 addresses."""
    return f"[{target}]:{port}" if ":" in target else f"{target}:{port}"


def resolve_target_addresses(target, port):
    """Resolve an IP literal or hostname into a list of addresses."""
    try:
        ip = ipaddress.ip_address(target)
        return [(str(ip), ip.version)]
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(
            target,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target '{target}'") from exc

    targets = []
    seen = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        for current_family, _, _, _, sockaddr in addr_info:
            if current_family != family:
                continue
            version = 4 if current_family == socket.AF_INET else 6
            addr = sockaddr[0]
            key = (addr, version)
            if key in seen:
                continue
            seen.add(key)
            targets.append(key)

    if targets:
        return targets

    raise ValueError(f"No IPv4/IPv6 address found for target '{target}'")
