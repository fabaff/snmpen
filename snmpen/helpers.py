"""Helper functions for SNMPen."""

import argparse
import ipaddress
import re


def community_type(value):
    """Validate SNMP community string length."""
    if len(value) >= 32:
        raise argparse.ArgumentTypeError(
            "Community string must be shorter than 32 chars"
        )
    return value


def port_type(value):
    """Validate SNMP port range."""
    port = int(value)
    if not (0 <= port <= 65535):
        raise argparse.ArgumentTypeError("Port must be between 0 and 65535")
    return port


def retries_type(value):
    """Validate request retries range."""
    retries = int(value)
    if not (0 <= retries <= 10):
        raise argparse.ArgumentTypeError("Retries must be between 0 and 10")
    return retries


def target_type(value):
    """Validate that IP literals are well-formed while allowing hostnames."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if ":" in value:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}")

    labels = value.split(".")
    numeric_labels = sum(label.isdigit() for label in labels)
    if len(labels) == 4 and numeric_labels >= 3:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}")

    return value


def target_to_output_filename(target):
    """Create a safe output filename from a target name."""
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target).strip("._")
    if not safe_target:
        safe_target = "snmp-target"
    return f"{safe_target}.txt"
