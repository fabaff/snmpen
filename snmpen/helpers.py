"""Helper functions for SNMPen."""

import argparse
import ipaddress
import re
import tomllib
from pathlib import Path


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


def load_project_metadata():
    """Load project metadata from pyproject.toml."""
    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    try:
        with pyproject_path.open("rb") as pyproject_file:
            data = tomllib.load(pyproject_file)
    except OSError as exc:
        raise RuntimeError(f"Unable to read {pyproject_path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"Invalid TOML in {pyproject_path}: {exc}") from exc

    project = data.get("project", {})
    if not isinstance(project, dict):
        raise RuntimeError("Missing [project] section in pyproject.toml")

    tool_snmpen = data.get("tool", {}).get("snmpen", {})

    name = project.get("name")
    version = project.get("version")
    description = project.get("description")
    if not name or not version or not description:
        raise RuntimeError(
            "pyproject.toml [project] must define name, version, and description"
        )

    authors = project.get("authors") or []
    first_author_entry = (
        authors[0] if authors and isinstance(authors[0], dict) else None
    )
    first_author = first_author_entry.get("name") if first_author_entry else None
    first_author_email = first_author_entry.get("email") if first_author_entry else None
    if not first_author:
        raise RuntimeError(
            "pyproject.toml [project].authors must include at least one author name"
        )

    author_display = first_author
    if first_author_email:
        author_display = f"{first_author} <{first_author_email}>"

    return {
        "name": name,
        "version": version,
        "description": description,
        "copyright": tool_snmpen.get("copyright", ""),
        "author": author_display,
    }


def target_to_output_filename(target):
    """Create a safe output filename from a target name."""
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target).strip("._")
    if not safe_target:
        safe_target = "snmp-target"
    return f"{safe_target}.txt"
