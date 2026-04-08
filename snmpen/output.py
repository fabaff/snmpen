"""Helpers for output formatting and display."""

from .utils import value_to_string

FIELDS_ORDER = [
    "Host IP address",
    "Supported SNMP versions",
    "Hostname",
    "Description",
    "Contact",
    "Location",
    "Uptime system",
    "Uptime snmp",
    "System date",
    "Domain",
    "Network information",
    "Network interfaces",
    "Network IP",
    "Routing information",
    "TCP connections and listening ports",
    "Listening UDP ports",
    "Processes",
    "Storage information",
    "File system information",
    "Device information",
    "Software components",
    "Network services",
    "Share",
    "IIS server information",
    "HP LaserJet printer enumeration",
    "Printer supplies",
    "Printer input trays",
    "Printer output trays",
    "Printer cover status",
    "Printer localization",
    "Printer reset",
    "Printer console display",
    "Printer infos",
    "Printer jobs",
    "User accounts",
]

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    Console = None
    Table = None


def _normalized_scalar(value):
    """Normalize scalar values for output rendering."""
    value_str = value_to_string(value).strip()
    if not value_str or "Null" in value_str or "noSuchInstance" in value_str:
        return "-"
    return value_str


def _collect_sections(output_data):
    """Split output data into summary fields and structured sections."""
    summary_rows = []
    structured_sections = []

    for key in FIELDS_ORDER:
        if key not in output_data:
            continue

        value = output_data[key]
        if isinstance(value, dict):
            structured_sections.append(("dict", key, value))
        elif isinstance(value, list):
            structured_sections.append(("list", key, value))
        else:
            summary_rows.append((key, _normalized_scalar(value)))

    return summary_rows, structured_sections


def _render_text_dict(title, data):
    """Render a dictionary section as plain text."""
    lines = [title]
    for key, value in data.items():
        lines.append(f"{str(key).strip()}: {_normalized_scalar(value)}")
    return "\n".join(lines)


def _render_text_list(title, items):
    """Render a list section as plain text."""
    lines = [title]
    if not items:
        lines.append("-")
        return "\n".join(lines)

    if all(isinstance(item, dict) for item in items):
        for index, item in enumerate(items, start=1):
            lines.append(f"[{index}]")
            for key, value in item.items():
                lines.append(f"{str(key).strip()}: {_normalized_scalar(value)}")
        return "\n".join(lines)

    if all(isinstance(item, list) for item in items):
        header = None
        rows = items
        if items and all(isinstance(cell, str) for cell in items[0]):
            header = items[0]
            rows = items[1:]

        if header:
            lines.append(" | ".join(str(name).strip() for name in header))
            lines.append("-" * len(lines[-1]))

        for row in rows:
            lines.append(" | ".join(_normalized_scalar(cell) for cell in row))

        return "\n".join(lines)

    for item in items:
        lines.append(_normalized_scalar(item))
    return "\n".join(lines)


def render_output_text(output_data):
    """Render output data as plain text."""
    summary_rows, structured_sections = _collect_sections(output_data)
    lines = ["System information"]

    for key, value in summary_rows:
        lines.append(f"{key}: {value}")

    for section_type, key, value in structured_sections:
        lines.append("")
        if section_type == "dict":
            lines.append(_render_text_dict(key, value))
        else:
            lines.append(_render_text_list(key, value))

    return "\n".join(lines)


def render_output_rich_text(output_data):
    """Render output data using Rich tables and return plain exported text."""
    if Console is None or Table is None:
        raise RuntimeError(
            "rich is required for rich-formatted output. Install it with: pip install rich"
        )

    record_console = Console(record=True, force_terminal=False, color_system=None)
    _render_output(record_console, output_data)
    return record_console.export_text()


def _render_rich_dict(console, title, data):
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Key", style="bold")
    table.add_column("Value", overflow="fold")
    for key, value in data.items():
        table.add_row(str(key).strip(), value_to_string(value).strip() or "-")
    console.print(table)


def _render_rich_list(console, title, items):
    if not items:
        return

    # List of dictionaries -> table with merged keys as columns
    if all(isinstance(item, dict) for item in items):
        columns = []
        for item in items:
            for key in item.keys():
                if key not in columns:
                    columns.append(key)

        table = Table(title=title, show_header=True, header_style="bold cyan")
        for col in columns:
            table.add_column(str(col).strip(), overflow="fold")

        for item in items:
            row = [
                value_to_string(item.get(col, "-")).strip() or "-" for col in columns
            ]
            table.add_row(*row)

        console.print(table)
        return

    # List of lists -> use first row as header if it looks like header text.
    if all(isinstance(item, list) for item in items):
        header = None
        rows = items
        if items and all(isinstance(cell, str) for cell in items[0]):
            header = items[0]
            rows = items[1:]

        col_count = (
            len(header) if header else max((len(row) for row in rows), default=1)
        )
        if col_count == 0:
            col_count = 1

        table = Table(title=title, show_header=True, header_style="bold cyan")
        if header:
            for idx in range(col_count):
                name = header[idx] if idx < len(header) else f"Col {idx + 1}"
                table.add_column(str(name).strip(), overflow="fold")
        else:
            for idx in range(col_count):
                table.add_column(f"Col {idx + 1}", overflow="fold")

        for row in rows:
            padded = [
                value_to_string(row[idx]).strip() if idx < len(row) else "-"
                for idx in range(col_count)
            ]
            table.add_row(*[(cell or "-") for cell in padded])

        console.print(table)
        return

    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Value", overflow="fold")
    for item in items:
        table.add_row(value_to_string(item).strip() or "-")
    console.print(table)


def print_output(output_data):
    """Print the formatted enumeration output to the console."""
    if Console is None or Table is None:
        print(
            "rich is required for formatted output. Install it with: pip install rich"
        )
        return

    console = Console()
    _render_output(console, output_data)


def _render_output(console, output_data):
    """Render output data using Rich tables to a given console."""
    summary = Table(
        title="System information", show_header=True, header_style="bold magenta"
    )
    summary.add_column("Field", style="bold")
    summary.add_column("Value", overflow="fold")

    summary_rows, structured_sections = _collect_sections(output_data)

    for key, value in summary_rows:
        summary.add_row(key, value)

    console.print(summary)

    for section_type, key, value in structured_sections:
        if section_type == "dict":
            _render_rich_dict(console, key, value)
        else:
            _render_rich_list(console, key, value)
