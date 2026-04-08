"""Unit tests for snmpen.output."""

from snmpen.output import (
    _collect_sections,
    _normalized_scalar,
    _render_text_dict,
    _render_text_list,
    render_output_text,
)


class TestNormalizedScalar:
    """Tests for _normalized_scalar."""

    def test_plain_string(self):
        """Tests that a plain string is returned as-is."""
        assert _normalized_scalar("Linux") == "Linux"

    def test_strips_whitespace(self):
        """Tests that leading and trailing whitespace is stripped."""
        assert _normalized_scalar("  value  ") == "value"

    def test_empty_string_returns_dash(self):
        """Tests that an empty string returns a dash."""
        assert _normalized_scalar("") == "-"

    def test_null_keyword_returns_dash(self):
        """Tests that the string 'Null' returns a dash."""
        assert _normalized_scalar("Null") == "-"

    def test_no_such_instance_returns_dash(self):
        """Tests that the string 'noSuchInstance' returns a dash."""
        assert _normalized_scalar("noSuchInstance") == "-"

    def test_none_returns_dash(self):
        """Tests that None returns a dash."""
        assert _normalized_scalar(None) == "-"


class TestCollectSections:
    """Tests for _collect_sections."""

    def test_scalar_fields_in_summary(self):
        """Tests that scalar fields are collected in summary_rows."""
        data = {"Hostname": "router", "Description": "RouterOS"}
        summary_rows, structured = _collect_sections(data)
        keys = [row[0] for row in summary_rows]
        assert "Hostname" in keys
        assert "Description" in keys
        assert structured == []

    def test_dict_field_in_structured(self):
        """Tests that a dict field is collected in structured."""
        data = {"Network information": {"iface0": "up"}}
        summary_rows, structured = _collect_sections(data)
        assert summary_rows == []
        assert len(structured) == 1
        assert structured[0][0] == "dict"
        assert structured[0][1] == "Network information"

    def test_list_field_in_structured(self):
        """Tests that a list field is collected in structured."""
        data = {"Processes": [{"Name": "init", "PID": "1"}]}
        _, structured = _collect_sections(data)
        assert structured[0][0] == "list"
        assert structured[0][1] == "Processes"

    def test_unknown_keys_ignored(self):
        """Tests that fields that are not scalar, dict, or list are ignored."""
        data = {"Unknown field": "value"}
        summary_rows, structured = _collect_sections(data)
        assert summary_rows == []
        assert structured == []

    def test_fields_order_respected(self):
        """Tests that the order of fields is respected."""
        data = {"Description": "desc", "Hostname": "host"}
        summary_rows, _ = _collect_sections(data)
        keys = [row[0] for row in summary_rows]
        # Hostname comes before Description in FIELDS_ORDER
        assert keys.index("Hostname") < keys.index("Description")


class TestRenderTextDict:
    """Tests for _render_text_dict."""

    def test_basic_dict(self):
        """Tests that a basic dictionary is rendered correctly."""
        result = _render_text_dict("My Section", {"key1": "val1", "key2": "val2"})
        assert "My Section" in result
        assert "key1: val1" in result
        assert "key2: val2" in result

    def test_null_value_normalized(self):
        """Tests that a null value is normalized to a dash."""
        result = _render_text_dict("Section", {"key": "noSuchInstance"})
        assert "key: -" in result

    def test_empty_dict(self):
        """Tests that an empty dictionary is rendered correctly."""
        result = _render_text_dict("Empty", {})
        assert result == "Empty"


class TestRenderTextList:
    """Tests for _render_text_list."""

    def test_empty_list(self):
        """Tests that an empty list is rendered correctly."""
        result = _render_text_list("Section", [])
        assert "Section" in result
        assert "-" in result

    def test_list_of_dicts(self):
        """Tests that a list of dictionaries is rendered correctly."""
        items = [{"Name": "bash", "PID": "100"}, {"Name": "python", "PID": "200"}]
        result = _render_text_list("Processes", items)
        assert "[1]" in result
        assert "[2]" in result
        assert "Name: bash" in result
        assert "PID: 100" in result

    def test_list_of_lists_with_header(self):
        """Tests that a list of lists with a header is rendered correctly."""
        items = [["IP", "Mask"], ["10.0.0.1", "255.0.0.0"]]
        result = _render_text_list("IPs", items)
        assert "IP | Mask" in result
        assert "10.0.0.1 | 255.0.0.0" in result

    def test_simple_string_list(self):
        """Tests that a simple list of strings is rendered correctly."""
        result = _render_text_list("Tags", ["alpha", "beta", "gamma"])
        assert "alpha" in result
        assert "beta" in result
        assert "gamma" in result


class TestRenderOutputText:
    """Tests for render_output_text."""

    def test_system_info_header(self):
        """Tests that the system information header is rendered."""
        result = render_output_text({"Hostname": "myrouter"})
        assert "System information" in result

    def test_scalar_value_rendered(self):
        """Tests that a scalar value is rendered correctly."""
        result = render_output_text({"Hostname": "myrouter"})
        assert "Hostname: myrouter" in result

    def test_null_scalar_becomes_dash(self):
        """Tests that a null scalar value is rendered as a dash."""
        result = render_output_text({"Hostname": "noSuchInstance"})
        assert "Hostname: -" in result

    def test_dict_section_rendered(self):
        """Tests that a dictionary section is rendered correctly."""
        result = render_output_text({"Network information": {"eth0": "up"}})
        assert "Network information" in result
        assert "eth0: up" in result

    def test_list_section_rendered(self):
        """Tests that a list section is rendered correctly."""
        result = render_output_text({"Processes": [{"Name": "init", "PID": "1"}]})
        assert "Processes" in result
        assert "Name: init" in result

    def test_empty_data(self):
        """Tests that empty data is rendered correctly."""
        result = render_output_text({})
        assert "System information" in result
