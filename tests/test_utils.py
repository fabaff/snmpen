"""Unit tests for snmpen.utils."""

from snmpen.utils import (
    format_endpoint,
    get_ip_string,
    get_mac_string,
    is_null,
    number_to_human_size,
    timeticks_to_dhm,
    timeticks_to_seconds,
    truncate_to_twidth,
    value_to_string,
)


class TestTruncateToTwidth:
    """Tests for truncate_to_twidth."""

    def test_shorter_than_width(self):
        """Tests that a string shorter than the width is returned as-is."""
        assert truncate_to_twidth("hello", 10) == "hello"

    def test_exactly_at_width_minus_one(self):
        """Tests that a string exactly at width minus one is returned as-is."""
        assert truncate_to_twidth("hello", 6) == "hello"

    def test_truncated(self):
        """Tests that a string longer than the width is truncated."""
        assert truncate_to_twidth("hello world", 6) == "hello"

    def test_int_input(self):
        """Tests that an integer input is converted to a string and truncated."""
        assert truncate_to_twidth(12345, 4) == "123"


class TestValueToString:
    """Tests for value_to_string."""

    def test_none_returns_empty(self):
        """Tests that None is converted to an empty string."""
        assert value_to_string(None) == ""

    def test_string_passthrough(self):
        """Tests that a string is returned as-is."""
        assert value_to_string("hello") == "hello"

    def test_int_converted(self):
        """Tests that an integer is converted to a string."""
        assert value_to_string(42) == "42"

    def test_zero(self):
        """Tests that zero is converted to a string."""
        assert value_to_string(0) == "0"


class TestNumberToHumanSize:
    """Tests for number_to_human_size."""

    def test_kilobytes(self):
        """Tests that a size in kilobytes is rendered correctly."""
        result = number_to_human_size(1024, 1)
        assert "KiB" in result or "1024" in result

    def test_megabytes(self):
        """Tests that a size in megabytes is rendered correctly."""
        result = number_to_human_size(1, 1048576)
        assert "MiB" in result

    def test_invalid_size(self):
        """Tests that an invalid size is returned as-is."""
        result = number_to_human_size("n/a", 1)
        assert result == "n/a"

    def test_zero(self):
        """Tests that a size of zero is rendered correctly."""
        result = number_to_human_size(0, 512)
        assert "0" in result


class TestTimeticksToSeconds:
    """Tests for timeticks_to_seconds."""

    def test_parenthesized_ticks(self):
        """Tests that parenthesized ticks are converted correctly."""
        # SNMP often returns "X day(s), H:MM:SS (ticks)" — parenthesized value
        assert timeticks_to_seconds("(100)") == 1.0

    def test_plain_digits(self):
        """Tests that plain digit strings are converted correctly."""
        assert timeticks_to_seconds("100") == 1.0

    def test_value_6000(self):
        """Tests that a value of 6000 ticks is converted correctly."""
        assert timeticks_to_seconds("6000") == 60.0

    def test_none_returns_none(self):
        """Tests that None input returns None."""
        assert timeticks_to_seconds(None) is None

    def test_empty_returns_none(self):
        """Tests that an empty string input returns None."""
        assert timeticks_to_seconds("") is None

    def test_null_string_returns_none(self):
        """Tests that a null string input returns None."""
        assert timeticks_to_seconds("noSuchInstance") is None

    def test_non_numeric_returns_none(self):
        """Tests that a non-numeric string input returns None."""
        assert timeticks_to_seconds("abc") is None


class TestTimeticksTodhm:
    """Tests for timeticks_to_dhm."""

    def test_zero_ticks(self):
        """Tests that zero ticks are converted correctly."""
        assert timeticks_to_dhm("0") == "0 minutes 0 seconds"

    def test_one_minute(self):
        """Tests that one minute is converted correctly."""
        result = timeticks_to_dhm("6000")  # 60 seconds
        assert "1 minute" in result

    def test_one_hour(self):
        """Tests that one hour is converted correctly."""
        result = timeticks_to_dhm("360000")  # 3600 seconds
        assert "1 hour" in result

    def test_one_day(self):
        """Tests that one day is converted correctly."""
        result = timeticks_to_dhm("8640000")  # 86400 seconds
        assert "1 day" in result

    def test_none_returns_dash(self):
        """Tests that None input returns a dash."""
        assert timeticks_to_dhm(None) == "-"

    def test_plural_seconds(self):
        """Tests that plural seconds are rendered correctly."""
        result = timeticks_to_dhm("200")  # 2 seconds
        assert "2 seconds" in result

    def test_singular_second(self):
        """Tests that a singular second is rendered correctly."""
        result = timeticks_to_dhm("100")  # 1 second
        assert "1 second" in result


class TestIsNull:
    """Tests for is_null."""

    def test_none(self):
        """Tests that None input is considered null."""
        assert is_null(None) is True

    def test_no_such_instance(self):
        """Tests that 'noSuchInstance' is considered null."""
        assert is_null("noSuchInstance") is True

    def test_no_such_object(self):
        """Tests that 'noSuchObject' is considered null."""
        assert is_null("noSuchObject") is True

    def test_end_of_mib_view(self):
        """Tests that 'endOfMibView' is considered null."""
        assert is_null("endOfMibView") is True

    def test_non_null_string(self):
        """Tests that a non-null string is not considered null."""
        assert is_null("Linux") is False

    def test_non_null_number(self):
        """Tests that a non-null number is not considered null."""
        assert is_null(0) is False

    def test_empty_string(self):
        """Tests that an empty string is not considered null."""
        assert is_null("") is False


class TestGetMacString:
    """Tests for get_mac_string."""

    def test_six_bytes(self):
        """Tests that a MAC address with six bytes is formatted correctly."""
        raw = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        assert get_mac_string(raw) == "aa:bb:cc:dd:ee:ff"

    def test_more_than_six_bytes_truncated(self):
        """Tests that a MAC address with more than six bytes is truncated."""
        raw = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        assert get_mac_string(raw) == "00:11:22:33:44:55"

    def test_invalid_returns_string(self):
        """Tests that an invalid input returns a string."""
        result = get_mac_string("not-bytes")
        assert isinstance(result, str)


class TestGetIpString:
    """Tests for get_ip_string."""

    def test_ipv4_bytes(self):
        """Tests that an IPv4 address in bytes is converted correctly."""
        raw = bytes([192, 168, 0, 1])
        assert get_ip_string(raw) == "192.168.0.1"

    def test_non_four_bytes_fallback(self):
        """Tests that a non-four-byte input falls back to a string."""
        raw = bytes([10, 0])
        result = get_ip_string(raw)
        assert isinstance(result, str)

    def test_invalid_fallback(self):
        """Tests that an invalid input falls back to a string."""
        result = get_ip_string("bad")
        assert isinstance(result, str)


class TestFormatEndpoint:
    """Tests for format_endpoint."""

    def test_ipv4(self):
        """Tests that an IPv4 address is formatted correctly."""
        assert format_endpoint("192.168.1.1", 161) == "192.168.1.1:161"

    def test_ipv6_gets_brackets(self):
        """Tests that an IPv6 address is enclosed in brackets."""
        assert format_endpoint("::1", 161) == "[::1]:161"

    def test_hostname(self):
        """Tests that a hostname is formatted correctly."""
        assert format_endpoint("router.local", 161) == "router.local:161"
