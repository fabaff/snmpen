"""Unit tests for snmpen.helpers."""

import argparse

import pytest

from snmpen.helpers import (
    community_type,
    port_type,
    retries_type,
    target_to_output_filename,
    target_type,
)


class TestCommunityType:
    """Tests for community_type."""

    def test_valid_short_string(self):
        assert community_type("public") == "public"

    def test_valid_31_chars(self):
        """Tests that a string of exactly 31 characters is accepted."""
        s = "a" * 31
        assert community_type(s) == s

    def test_rejects_32_chars(self):
        """Tests that a string longer than 31 characters is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            community_type("a" * 32)

    def test_rejects_long_string(self):
        """Tests that a string longer than 31 characters is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            community_type("x" * 64)


class TestPortType:
    """Tests for port_type."""

    def test_valid_zero(self):
        """Tests that port 0 is accepted."""
        assert port_type("0") == 0

    def test_valid_161(self):
        """Tests that port 161 is accepted."""
        assert port_type("161") == 161

    def test_valid_max(self):
        """Tests that the maximum port 65535 is accepted."""
        assert port_type("65535") == 65535

    def test_rejects_negative(self):
        """Tests that a negative port number is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            port_type("-1")

    def test_rejects_above_max(self):
        """Tests that a port number above 65535 is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            port_type("65536")


class TestRetriesType:
    """Tests for retries_type."""

    def test_valid_zero(self):
        """Tests that 0 retries is accepted."""
        assert retries_type("0") == 0

    def test_valid_five(self):
        """Tests that 5 retries is accepted."""
        assert retries_type("5") == 5

    def test_valid_max(self):
        """Tests that the maximum of 10 retries is accepted."""
        assert retries_type("10") == 10

    def test_rejects_negative(self):
        """Tests that a negative number of retries is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            retries_type("-1")

    def test_rejects_above_max(self):
        """Tests that a number of retries above the maximum is rejected."""
        with pytest.raises(argparse.ArgumentTypeError):
            retries_type("11")


class TestTargetType:
    """Tests for target_type."""

    def test_valid_ipv4(self):
        """Tests that a valid IPv4 address is accepted."""
        assert target_type("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        """Tests that a valid IPv6 address is accepted."""
        assert target_type("::1") == "::1"

    def test_valid_hostname(self):
        """Tests that a valid hostname is accepted."""
        assert target_type("demo.pysnmp.com") == "demo.pysnmp.com"

    def test_valid_simple_hostname(self):
        """Tests that a simple hostname is accepted."""
        assert target_type("router") == "router"

    def test_rejects_invalid_ipv4(self):
        """Tests that an invalid IPv4 address is rejected."""
        with pytest.raises(argparse.ArgumentTypeError, match="Invalid IP address"):
            target_type("999.1.1.1")

    def test_rejects_invalid_ipv4_three_numeric_labels(self):
        """Tests that an IPv4 address with three numeric labels is rejected."""
        with pytest.raises(argparse.ArgumentTypeError, match="Invalid IP address"):
            target_type("192.168.1.999")

    def test_rejects_ipv6_like_string(self):
        """Tests that an invalid IPv6 address is rejected."""
        with pytest.raises(argparse.ArgumentTypeError, match="Invalid IP address"):
            target_type("gg::1")

    def test_four_labels_three_numeric_rejects(self):
        """Tests that a string with four labels but three numeric is rejected as an IP address."""
        # e.g. "192.168.0.abc" - 3 numeric labels out of 4
        with pytest.raises(argparse.ArgumentTypeError, match="Invalid IP address"):
            target_type("192.168.0.abc")

    def test_four_labels_two_numeric_allowed(self):
        """Tests that a string with four labels but only two numeric is accepted as a hostname."""
        # Looks enough like a hostname (only 2 numeric parts)
        assert target_type("host.1.2.example") == "host.1.2.example"


class TestTargetToOutputFilename:
    """Tests for target_to_output_filename."""

    def test_plain_ip(self):
        """Tests that a plain IP address is converted to a filename."""
        assert target_to_output_filename("192.168.1.1") == "192.168.1.1.txt"

    def test_hostname(self):
        """Tests that a hostname is converted to a filename."""
        assert target_to_output_filename("router.local") == "router.local.txt"

    def test_special_chars_replaced(self):
        """Tests that special characters are replaced in the filename."""
        result = target_to_output_filename("host name::")
        assert " " not in result
        assert result.endswith(".txt")
        assert ":" not in result

    def test_empty_string_fallback(self):
        """Tests that an empty string results in the fallback filename."""
        assert target_to_output_filename("") == "snmp-target.txt"

    def test_only_special_chars_fallback(self):
        """Tests that a string with only special characters results in the fallback filename."""
        assert target_to_output_filename(":::") == "snmp-target.txt"
