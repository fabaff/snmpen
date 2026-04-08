"""Unit tests for static MIB mappings in snmpen.types."""

from snmpen.types import (
    DEVICE_STATUSES,
    DEVICE_TYPES,
    FS_TYPES,
    IF_STATUSES,
    STORAGE_TYPES,
    TCP_STATES,
)


def test_if_statuses_mapping():
    """Test the mapping of interface statuses from IF-MIB."""
    assert IF_STATUSES[1] == "up"
    assert IF_STATUSES[2] == "down"
    assert IF_STATUSES[3] == "testing"


def test_tcp_states_mapping():
    """Test the mapping of TCP connection states from TCP-MIB."""
    assert TCP_STATES[1] == "closed"
    assert TCP_STATES[5] == "established"
    assert TCP_STATES[12] == "deleteTCB"


def test_storage_type_mapping():
    """Test the mapping of storage types from HOST-RESOURCES-MIB."""
    assert STORAGE_TYPES["1.3.6.1.2.1.25.2.1.4"] == "Fixed Disk"
    assert STORAGE_TYPES["1.3.6.1.2.1.25.2.1.9"] == "Flash Memory"


def test_fs_type_mapping():
    """Test the mapping of filesystem types from HOST-RESOURCES-MIB."""
    assert FS_TYPES["1.3.6.1.2.1.25.3.9.9"] == "NTFS"
    assert FS_TYPES["1.3.6.1.2.1.25.3.9.22"] == "FAT32"


def test_device_type_mapping():
    """Test the mapping of device types from HOST-RESOURCES-MIB."""
    assert DEVICE_TYPES["1.3.6.1.2.1.25.3.1.5"] == "Printer"
    assert DEVICE_TYPES["1.3.6.1.2.1.25.3.1.18"] == "Non Volatile Memory"


def test_device_status_mapping():
    """Test the mapping of device statuses from HOST-RESOURCES-MIB."""
    assert DEVICE_STATUSES[1] == "unknown"
    assert DEVICE_STATUSES[2] == "running"
    assert DEVICE_STATUSES[5] == "down"
