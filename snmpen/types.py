"""MIB-related types and mappings for SNMP operations."""

import re

from pysnmp.smi import builder, view

mibBuilder = builder.MibBuilder()
mibView = view.MibViewController(mibBuilder)
mibBuilder.load_modules(
    "IF-MIB", "RFC1213-MIB", "HOST-RESOURCES-MIB", "HOST-RESOURCES-TYPES"
)

(ifAdminStatus_mib,) = mibBuilder.import_symbols("IF-MIB", "ifAdminStatus")
IF_STATUSES = {int(v): str(k) for k, v in ifAdminStatus_mib.syntax.namedValues.items()}

(tcpConnState_mib,) = mibBuilder.import_symbols("RFC1213-MIB", "tcpConnState")
TCP_STATES = {int(v): str(k) for k, v in tcpConnState_mib.syntax.namedValues.items()}


def _hr_type_map(mb, module, prefix, names, split_camel=True):
    objs = mb.import_symbols(module, *names)
    result = {}
    for sym, obj in zip(names, objs):
        oid = ".".join(str(x) for x in obj.getName())
        label = sym[len(prefix) :]
        if split_camel:
            label = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", label)
        result[oid] = label
    return result


STORAGE_TYPES = _hr_type_map(
    mibBuilder,
    "HOST-RESOURCES-TYPES",
    "hrStorage",
    [
        "hrStorageOther",
        "hrStorageRam",
        "hrStorageVirtualMemory",
        "hrStorageFixedDisk",
        "hrStorageRemovableDisk",
        "hrStorageFloppyDisk",
        "hrStorageCompactDisc",
        "hrStorageRamDisk",
        "hrStorageFlashMemory",
        "hrStorageNetworkDisk",
    ],
)

FS_TYPES = _hr_type_map(
    mibBuilder,
    "HOST-RESOURCES-TYPES",
    "hrFS",
    [
        "hrFSOther",
        "hrFSUnknown",
        "hrFSBerkeleyFFS",
        "hrFSSys5FS",
        "hrFSFat",
        "hrFSHPFS",
        "hrFSHFS",
        "hrFSMFS",
        "hrFSNTFS",
        "hrFSVNode",
        "hrFSJournaled",
        "hrFSiso9660",
        "hrFSRockRidge",
        "hrFSNFS",
        "hrFSNetware",
        "hrFSAFS",
        "hrFSDFS",
        "hrFSAppleshare",
        "hrFSRFS",
        "hrFSDGCFS",
        "hrFSBFS",
        "hrFSFAT32",
        "hrFSLinuxExt2",
    ],
    split_camel=False,
)

DEVICE_TYPES = _hr_type_map(
    mibBuilder,
    "HOST-RESOURCES-TYPES",
    "hrDevice",
    [
        "hrDeviceOther",
        "hrDeviceUnknown",
        "hrDeviceProcessor",
        "hrDeviceNetwork",
        "hrDevicePrinter",
        "hrDeviceDiskStorage",
        "hrDeviceVideo",
        "hrDeviceAudio",
        "hrDeviceCoprocessor",
        "hrDeviceKeyboard",
        "hrDeviceModem",
        "hrDeviceParallelPort",
        "hrDevicePointing",
        "hrDeviceSerialPort",
        "hrDeviceTape",
        "hrDeviceClock",
        "hrDeviceVolatileMemory",
        "hrDeviceNonVolatileMemory",
    ],
)

(hrDeviceStatus_mib,) = mibBuilder.import_symbols(
    "HOST-RESOURCES-MIB", "hrDeviceStatus"
)
DEVICE_STATUSES = {
    int(v): str(k) for k, v in hrDeviceStatus_mib.syntax.namedValues.items()
}
