"""MIB-related types and mappings for SNMP operations.

Mappings are defined statically from RFC MIB definitions so runtime imports from
external MIB packages are not required.
"""

IF_STATUSES = {
    1: "up",
    2: "down",
    3: "testing",
}

TCP_STATES = {
    1: "closed",
    2: "listen",
    3: "synSent",
    4: "synReceived",
    5: "established",
    6: "finWait1",
    7: "finWait2",
    8: "closeWait",
    9: "lastAck",
    10: "closing",
    11: "timeWait",
    12: "deleteTCB",
}

STORAGE_TYPES = {
    "1.3.6.1.2.1.25.2.1.1": "Other",
    "1.3.6.1.2.1.25.2.1.2": "Ram",
    "1.3.6.1.2.1.25.2.1.3": "Virtual Memory",
    "1.3.6.1.2.1.25.2.1.4": "Fixed Disk",
    "1.3.6.1.2.1.25.2.1.5": "Removable Disk",
    "1.3.6.1.2.1.25.2.1.6": "Floppy Disk",
    "1.3.6.1.2.1.25.2.1.7": "Compact Disc",
    "1.3.6.1.2.1.25.2.1.8": "Ram Disk",
    "1.3.6.1.2.1.25.2.1.9": "Flash Memory",
    "1.3.6.1.2.1.25.2.1.10": "Network Disk",
}

FS_TYPES = {
    "1.3.6.1.2.1.25.3.9.1": "Other",
    "1.3.6.1.2.1.25.3.9.2": "Unknown",
    "1.3.6.1.2.1.25.3.9.3": "BerkeleyFFS",
    "1.3.6.1.2.1.25.3.9.4": "Sys5FS",
    "1.3.6.1.2.1.25.3.9.5": "Fat",
    "1.3.6.1.2.1.25.3.9.6": "HPFS",
    "1.3.6.1.2.1.25.3.9.7": "HFS",
    "1.3.6.1.2.1.25.3.9.8": "MFS",
    "1.3.6.1.2.1.25.3.9.9": "NTFS",
    "1.3.6.1.2.1.25.3.9.10": "VNode",
    "1.3.6.1.2.1.25.3.9.11": "Journaled",
    "1.3.6.1.2.1.25.3.9.12": "iso9660",
    "1.3.6.1.2.1.25.3.9.13": "RockRidge",
    "1.3.6.1.2.1.25.3.9.14": "NFS",
    "1.3.6.1.2.1.25.3.9.15": "Netware",
    "1.3.6.1.2.1.25.3.9.16": "AFS",
    "1.3.6.1.2.1.25.3.9.17": "DFS",
    "1.3.6.1.2.1.25.3.9.18": "Appleshare",
    "1.3.6.1.2.1.25.3.9.19": "RFS",
    "1.3.6.1.2.1.25.3.9.20": "DGCFS",
    "1.3.6.1.2.1.25.3.9.21": "BFS",
    "1.3.6.1.2.1.25.3.9.22": "FAT32",
    "1.3.6.1.2.1.25.3.9.23": "LinuxExt2",
}

DEVICE_TYPES = {
    "1.3.6.1.2.1.25.3.1.1": "Other",
    "1.3.6.1.2.1.25.3.1.2": "Unknown",
    "1.3.6.1.2.1.25.3.1.3": "Processor",
    "1.3.6.1.2.1.25.3.1.4": "Network",
    "1.3.6.1.2.1.25.3.1.5": "Printer",
    "1.3.6.1.2.1.25.3.1.6": "Disk Storage",
    "1.3.6.1.2.1.25.3.1.7": "Video",
    "1.3.6.1.2.1.25.3.1.8": "Audio",
    "1.3.6.1.2.1.25.3.1.9": "Coprocessor",
    "1.3.6.1.2.1.25.3.1.10": "Keyboard",
    "1.3.6.1.2.1.25.3.1.11": "Modem",
    "1.3.6.1.2.1.25.3.1.12": "Parallel Port",
    "1.3.6.1.2.1.25.3.1.13": "Pointing",
    "1.3.6.1.2.1.25.3.1.14": "Serial Port",
    "1.3.6.1.2.1.25.3.1.15": "Tape",
    "1.3.6.1.2.1.25.3.1.16": "Clock",
    "1.3.6.1.2.1.25.3.1.17": "Volatile Memory",
    "1.3.6.1.2.1.25.3.1.18": "Non Volatile Memory",
}

DEVICE_STATUSES = {
    1: "unknown",
    2: "running",
    3: "warning",
    4: "testing",
    5: "down",
}
