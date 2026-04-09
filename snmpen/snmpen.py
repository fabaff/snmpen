"""Primary SNMP enumeration logic for snmpen."""

import argparse
import asyncio
import builtins
import re
import signal
import sys
import traceback
from datetime import datetime, timedelta

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    get_cmd,
    next_cmd,
    set_cmd,
)
from pysnmp.proto.rfc1902 import OctetString

from .helpers import (
    community_type,
    port_type,
    retries_type,
    target_to_output_filename,
    target_type,
)
from .output import print_output, render_output_rich_text, render_output_text
from .types import (
    DEVICE_STATUSES,
    DEVICE_TYPES,
    FS_TYPES,
    IF_STATUSES,
    STORAGE_TYPES,
    TCP_STATES,
)
from .utils import (
    extract_job_attr,
    format_endpoint,
    get_ip_string,
    get_mac_string,
    is_null,
    number_to_human_size,
    resolve_target_addresses,
    timeticks_to_dhm,
    timeticks_to_seconds,
    value_to_string,
)

signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

AUTO_TARGET_OUTPUT = "__TARGET_OUTPUT__"


async def snmp_get(engine, auth_data, transport, oid):
    """Perform an SNMP GET operation for a given OID."""
    try:
        error_indication, error_status, _, var_binds = await get_cmd(
            engine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
        )
        if error_indication or error_status:
            return None
        return var_binds[0][1] if var_binds else None
    except Exception:
        return None


async def snmp_set(engine, auth_data, transport, oid, value):
    """Perform an SNMP SET operation for a given OID and value."""
    try:
        error_indication, error_status, _, _ = await set_cmd(
            engine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid), value),
            lookupMib=False,
        )
        return not error_indication and not error_status
    except Exception:
        return False


async def snmp_walk(engine, auth_data, transport, oids):
    """Perform an SNMP WALK operation for a list of OIDs."""
    base_oids = list(oids)
    object_types = [ObjectType(ObjectIdentity(oid)) for oid in base_oids]
    try:
        while object_types:
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                auth_data,
                transport,
                ContextData(),
                *object_types,
                lookupMib=False,
            )
            if error_indication or error_status or not var_binds:
                break

            row_values = []
            next_object_types = []
            for base_oid, var_bind in zip(base_oids, var_binds):
                current_oid = str(var_bind[0])
                if is_null(var_bind[1]):
                    return
                if current_oid != base_oid and not current_oid.startswith(
                    base_oid + "."
                ):
                    return
                row_values.append(var_bind[1])
                next_object_types.append(ObjectType(ObjectIdentity(current_oid)))

            if len(row_values) != len(base_oids):
                return

            yield row_values
            object_types = next_object_types
    except Exception:
        return


async def detect_supported_snmp_versions(engine, transport, community):
    """Detect supported SNMP versions for the given host and community."""
    supported_versions = []
    probe_oid = "1.3.6.1.2.1.1.1.0"

    for version_label, mp_model in (("1", 0), ("2c", 1)):
        auth_data = CommunityData(community, mpModel=mp_model)
        response = await snmp_get(engine, auth_data, transport, probe_oid)
        if response is not None:
            supported_versions.append(f"SNMPv{version_label}")

    return supported_versions


async def enumerate(
    engine,
    auth_data,
    transport,
    target,
    check_write,
    disable_tcp,
    supported_versions,
):
    """Perform SNMP enumeration and return the collected data."""
    output_data = {"Host IP address": target}
    output_data["Supported SNMP versions"] = (
        ", ".join(supported_versions) if supported_versions else "-"
    )

    # Basic system info
    sys_name_value = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.1.5.0")
    sys_name = value_to_string(sys_name_value).strip()
    output_data["Hostname"] = sys_name

    if check_write and sys_name:
        if await snmp_set(
            engine,
            auth_data,
            transport,
            "1.3.6.1.2.1.1.5.0",
            OctetString(sys_name.encode()),
        ):
            print("Write access permitted\n\n")
        else:
            print("Write access not permitted\n")

    sys_desc_value = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.1.1.0")
    sys_desc = re.sub(r"[\s\n\r]+", " ", value_to_string(sys_desc_value)).strip()
    output_data["Description"] = sys_desc

    sys_contact = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.1.4.0")
    output_data["Contact"] = value_to_string(sys_contact).strip()

    sys_location = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.1.6.0")
    output_data["Location"] = value_to_string(sys_location).strip()

    sys_uptime = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.1.3.0")
    output_data["Uptime system"] = timeticks_to_dhm(sys_uptime)

    snmp_uptime = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.25.1.1.0")
    output_data["Uptime snmp"] = timeticks_to_dhm(snmp_uptime)

    # Pre-calculate start date for use with uptime fields
    # Use snmp_uptime if available, otherwise fall back to sys_uptime
    uptime_for_start = (
        snmp_uptime if snmp_uptime and not is_null(snmp_uptime) else sys_uptime
    )
    start_date_str = None

    # System date (RFC 2579 DateAndTime)
    system_date_val = await snmp_get(
        engine, auth_data, transport, "1.3.6.1.2.1.25.1.2.0"
    )
    system_date_dt = None
    system_date_s = value_to_string(system_date_val)
    if not system_date_val or is_null(system_date_val) or "Null" in system_date_s:
        output_data["System date"] = "-"
        # Fall back to current system date if SNMP date is not available for the calculation
        system_date_dt = datetime.now()
    else:
        try:
            raw = bytes(system_date_val)
            if len(raw) >= 8:
                year = raw[0] * 256 + raw[1]
                month = raw[2]
                day = raw[3]
                hour = raw[4]
                minutes = raw[5]
                seconds = raw[6]
                tenths = raw[7]
                system_date_dt = datetime(
                    year,
                    month,
                    day,
                    hour,
                    minutes,
                    seconds,
                    tenths * 100000,
                )
                output_data["System date"] = (
                    f"{year}-{month:02d}-{day:02d} {hour:02d}:{minutes:02d}:{seconds:02d}.{tenths}"
                )
            else:
                output_data["System date"] = "-"
                # Fall back to current system date for the calculation if SNMP date is not valid
                system_date_dt = datetime.now()
        except Exception:
            output_data["System date"] = "-"
            # Fall back to current system date for the calculation if SNMP date is not parseable
            system_date_dt = datetime.now()

    # Calculate start date and append to uptime fields
    uptime_seconds = timeticks_to_seconds(uptime_for_start)
    if system_date_dt is not None and uptime_seconds is not None:
        start_date = system_date_dt - timedelta(seconds=uptime_seconds)
        start_date_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
        # Append start date to whichever uptime fields are available
        if sys_uptime and not is_null(sys_uptime):
            output_data["Uptime system"] = (
                f"{output_data['Uptime system']} (Start: {start_date_str})"
            )
        if snmp_uptime and not is_null(snmp_uptime):
            output_data["Uptime snmp"] = (
                f"{output_data['Uptime snmp']} (Start: {start_date_str})"
            )

    # Windows-specific: domain, users
    if "Windows" in sys_desc:
        domain_value = await snmp_get(
            engine, auth_data, transport, "1.3.6.1.4.1.77.1.4.1.0"
        )
        output_data["Domain"] = value_to_string(domain_value).strip()

        users = []
        async for row in snmp_walk(
            engine,
            auth_data,
            transport,
            ["1.3.6.1.4.1.77.1.2.25.1.1", "1.3.6.1.4.1.77.1.2.25.1"],
        ):
            users.append([value_to_string(row[0])])
        if users:
            output_data["User accounts"] = users

    # Network information
    network_information = {}
    ip_forwarding_value = await snmp_get(
        engine, auth_data, transport, "1.3.6.1.2.1.4.1.0"
    )
    if ip_forwarding_value is not None and not is_null(ip_forwarding_value):
        try:
            ipf = int(str(ip_forwarding_value))
            if ipf in (0, 2):
                network_information["IP forwarding enabled"] = "no"
            elif ipf == 1:
                network_information["IP forwarding enabled"] = "yes"
        except (ValueError, TypeError):
            pass

    for oid, key in [
        ("1.3.6.1.2.1.4.2.0", "Default TTL"),
        ("1.3.6.1.2.1.6.10.0", "TCP segments received"),
        ("1.3.6.1.2.1.6.11.0", "TCP segments sent"),
        ("1.3.6.1.2.1.6.12.0", "TCP segments retrans"),
        ("1.3.6.1.2.1.4.3.0", "Input datagrams"),
        ("1.3.6.1.2.1.4.9.0", "Delivered datagrams"),
        ("1.3.6.1.2.1.4.10.0", "Output datagrams"),
    ]:
        value = await snmp_get(engine, auth_data, transport, oid)
        if value and not is_null(value) and "Null" not in value_to_string(value):
            network_information[key] = value_to_string(value)

    if network_information:
        output_data["Network information"] = network_information

    # Network interfaces
    network_interfaces = []
    iface_oids = [
        "1.3.6.1.2.1.2.2.1.1",  # ifIndex
        "1.3.6.1.2.1.2.2.1.2",  # ifDescr
        "1.3.6.1.2.1.2.2.1.6",  # ifPhysAddress (MAC)
        "1.3.6.1.2.1.2.2.1.3",  # ifType
        "1.3.6.1.2.1.2.2.1.4",  # ifMtu
        "1.3.6.1.2.1.2.2.1.5",  # ifSpeed
        "1.3.6.1.2.1.2.2.1.10",  # ifInOctets
        "1.3.6.1.2.1.2.2.1.16",  # ifOutOctets
        "1.3.6.1.2.1.2.2.1.7",  # ifAdminStatus
    ]
    async for row in snmp_walk(engine, auth_data, transport, iface_oids):
        (
            ifindex,
            ifdescr,
            ifmac_raw,
            iftype,
            ifmtu,
            ifspeed,
            ifinoc,
            ifoutoc,
            ifstatus,
        ) = row

        ifmac = get_mac_string(ifmac_raw)

        try:
            iftype_string = value_to_string(iftype)
        except (ValueError, TypeError):
            iftype_string = "unknown"

        try:
            ifstatus_string = IF_STATUSES.get(int(str(ifstatus)), "unknown")
        except (ValueError, TypeError):
            ifstatus_string = "unknown"

        try:
            speed_mbps = int(str(ifspeed)) // 1000000
        except (ValueError, TypeError):
            speed_mbps = 0

        network_interfaces.append(
            {
                "Interface": f"[ {ifstatus_string} ] {value_to_string(ifdescr)}",
                "Id": value_to_string(ifindex),
                "MAC Address": ifmac,
                "Type": iftype_string,
                "Speed": f"{speed_mbps} Mbps",
                "MTU": value_to_string(ifmtu),
                "In octets": value_to_string(ifinoc),
                "Out octets": value_to_string(ifoutoc),
            }
        )

    if network_interfaces:
        output_data["Network interfaces"] = network_interfaces

    # Network IP
    network_ip = []
    async for row in snmp_walk(
        engine,
        auth_data,
        transport,
        [
            "1.3.6.1.2.1.4.20.1.2",
            "1.3.6.1.2.1.4.20.1.1",
            "1.3.6.1.2.1.4.20.1.3",
            "1.3.6.1.2.1.4.20.1.4",
        ],
    ):
        # row[0] = ifIndex, row[1] = ipAddr, row[2] = netMask, row[3] = bcastAddr
        network_ip.append(
            [
                value_to_string(row[0]),
                get_ip_string(row[1]),
                get_ip_string(row[2]),
                value_to_string(row[3]),
            ]
        )
    if network_ip:
        output_data["Network IP"] = [
            ["Id", "IP Address", "Netmask", "Broadcast"]
        ] + network_ip

    # Routing
    routing = []
    async for row in snmp_walk(
        engine,
        auth_data,
        transport,
        [
            "1.3.6.1.2.1.4.21.1.1",
            "1.3.6.1.2.1.4.21.1.7",
            "1.3.6.1.2.1.4.21.1.11",
            "1.3.6.1.2.1.4.21.1.3",
        ],
    ):
        # row[0] = dest, row[1] = nextHop, row[2] = mask, row[3] = metric
        destination = get_ip_string(row[0])
        hop = get_ip_string(row[1])
        mask = get_ip_string(row[2])
        metric = value_to_string(row[3])
        routing.append([destination, hop, mask, metric or "-"])
    if routing:
        output_data["Routing information"] = [
            ["Destination", "Next hop", "Mask", "Metric"]
        ] + routing

    # TCP connections
    if not disable_tcp:
        tcp = []
        async for row in snmp_walk(
            engine,
            auth_data,
            transport,
            [
                "1.3.6.1.2.1.6.13.1.2",
                "1.3.6.1.2.1.6.13.1.3",
                "1.3.6.1.2.1.6.13.1.4",
                "1.3.6.1.2.1.6.13.1.5",
                "1.3.6.1.2.1.6.13.1.1",
            ],
        ):
            ladd, lport, radd, rport, state = row
            ladd_string = (
                "-"
                if (is_null(ladd) or not value_to_string(ladd))
                else value_to_string(ladd)
            )
            lport_string = (
                "-"
                if (is_null(lport) or not value_to_string(lport))
                else value_to_string(lport)
            )
            radd_string = (
                "-"
                if (is_null(radd) or not value_to_string(radd))
                else value_to_string(radd)
            )
            rport_string = (
                "-"
                if (is_null(rport) or not value_to_string(rport))
                else value_to_string(rport)
            )
            try:
                state_string = TCP_STATES.get(int(str(state)), "unknown")
            except (ValueError, TypeError):
                state_string = "unknown"
            tcp.append(
                [ladd_string, lport_string, radd_string, rport_string, state_string]
            )
        if tcp:
            output_data["TCP connections and listening ports"] = [
                [
                    "Local address",
                    "Local port",
                    "Remote address",
                    "Remote port",
                    "State",
                ]
            ] + tcp

    # UDP ports
    udp = []
    async for row in snmp_walk(
        engine, auth_data, transport, ["1.3.6.1.2.1.7.5.1.1", "1.3.6.1.2.1.7.5.1.2"]
    ):
        udp.append([value_to_string(row[0]), value_to_string(row[1])])
    if udp:
        output_data["Listening UDP ports"] = [["Local address", "Local port"]] + udp

    # Windows-specific: network services, shares, IIS
    if "Windows" in sys_desc:
        network_services = []
        n = 0
        async for row in snmp_walk(
            engine,
            auth_data,
            transport,
            ["1.3.6.1.4.1.77.1.2.3.1.1", "1.3.6.1.4.1.77.1.2.3.1.2"],
        ):
            network_services.append([n, value_to_string(row[0])])
            n += 1
        if network_services:
            output_data["Network services"] = [["Index", "Name"]] + network_services

        share = []
        async for row in snmp_walk(
            engine,
            auth_data,
            transport,
            [
                "1.3.6.1.4.1.77.1.2.27.1.1",
                "1.3.6.1.4.1.77.1.2.27.1.2",
                "1.3.6.1.4.1.77.1.2.27.1.3",
            ],
        ):
            share.append(
                {
                    "  Name": value_to_string(row[0]),
                    "  Path": value_to_string(row[1]),
                    "  Comment": value_to_string(row[2]),
                }
            )
        if share:
            output_data["Share"] = share

        iis = {}
        iis_oids = {
            "1.3.6.1.4.1.311.1.7.3.1.2.0": "TotalBytesSentLowWord",
            "1.3.6.1.4.1.311.1.7.3.1.4.0": "TotalBytesReceivedLowWord",
            "1.3.6.1.4.1.311.1.7.3.1.5.0": "TotalFilesSent",
            "1.3.6.1.4.1.311.1.7.3.1.6.0": "CurrentAnonymousUsers",
            "1.3.6.1.4.1.311.1.7.3.1.7.0": "CurrentNonAnonymousUsers",
            "1.3.6.1.4.1.311.1.7.3.1.8.0": "TotalAnonymousUsers",
            "1.3.6.1.4.1.311.1.7.3.1.9.0": "TotalNonAnonymousUsers",
            "1.3.6.1.4.1.311.1.7.3.1.10.0": "MaxAnonymousUsers",
            "1.3.6.1.4.1.311.1.7.3.1.11.0": "MaxNonAnonymousUsers",
            "1.3.6.1.4.1.311.1.7.3.1.12.0": "CurrentConnections",
            "1.3.6.1.4.1.311.1.7.3.1.13.0": "MaxConnections",
            "1.3.6.1.4.1.311.1.7.3.1.14.0": "ConnectionAttempts",
            "1.3.6.1.4.1.311.1.7.3.1.15.0": "LogonAttempts",
            "1.3.6.1.4.1.311.1.7.3.1.16.0": "Gets",
            "1.3.6.1.4.1.311.1.7.3.1.17.0": "Posts",
            "1.3.6.1.4.1.311.1.7.3.1.18.0": "Heads",
            "1.3.6.1.4.1.311.1.7.3.1.19.0": "Others",
            "1.3.6.1.4.1.311.1.7.3.1.20.0": "CGIRequests",
            "1.3.6.1.4.1.311.1.7.3.1.21.0": "BGIRequests",
            "1.3.6.1.4.1.311.1.7.3.1.22.0": "NotFoundErrors",
        }
        for oid, key in iis_oids.items():
            value = await snmp_get(engine, auth_data, transport, oid)
            if value and not is_null(value) and "Null" not in value_to_string(value):
                iis[key] = value_to_string(value)
        if iis:
            output_data["IIS server information"] = iis

    # Storage information
    storage_raw = []
    async for row in snmp_walk(
        engine,
        auth_data,
        transport,
        [
            "1.3.6.1.2.1.25.2.3.1.1",
            "1.3.6.1.2.1.25.2.3.1.2",
            "1.3.6.1.2.1.25.2.3.1.3",
            "1.3.6.1.2.1.25.2.3.1.4",
            "1.3.6.1.2.1.25.2.3.1.5",
            "1.3.6.1.2.1.25.2.3.1.6",
        ],
    ):
        index, type_oid, descr, allocation, size, used = row
        type_string = STORAGE_TYPES.get(value_to_string(type_oid), "unknown")
        alloc_string = "unknown" if is_null(allocation) else value_to_string(allocation)
        size_string = "unknown" if is_null(size) else value_to_string(size)
        used_string = "unknown" if is_null(used) else value_to_string(used)
        storage_raw.append(
            (
                [value_to_string(descr)],
                [value_to_string(index)],
                [type_string],
                [alloc_string],
                [size_string],
                [used_string],
            )
        )

    if storage_raw:
        storage = []
        for (
            description,
            device_id,
            filesystem_type,
            device_unit,
            memory_size,
            memory_used,
        ) in storage_raw:
            storage.append(
                {
                    "Description": description[0],
                    "Device id": device_id[0],
                    "Filesystem type": filesystem_type[0],
                    "Device unit": device_unit[0],
                    "Memory size": number_to_human_size(memory_size[0], device_unit[0]),
                    "Memory used": number_to_human_size(memory_used[0], device_unit[0]),
                }
            )
        output_data["Storage information"] = storage

    # File system information
    file_system = {}
    for oid, key in [
        ("1.3.6.1.2.1.25.3.8.1.1.1", "Index"),
        ("1.3.6.1.2.1.25.3.8.1.2.1", "Mount point"),
    ]:
        value = await snmp_get(engine, auth_data, transport, oid)
        if value and not is_null(value) and "Null" not in value_to_string(value):
            file_system[key] = value_to_string(value)

    hr_remote = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.25.3.8.1.3.1")
    hr_remote_string = value_to_string(hr_remote)
    if (
        hr_remote
        and not is_null(hr_remote)
        and "noSuch" not in hr_remote_string
        and "Null" not in hr_remote_string
    ):
        file_system["Remote mount point"] = (
            hr_remote_string if hr_remote_string else "-"
        )

    hr_fs_type = await snmp_get(
        engine, auth_data, transport, "1.3.6.1.2.1.25.3.8.1.4.1"
    )
    if hr_fs_type and not is_null(hr_fs_type):
        fs_str = FS_TYPES.get(value_to_string(hr_fs_type))
        if fs_str:
            file_system["Type"] = fs_str

    for oid, key in [
        ("1.3.6.1.2.1.25.3.8.1.5.1", "Access"),
        ("1.3.6.1.2.1.25.3.8.1.6.1", "Bootable"),
    ]:
        value = await snmp_get(engine, auth_data, transport, oid)
        if value and not is_null(value) and "Null" not in value_to_string(value):
            file_system[key] = value_to_string(value)

    if file_system:
        output_data["File system information"] = file_system

    # Device information
    device_information = []
    async for row in snmp_walk(
        engine,
        auth_data,
        transport,
        [
            "1.3.6.1.2.1.25.3.2.1.1",
            "1.3.6.1.2.1.25.3.2.1.2",
            "1.3.6.1.2.1.25.3.2.1.5",
            "1.3.6.1.2.1.25.3.2.1.3",
        ],
    ):
        index, type_oid, status, descr = row
        type_string = DEVICE_TYPES.get(value_to_string(type_oid), "unknown")
        try:
            status_string = DEVICE_STATUSES.get(int(str(status)), "unknown")
        except (ValueError, TypeError):
            status_string = "unknown"
        descr_string = "unknown" if is_null(descr) else value_to_string(descr)
        device_information.append(
            [value_to_string(index), type_string, status_string, descr_string]
        )

    if device_information:
        output_data["Device information"] = [
            ["Id", "Type", "Status", "Descr"]
        ] + device_information

    # Software components
    software_list = []
    async for row in snmp_walk(
        engine,
        auth_data,
        transport,
        ["1.3.6.1.2.1.25.6.3.1.1", "1.3.6.1.2.1.25.6.3.1.2"],
    ):
        software_list.append([value_to_string(row[0]), value_to_string(row[1])])
    if software_list:
        output_data["Software components"] = [["Index", "Name"]] + software_list

    # Processes
    process_list = []
    async for row in snmp_walk(
        engine,
        auth_data,
        transport,
        [
            "1.3.6.1.2.1.25.4.2.1.1",
            "1.3.6.1.2.1.25.4.2.1.2",
            "1.3.6.1.2.1.25.4.2.1.4",
            "1.3.6.1.2.1.25.4.2.1.5",
            "1.3.6.1.2.1.25.4.2.1.7",
        ],
    ):
        pid, name, path, param, status = row
        try:
            status = int(str(status))
            status_string = (
                "running" if status == 1 else ("runnable" if status == 2 else "unknown")
            )
        except (ValueError, TypeError):
            status_string = "unknown"
        process_list.append(
            [
                value_to_string(pid),
                status_string,
                value_to_string(name),
                value_to_string(path),
                value_to_string(param),
            ]
        )
    if process_list:
        output_data["Processes"] = [
            ["Id", "Status", "Name", "Path", "Parameters"]
        ] + process_list

    # HP LaserJet printer enumeration
    hp_jobs = []
    hp_oids = [
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.1",  # job-info-name1
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.2",  # job-info-name2
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.1",  # job-info-attr-1 (username)
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.2",  # job-info-attr-2 (machine)
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.3",  # job-info-attr-3 (domain)
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.4",  # job-info-attr-4 (timestamp)
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.6",  # job-info-attr-6 (app name)
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.7",  # job-info-attr-7 (app command)
    ]
    async for row in snmp_walk(engine, auth_data, transport, hp_oids):
        (
            name1,
            name2,
            username_value,
            client_value,
            domain_value,
            timestamp_value,
            app_name_value,
            app_cmd_value,
        ) = row
        filename = value_to_string(name1) + value_to_string(name2)
        username = extract_job_attr(username_value)
        client = extract_job_attr(client_value)
        domain = extract_job_attr(domain_value)
        app_name = extract_job_attr(app_name_value)
        app_cmd = extract_job_attr(app_cmd_value)
        timestamp = (
            None if is_null(timestamp_value) else extract_job_attr(timestamp_value)
        )
        if timestamp is not None:
            hp_jobs.append(
                {
                    "Filename": filename + str(len(filename)),
                    "Username": username,
                    "Client": client,
                    "Timestamp": timestamp,
                    "Domain": domain,
                    "Application name": app_name,
                    "Application command": app_cmd,
                }
            )
    if hp_jobs:
        output_data["HP LaserJet printer enumeration"] = hp_jobs

    return output_data


async def run_enumeration(
    target,
    port,
    timeout,
    retries,
    community,
    mp_model,
    check_write,
    disable_tcp,
    ip_version,
):
    """Set up SNMP engine and transport, run enumeration, and return the collected data."""
    engine = SnmpEngine()
    try:
        auth_data = CommunityData(community, mpModel=mp_model)
        transport_class = Udp6TransportTarget if ip_version == 6 else UdpTransportTarget
        transport = await transport_class.create(
            (target, port), timeout=timeout, retries=retries
        )

        supported_versions = await detect_supported_snmp_versions(
            engine, transport, community
        )

        selected_version = "SNMPv1" if mp_model == 0 else "SNMPv2c"
        if not supported_versions:
            raise TimeoutError("No SNMP response from target")

        if selected_version not in supported_versions:
            supported_text = ", ".join(supported_versions)
            raise RuntimeError(
                f"Selected {selected_version} is not supported by target "
                f"(supported: {supported_text})"
            )

        # Fail fast on non-responsive targets instead of timing out across many OIDs.
        probe = await snmp_get(engine, auth_data, transport, "1.3.6.1.2.1.1.1.0")
        if probe is None:
            raise TimeoutError("No SNMP response from target")

        return await enumerate(
            engine,
            auth_data,
            transport,
            target,
            check_write,
            disable_tcp,
            supported_versions,
        )
    finally:
        engine.close_dispatcher()


def main():
    """Parse command-line arguments and run SNMP enumeration."""

    script_name = "snmpen"
    script_version = "1.1.0"
    script_description = "SNMP Enumerator"
    script_copyright = "Copyright (c) 2019-2026"
    script_author = "Fabian Affolter <fabian@affolter-engineering.ch>"

    description_header = f"{script_name} {script_version} - {script_description}"
    if script_copyright:
        description_header += f"\n{script_copyright} {script_author}"
    else:
        description_header += f"\nby {script_author}"

    parser = argparse.ArgumentParser(
        prog=script_name,
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description_header,
        epilog=(
            "Usage examples:\n"
            f"  {script_name} 172.16.1.1\n"
            f"  {script_name} 2001:db8::10\n"
            f"  {script_name} demo.pysnmp.com\n"
            f"  {script_name} -f hosts.txt\n"
            f"  {script_name} -o 172.16.1.1\n"
            f"  {script_name} --output-format plain -f hosts.txt\n"
            f"  {script_name} --output-format rich -o report.txt 172.16.1.1\n"
            f"  {script_name} -c private -s 2c 172.16.1.1\n"
            f"  {script_name} -w -d -t 10 172.16.1.1\n"
        ),
    )
    parser.add_argument(
        "-p",
        "--port",
        type=port_type,
        default=161,
        metavar="PORT",
        help="SNMP port (default: 161)",
    )
    parser.add_argument(
        "-c",
        "--community",
        type=community_type,
        default="public",
        metavar="COMMUNITY",
        help="SNMP community string (default: public)",
    )
    parser.add_argument(
        "-s",
        "--snmp-version",
        type=str,
        default="1",
        choices=["1", "2c"],
        metavar="VERSION",
        help="SNMP version: 1 or 2c (default: 1)",
    )
    parser.add_argument(
        "-w",
        "--write",
        action="store_true",
        help="Detect write access (not part of the enumeration)",
    )
    parser.add_argument(
        "-d",
        "--disable_tcp",
        action="store_true",
        help="Disable TCP connections enumeration",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=5,
        metavar="SECONDS",
        help="Timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=retries_type,
        default=1,
        metavar="RETRIES",
        help="Request retries (default: 1)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        nargs="?",
        const=AUTO_TARGET_OUTPUT,
        metavar="FILE",
        help="Write output to FILE (or auto-name as <target>.txt if omitted)",
    )
    parser.add_argument(
        "--output-format",
        type=str,
        default="auto",
        choices=["auto", "plain", "rich"],
        metavar="FORMAT",
        help="Output format: auto, plain, or rich (default: auto)",
    )
    parser.add_argument(
        "-f",
        "--hosts-file",
        type=str,
        default=None,
        metavar="FILE",
        help="Read targets from FILE (one host per line)",
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Show script version and exit"
    )
    parser.add_argument(
        "-h", "--help", action="store_true", help="Show this help message and exit"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        type=target_type,
        help="Target IPv4/IPv6 address or hostname (FQDN)",
    )

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    if args.version:
        print(f"{script_version}")
        sys.exit(0)

    requested_targets = []
    if args.hosts_file:
        try:
            with open(args.hosts_file, "r", encoding="utf-8") as hosts_file:
                for raw_line in hosts_file:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    requested_targets.append(target_type(line))
        except OSError as exc:
            print(f"Unable to read hosts file '{args.hosts_file}': {exc}")
            sys.exit(1)
        except argparse.ArgumentTypeError as exc:
            print(str(exc))
            sys.exit(1)

    if args.target is not None:
        requested_targets.append(args.target)

    if not requested_targets:
        print("You need to specify a target IP address/hostname or --hosts-file")
        sys.exit(1)

    community = args.community
    port = args.port
    timeout = args.timeout
    retries = args.retries
    check_write = args.write
    disable_tcp = args.disable_tcp

    if args.snmp_version == "1":
        mp_model = 0  # SNMPv1
    else:
        mp_model = 1  # SNMPv2c

    if check_write:
        print("Write access check enabled\n")
    if disable_tcp:
        print("TCP connections enumeration disabled")

    results = []
    has_failures = False

    if len(requested_targets) > 1:
        print(f"Total targets to enumerate: {len(requested_targets)}\n")

    for requested_target in requested_targets:
        try:
            targets = resolve_target_addresses(requested_target, port)
        except ValueError as exc:
            print(str(exc))
            has_failures = True
            continue

        output_data = None

        for idx, (target, ip_version) in builtins.enumerate(targets, start=1):
            print(
                f"Connecting to {format_endpoint(target, port)} "
                f"with community '{community}' ..."
            )

            try:
                output_data = asyncio.run(
                    run_enumeration(
                        target,
                        port,
                        timeout,
                        retries,
                        community,
                        mp_model,
                        check_write,
                        disable_tcp,
                        ip_version,
                    )
                )
                break
            except Exception as exc:
                exc_name = type(exc).__name__
                exc_str = str(exc).lower()
                if "timeout" in exc_name.lower() or "timeout" in exc_str:
                    print(f"{format_endpoint(target, port)} SNMP request timeout")
                elif "connection" in exc_name.lower() or "refused" in exc_str:
                    print(f"{format_endpoint(target, port)} Connection refused")
                else:
                    print(f"Unknown error: {exc_name} {exc}")
                    print(f"Call stack:\n{traceback.format_exc()}")

        if output_data is None:
            has_failures = True
            continue

        results.append((requested_target, output_data))

        # In interactive mode, print each host result as soon as it is ready.
        if not args.output:
            if len(requested_targets) > 1:
                print(f"Results for {requested_target}\n")
            selected_mode = (
                "rich" if args.output_format == "auto" else args.output_format
            )
            if selected_mode == "plain":
                print(render_output_text(output_data))
            else:
                print_output(output_data)
            print()

    if not results:
        sys.exit(1)

    try:
        if args.output:
            selected_mode = (
                "plain" if args.output_format == "auto" else args.output_format
            )

            if args.output == AUTO_TARGET_OUTPUT:
                for requested_target, output_data in results:
                    output_filename = target_to_output_filename(requested_target)
                    if selected_mode == "rich":
                        rendered_output = render_output_rich_text(output_data)
                    else:
                        rendered_output = render_output_text(output_data)

                    with open(output_filename, "w", encoding="utf-8") as output_handle:
                        output_handle.write(rendered_output)
                        output_handle.write("\n")
                    print(f"Output written to {output_filename}")
            else:
                rendered_outputs = []
                for requested_target, output_data in results:
                    if len(results) > 1:
                        rendered_outputs.append(f"Target: {requested_target}")
                    if selected_mode == "rich":
                        rendered_outputs.append(render_output_rich_text(output_data))
                    else:
                        rendered_outputs.append(render_output_text(output_data))

                with open(args.output, "w", encoding="utf-8") as output_handle:
                    output_handle.write("\n\n".join(rendered_outputs))
                    output_handle.write("\n")
                print(f"Output written to {args.output}")
    except RuntimeError as exc:
        print(str(exc))
        sys.exit(1)
    except OSError as exc:
        print(f"Unable to write output file '{args.output}': {exc}")

    if len(requested_targets) > 1:
        failed_targets = len(requested_targets) - len(results)
        if failed_targets:
            print(
                f"\nAll hosts done: {len(results)}/{len(requested_targets)} succeeded, "
                f"{failed_targets} failed"
            )
        else:
            print(
                f"\nAll hosts done: {len(results)}/{len(requested_targets)} succeeded"
            )

    if has_failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
