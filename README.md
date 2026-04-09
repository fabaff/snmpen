# SNMPen (SNMP Enumerator)

You know `snmpcheck`? Good, `snmpen` is doing the same. It's another enumerator for SNMP enabled hosts. It's started as a drop-in replacement for `snmpcheck` which was no longer maintained back in 2018/2019. Nowadays, `snmpen` has it's own heart and mind but still shares a similar CLI interface with `snmpcheck`.

Enummerations are happening against RFC1157-compliant systems. The heavy lifting is done by `pysnmp`.

## Installation

```bash
$ pip install snmpen
```

For Nix or NixOS users is a package available. Keep in mind that the lastest releases might only
be present in the ``unstable`` channel.

```bash
 $ nix-env -iA nixos.snmpen
```

## Usage

The tools support IPv4 addresses, IPv6 addresses and FQDNs as input.

```bash
$ snmpen -h

options:
  -p, --port PORT       SNMP port (default: 161)
  -c, --community COMMUNITY
                        SNMP community string (default: public)
  -s, --snmp-version VERSION
                        SNMP version: 1 or 2c (default: 1)
  -w, --write           Detect write access (not part of the enumeration)
  -d, --disable_tcp     Disable TCP connections enumeration
  -t, --timeout SECONDS
                        Timeout in seconds (default: 5)
  -r, --retries RETRIES
                        Request retries (default: 1)
  -o, --output FILE     Write formatted enumeration output to FILE
  --output-format FORMAT
                        Output format: auto, plain, or rich (default: auto)
  -f, --hosts-file FILE
                        Read targets from FILE (one host per line)
  -v, --version         Show script version and exit
  -h, --help            Show this help message and exit

Usage examples:
  snmpen 172.16.1.1
  snmpen 2001:db8::10
  snmpen demo.pysnmp.com
  snmpen 172.16.1.1 -o
  snmpen -f hosts.txt
  snmpen --output-format plain -f hosts.txt
  snmpen --output-format rich -o report.txt 172.16.1.1
  snmpen -c private -s 2c 172.16.1.1
  snmpen -w -d -t 10 172.16.1.1
```

The hosts file supports one target per line. Empty lines and lines starting with # are ignored.

When `-o` is used without a filename, snmpen writes one file per successful target using `<target>.txt`.

The system information section also shows the detected supported SNMP versions for the host (currently SNMPv1 and SNMPv2c detection).

## License

`snmpen` is licensed under MIT. 
