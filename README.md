# net-recon

## About

* net-recon is a tool written to perform information gathering on internal networks.
* Since net-recon utilizes host-discovery and broadcast-related protocols, information which may be valuable to an attacker
  can be obtained without ever actively scanning or querying a host.

* This tool does not parse or search for network-based credentials.
* If you wish to parse a PCAP for secrets, be sure to check out the super awesome net-creds (https://github.com/DanMcInerney/net-creds)

## Supported Protocols and Data Types

* Link Local Discovery Protocol (Supported, PoC code)
  - Network switches, potentially including full fingerprints and management addresses

* Microsoft Windows Browser Protocol (Supported, PoC code)
  - Hostnames
  - Windows OS Version
  - Server Type
  - Host Comment (reveals potentially sensitive information / service fingerprints)

* DHCPv4 Bootstrap (Supported, PoC code)
  - DHCP Server IP Address
  - Router IP Address
  - Domain Name Server Addresses
  - Hostnames    

## Protocols and Data Types Currently In Progress

* MDNS
  - Internal domain names
  - Lookup types

## Future Protocols and Data Types From Poisoning Attacks

* SMB Session Setup AndX Response
* Kerberos
* HTTP/WPAD

## Usage

* Perform a packet capture to a PCAP file using a tool like tcpdump.

    tcpdump -i <iface> -w <pcap_outfile_path>

* Then, use net-recon to analyze the PCAP file for info.

    ./net-recon.py --pcap <pcap_file_path>

## Todo

* Add live interface packet capture support
