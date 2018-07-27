#!/usr/bin/python2
#
##################################################################################
#
# 888b    888          888         8888888b.
# 8888b   888          888         888   Y88b
# 88888b  888          888         888    888
# 888Y88b 888  .d88b.  888888      888   d88P .d88b.   .d8888b .d88b.  88888b.
# 888 Y88b888 d8P  Y8b 888         8888888P" d8P  Y8b d88P"   d88""88b 888 "88b
# 888  Y88888 88888888 888  888888 888 T88b  88888888 888     888  888 888  888
# 888   Y8888 Y8b.     Y88b.       888  T88b Y8b.     Y88b.   Y88..88P 888  888
# 888    Y888  "Y8888   "Y888      888   T88b "Y8888   "Y8888P "Y88P"  888  888
#
# Net-Recon | A tool used for network and Active Directory information gathering
#             using passive network protocols
#
# Copyright (C) 2018 Kory Findley (k0fin)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##################################################################################

import sys
import os
import glob
import subprocess
import time

from scapy.all import *
from scapy.utils import *

from argparse import ArgumentParser

def banner():

    with open('/opt/net-recon/banners/default.banner','r') as bfile:
        print bfile.read().strip()

    print ''

class MDNS:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()


        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(UDP) and packet.getlayer(IP) and packet[UDP].sport == 5353 and packet[UDP].dport == 5353 and packet[IP].dst == '224.0.0.251':
                    raw_packet = str(packet[DNS]).replace('\r','\t').split('\t')
                    try:
                        domain = raw_packet[1].split()[0].replace('\x05','.').replace('\x04','.').split('\x00')[0].strip()

                    except IndexError:
                        domain = None

                    if domain != None and domain not in self.keys['domains'].keys():
                        self.keys['domains'].update({domain: {'protocol': 'mdns', 'client_ipv4': packet[IP].src}})

        return self.keys

class WinBrowser:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(UDP) and packet[UDP].sport == 138 and packet[UDP].dport == 138 and packet[IP].dst == '192.168.112.255':
                    raw_packet = list(str(packet[Raw]))
                    browser_cmd = raw_packet[85:87]

                    if browser_cmd[1] == '\x01':

                        announcement = 'Host Announcement (0x01)'
                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        hostname = ''.join(raw_packet[92:]).rsplit('\x00')[0].strip()

                        if list(raw_packet[108:110])[0] == '\x06' and list(raw_packet[108:110])[1] == '\x01':
                            os = 'Windows 7 / Windows Server 2008 R2 (Windows 6.1)'

                        else:
                            os = None

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'announcement': announcement, 'mac': mac, 'ipv4': ipv4, 'os': os, 'protocol': 'Windows Browser Protocol'}})

                        else:

                            if 'os' not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'os':os})

                    elif browser_cmd[1] == '\x0c':

                        announcement = 'Domain/Workgroup Announcement (0x0c)'
                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        domain = ''.join(raw_packet[92:]).rsplit('\x00')[0].strip()
                        hostname = ''.join(raw_packet[118:]).rstrip('\x00')

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'announcement': announcement, 'mac': mac, 'ipv4': ipv4, 'domain': domain, 'protocol': 'Windows Browser Protocol'}})

                        else:
                            if 'domain' not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'domain': domain})

                        if domain not in self.keys['domains'].keys():
                            self.keys['domains'].update({domain:{'protocol': 'Windows Browser Protocol'}})


                    elif browser_cmd[1] == '\x0f':

                        announcement = 'Local Master Announcement (0x0f)'
                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        hostname = ''.join(raw_packet[92:]).rsplit('\x00')[0].strip()
                        comment = None
                        if raw_packet[118:] != ['\x00']:
                            comment = ''.join(raw_packet[118:]).strip()

                        if hostname not in self.keys['hosts'].keys():
                            self.keys['hosts'].update({hostname:{'announcement': announcement, 'mac': mac, 'ipv4': ipv4, 'comment': comment, 'protocol': 'Windows Browser Protocol'}})

                        else:
                            if comment not in self.keys['hosts'][hostname].keys():
                                self.keys['hosts'][hostname].update({'comment': comment})

        return self.keys

class LLDP:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(Ether) and packet[Ether].dst == "01:80:c2:00:00:0e":
                    mac = packet[Ether].src
                    raw_packet = list(str(packet[Raw]))
                    hostname = ''.join(raw_packet[53:]).rsplit('\x0c')[0].strip()
                    system_description = ''.join(raw_packet[71:]).rsplit('\x0e')[0].strip()
                    mgt_addr_split = list(raw_packet[131:135])
                    mgt_addr_list = []

                    for mgt in mgt_addr_split:
                        octet = int(mgt.encode('hex'), 16)
                        mgt_addr_list.append(str(octet))

                    mgt_ipv4 = '.'.join(mgt_addr_list)

                    if hostname not in self.keys['hosts'].keys():
                        self.keys['hosts'].update({hostname:{'mac': mac, 'fingerprints': system_description, 'management_ipv4': mgt_ipv4, 'protocol': 'LLDP'}})


        return self.keys

class BootStrap:

    def __init__(self, data, keys):

        self.data = data
        self.keys = keys

    def search(self):

        sessions = self.data.sessions()

        for session in sessions:

            for packet in sessions[session]:

                if packet.getlayer(IP) and packet.getlayer(BOOTP):
                    raw_packet = list(str(packet[BOOTP]))

                    if raw_packet[0] == '\x01':

                        if raw_packet[254:][0] == '\xc0':
                            hostname = ''.join(raw_packet[260:]).rsplit('Q')[0].strip()
                            fqdn = ''.join(raw_packet[270:]).replace('\x00', '^').split('^').pop().rsplit('<')[0].strip()

                        else:
                            hostname = ''.join(raw_packet[254:]).rsplit('<')[0].rsplit('Q')[0].strip()
                            fqdn = None

                        if hostname not in self.keys['hosts'].keys():
                            mac = packet[Ether].src
                            ipv4 = packet[IP].src

                            self.keys['hosts'].update({hostname:{'mac': mac, 'fqdn': fqdn, 'ipv4': ipv4, 'protocol': 'DHCPv4 Bootstrap Request'}})

                    else:

                        dhcp_id_list = []
                        router_list = []
                        dns_list = []
                        dns_addr_length = int(raw_packet[256].encode('hex'), 16)
                        dns_addr_count = dns_addr_length / 4

                        dhcp_srv_split = list(raw_packet[245:249])
                        router_split = list(raw_packet[251:255])
                        dns_split = list(raw_packet[257:(257 + dns_addr_length)])
                        dns_count = 0

                        for dhcp in dhcp_srv_split:
                            octet = int(dhcp.encode('hex'), 16)
                            dhcp_id_list.append(str(octet))

                        for router in router_split:
                            octet = int(router.encode('hex'), 16)
                            router_list.append(str(octet))

                        for dns in dns_split:
                            octet = int(dns.encode('hex'), 16)
                            dns_list.append(str(octet))
                            dns_count += 1

                            if dns_count == (dns_addr_length / dns_addr_count):
                                dns_list.append(',')

                        dhcp_srv_id = '.'.join(dhcp_id_list)
                        router_addr = '.'.join(router_list)
                        dns_addr_chars = '.'.join(dns_list).lstrip('.').rstrip('.')
                        dns_addrs = sorted(list(set(dns_addr_chars.split('.,.'))))

                        mac = packet[Ether].src
                        ipv4 = packet[IP].src
                        hostname = 'Router-{}'.format(ipv4)

                        self.keys['hosts'].update({hostname:{'mac': mac, 'router': router_addr, 'dhcp': dhcp_srv_id, 'dns': dns_addrs, 'ipv4': ipv4, 'protocol': 'DHCPv4 Bootstrap Acknowledgment'}})

        return self.keys

def pcap_traffic_summary(pcap_buf):

    pass

def create_report(rname, rkeys, quiet=False):

    hostlist = []
    domlist = []

    hostjson = rkeys['hosts']
    domjson = rkeys['domains']

    hosts = sorted(list(set(hostjson.keys())))
    doms = sorted(list(set(domjson.keys())))

    print ''

    domcomstr = '''

    print '-' * 100
    print 'Domain Names'
    print '-' * 100

    for dom in doms:

        if not quiet:
            print dom.upper()

        domlist.append(dom)

        domdatajson = domjson[dom]
        dom_data_keys = domdatajson.keys()

        for dom_data_key in dom_data_keys:

            if not quiet:
                print '  - {} {}'.format(dom_data_key.upper(), domdatajson[dom_data_key])

        print ''

    print '-' * 100
'''

    print '-' * 100
    print 'Net-Recon Results'
    print '-' * 100
    for host in hosts:

        if not quiet:
            print host.upper()

        hostlist.append(host)

        hostdatajson = hostjson[host]
        host_data_keys = sorted(list(set(hostdatajson.keys())))

        for host_data_key in host_data_keys:
            host_data_val = hostdatajson[host_data_key]
            host_data_val_type = str(type(host_data_val)).split()[1].rstrip('>').lstrip("'").rstrip("'")

            if host_data_val_type == 'list':
                host_data_val = ', '.join(host_data_val)

            if not quiet:
                print '  - {0:15} {1:10}'.format(host_data_key.upper(), host_data_val)

        print ''

    print ''
    print '[*] Done! Report written to outfile: {}'.format(rname)

def main():

    parser = ArgumentParser(description='A tool for parsing network/Active Directory information from packet captures')

    parser.add_argument('--pcap', help='Packet capture to read from')
    parser.add_argument('--quiet', action='store_true', default=False, help='Collect information from PCAP file, save to a report and exit without output.')
    parser.add_argument('--report', help='Create a report of discovered information to a specified output filename')

    args = parser.parse_args()

    pcap = args.pcap
    quiet = args.quiet
    report = args.report

    if pcap:
        recon_keys = {'hosts':{}, 'domains':{}}

        print '[*] Reading PCAP file: {}...\n'.format(pcap)
        pcap_buf = rdpcap(pcap)

        print '  - Searching for LLDP information...'
        lldp_info = LLDP(pcap_buf, recon_keys).search()

        print '  - Searching for DHCP information...'
        dhcp_info = BootStrap(pcap_buf, recon_keys).search()

        print '  - Searching for MDNS information...'
        mdns_info = MDNS(pcap_buf, recon_keys).search()

        print '  - Searching for Windows Browser information...'
        win_browse_info = WinBrowser(pcap_buf, recon_keys).search()


        if report:
            create_report(report, win_browse_info, quiet=quiet)

if __name__ == '__main__':

    banner()
    main()


