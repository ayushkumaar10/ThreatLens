"""
core/statistics.py

Collects statistics from packets.
"""

from collections import Counter

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP


class Statistics:

    def __init__(self, packets):
        self.packets = packets

    def packet_count(self):
        return len(self.packets)

    def protocol_statistics(self):

        protocols = Counter()

        for packet in self.packets:

            if ARP in packet:
                protocols["ARP"] += 1

            if ICMP in packet:
                protocols["ICMP"] += 1

            if DNS in packet:
                protocols["DNS"] += 1

            if TCP in packet:
                protocols["TCP"] += 1

                sport = packet[TCP].sport
                dport = packet[TCP].dport

                if sport in (80, 8080) or dport in (80, 8080):
                    protocols["HTTP"] += 1

                elif sport == 443 or dport == 443:
                    protocols["HTTPS"] += 1

            elif UDP in packet:
                protocols["UDP"] += 1

        return protocols

    def top_source_ips(self, limit=5):

        sources = Counter()

        for packet in self.packets:

            if IP in packet:
                sources[packet[IP].src] += 1

        return sources.most_common(limit)

    def top_destination_ips(self, limit=5):

        destinations = Counter()

        for packet in self.packets:

            if IP in packet:
                destinations[packet[IP].dst] += 1

        return destinations.most_common(limit)

    def top_destination_ports(self, limit=5):

        ports = Counter()

        for packet in self.packets:

            if TCP in packet:
                ports[packet[TCP].dport] += 1

            elif UDP in packet:
                ports[packet[UDP].dport] += 1

        return ports.most_common(limit)

    def unique_hosts(self):

        hosts = set()

        for packet in self.packets:

            if IP in packet:
                hosts.add(packet[IP].src)
                hosts.add(packet[IP].dst)

        return len(hosts)
