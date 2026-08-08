"""
ThreatLens v2.0

Entry point for the application.
"""

import argparse

from core.parser import PacketParser
from core.analyzer import Analyzer
from core.reporter import Reporter
from core.statistics import Statistics

def main():

    parser = argparse.ArgumentParser(
        description="ThreatLens v2.0 - Network Threat Detection Framework"
    )

    parser.add_argument(
        "pcap",
        help="Path to the PCAP file"
    )

    args = parser.parse_args()

    packet_parser = PacketParser(args.pcap)

    packets = packet_parser.load_packets()
   
    statistics = Statistics(packets)
   
    analyzer = Analyzer(packets)

    findings = analyzer.analyze()

    protocols = statistics.protocol_statistics()

    top_sources = statistics.top_source_ips()

    top_destinations = statistics.top_destination_ips()

    top_ports = statistics.top_destination_ports()

    unique_hosts = statistics.unique_hosts()

    reporter = Reporter()

    reporter.display(
        findings=findings,
        packet_count=statistics.packet_count(),
        pcap_file=args.pcap,
        detectors_run=len(analyzer.engine.detectors),
        protocols=protocols,
        top_sources=top_sources,
        top_destinations=top_destinations,
        top_ports=top_ports,
        unique_hosts=unique_hosts
    )


if __name__ == "__main__":
    main()
