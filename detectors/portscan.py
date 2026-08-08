"""
Port Scan Detector
"""

from collections import defaultdict

from scapy.layers.inet import IP, TCP

from detectors.base_detector import BaseDetector


class PortScanDetector(BaseDetector):

    PORT_THRESHOLD = 10

    def __init__(self):

        super().__init__(
            name="Port Scan",
            severity="HIGH"
        )

    def detect(self, packets):

        scanned_ports = defaultdict(set)

        findings = []

        for packet in packets:

            if IP in packet and TCP in packet:

                src = packet[IP].src
                dst = packet[IP].dst
                dport = packet[TCP].dport

                scanned_ports[(src, dst)].add(dport)

        for (src, dst), ports in scanned_ports.items():

            if len(ports) >= self.PORT_THRESHOLD:

                findings.append({
                    "detector": self.name,
                    "severity": self.severity,
                    "source": src,
                    "destination": dst,
                    "ports": sorted(list(ports)),
                    "message": f"Possible port scan detected ({len(ports)} ports)"
                })

        return findings
