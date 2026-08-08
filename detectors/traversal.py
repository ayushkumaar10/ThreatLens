"""
detectors/traversal.py

Detects Directory Traversal attempts.
"""

from scapy.layers.inet import IP
from scapy.packet import Raw

from detectors.base_detector import BaseDetector


class TraversalDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="Directory Traversal",
            severity="High"
        )

    def detect(self, packets):

        findings = []

        payloads = [
            "../",
            "..\\",
            "%2e%2e%2f",
            "%2e%2e\\",
            "..%2f",
            "..%5c",
            "/etc/passwd",
            "/etc/shadow",
            "boot.ini",
            "win.ini",
        ]

        for packet in packets:

            request_line = self.get_request_line(packet)

            if request_line is None:
                continue

            for signature in payloads:

                if signature.lower() in request_line:

                    src, dst = self.get_hosts(packet)

                    findings.append(
                        self.create_finding(
                            src,
                            dst,
                            f"Possible Directory Traversal detected ({signature})"
                        )
                    )

                    break

        return findings
