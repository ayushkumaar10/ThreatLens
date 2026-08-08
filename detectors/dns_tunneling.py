"""
detectors/dns_tunneling.py

Detects possible DNS tunneling activity.
"""

import re

from scapy.layers.dns import DNS, DNSQR

from detectors.base_detector import BaseDetector


class DNSTunnelingDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="DNS Tunneling",
            severity="High"
        )

    def detect(self, packets):

        findings = []
        reported = set()

        for packet in packets:

            if DNS not in packet:
                continue

            if DNSQR not in packet:
                continue

            try:
                query = packet[DNSQR].qname

                if isinstance(query, bytes):
                    query = query.decode(
                        errors="ignore"
                    )

                query = query.rstrip(".").lower()

            except Exception:
                continue

            if not query:
                continue

            labels = query.split(".")

            suspicious = False
            reason = None

            # Very long DNS query
            if len(query) > 100:

                suspicious = True
                reason = "long DNS query"

            # Very long individual label
            elif any(len(label) > 50 for label in labels):

                suspicious = True
                reason = "long DNS label"

            # Look for encoded-looking subdomains
            elif len(labels) >= 3:

                subdomain = ".".join(labels[:-2])

                if len(subdomain) >= 30:

                    encoded_chars = len(
                        re.findall(
                            r"[a-f0-9]",
                            subdomain
                        )
                    )

                    if (
                        len(subdomain) > 0
                        and encoded_chars / len(subdomain) > 0.75
                    ):

                        suspicious = True
                        reason = "encoded-looking DNS data"

            if not suspicious:
                continue

            src, dst = self.get_hosts(packet)

            key = (
                src,
                dst,
                query
            )

            if key in reported:
                continue

            reported.add(key)

            findings.append(
                self.create_finding(
                    src,
                    dst,
                    f"Possible DNS Tunneling detected ({reason}): {query}"
                )
            )

        return findings

