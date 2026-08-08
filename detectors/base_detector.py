"""
Base class for all ThreatLens detectors.
"""

from urllib.parse import unquote

from scapy.layers.inet import IP
from scapy.packet import Raw


class BaseDetector:

    def __init__(self, name, severity):
        self.name = name
        self.severity = severity

    def get_payloads(self, packet):
        """
        Returns raw and URL-decoded payloads.
        """

        if Raw not in packet:
            return None

        try:
            raw = bytes(packet[Raw]).decode(
                errors="ignore"
            ).lower()

            decoded = unquote(raw).replace("+", " ")

            return {
                "raw": raw,
                "decoded": decoded
            }

        except Exception:
            return None

    def get_request_line(self, packet):
        """
        Returns the first HTTP request line
        (GET /..., POST /...) or None.
        """

        payloads = self.get_payloads(packet)

        if payloads is None:
            return None

        decoded = payloads["decoded"]

        if not (
            decoded.startswith("get ") or
            decoded.startswith("post ")
        ):
            return None

        return decoded.split("\n", 1)[0]

    def get_hosts(self, packet):
        """
        Returns source and destination IP addresses.
        """

        if IP in packet:
            return packet[IP].src, packet[IP].dst

        return "Unknown", "Unknown"

    def create_finding(self, src, dst, message):
        """
        Creates a standardized finding dictionary.
        """

        return {
            "detector": self.name,
            "severity": self.severity,
            "source": src,
            "destination": dst,
            "message": message,
        }

    def detect(self, packets):
        raise NotImplementedError
