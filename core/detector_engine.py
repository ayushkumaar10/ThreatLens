"""
core/detector_engine.py

Runs all available detectors.
"""

from detectors.portscan import PortScanDetector
from detectors.sqli import SQLiDetector
from detectors.xss import XSSDetector
from detectors.traversal import TraversalDetector
from detectors.command_injection import CommandInjectionDetector
from detectors.suspicious_useragent import SuspiciousUserAgentDetector
from detectors.dns_tunneling import DNSTunnelingDetector

class DetectorEngine:

    def __init__(self):

        self.detectors = [
            PortScanDetector(),
            SQLiDetector(),
            XSSDetector(),
            TraversalDetector(),
            CommandInjectionDetector(),
            SuspiciousUserAgentDetector(),
            DNSTunnelingDetector(),
        ]

    def run(self, packets):

        findings = []

        for detector in self.detectors:
            findings.extend(
                detector.detect(packets)
            )

        return findings
