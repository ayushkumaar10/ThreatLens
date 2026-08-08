"""
detectors/traversal.py

Detects Directory Traversal attempts.
"""

from detectors.base_detector import BaseDetector


class TraversalDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="Directory Traversal",
            severity="High"
        )

    def detect(self, packets):

        findings = []
        reported = set()

        signatures = [
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

            for signature in signatures:

                if signature in request_line:

                    src, dst = self.get_hosts(packet)

                    key = (
                        src,
                        dst,
                        request_line
                    )

                    if key not in reported:

                        reported.add(key)

                        findings.append(
                            self.create_finding(
                                src,
                                dst,
                                f"Possible Directory Traversal detected ({signature})"
                            )
                        )

                    break

        return findings
