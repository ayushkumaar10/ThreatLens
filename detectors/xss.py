"""
detectors/xss.py

Detects Cross-Site Scripting (XSS) attempts in HTTP traffic.
"""

from detectors.base_detector import BaseDetector


class XSSDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="Cross-Site Scripting",
            severity="Medium"
        )

    def detect(self, packets):

        findings = []
        reported = set()

        signatures = [
            "<script",
            "</script>",
            "javascript:",
            "alert(",
            "prompt(",
            "confirm(",
            "document.cookie",
            "onerror=",
            "onload=",
            "onmouseover=",
            "<iframe",
            "<svg",
            "<img",
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
                                f"Possible XSS detected ({signature})"
                            )
                        )

                    break

        return findings
