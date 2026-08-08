"""
detectors/sqli.py

Detects basic SQL Injection attempts in HTTP traffic.
"""

from detectors.base_detector import BaseDetector


class SQLiDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="SQL Injection",
            severity="High"
        )

    def detect(self, packets):

        findings = []
        reported = set()

        signatures = [
            "' or 1=1",
            '" or 1=1',
            "union select",
            "union all select",
            "information_schema",
            "xp_cmdshell",
            "load_file(",
            "into outfile",
            "sleep(",
            "benchmark(",
            "waitfor delay",
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
                                f"Possible SQL Injection detected ({signature})"
                            )
                        )

                    break

        return findings
