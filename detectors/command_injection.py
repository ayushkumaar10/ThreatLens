"""
detectors/command_injection.py

Detects basic Command Injection attempts in HTTP traffic.
"""

from detectors.base_detector import BaseDetector


class CommandInjectionDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="Command Injection",
            severity="Critical"
        )

    def detect(self, packets):

        findings = []
        reported = set()

        signatures = [
            "whoami",
            "cat /etc/passwd",
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
            "powershell",
            "$(",
        ]

        for packet in packets:

            packet_payloads = self.get_payloads(packet)

            if packet_payloads is None:
                continue

            decoded_payload = packet_payloads["decoded"]

            # Only inspect HTTP requests
            if not (
                decoded_payload.startswith("get ") or
                decoded_payload.startswith("post ")
            ):
                continue

            for signature in signatures:

                if signature.lower() in decoded_payload:

                    src, dst = self.get_hosts(packet)

                    key = (
                        src,
                        dst,
                        decoded_payload
                    )

                    if key not in reported:

                        reported.add(key)

                        findings.append(
                            self.create_finding(
                                src,
                                dst,
                                f"Possible Command Injection detected ({signature})"
                            )
                        )

                    break

        return findings
