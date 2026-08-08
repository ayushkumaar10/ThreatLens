"""
detectors/suspicious_useragent.py

Detects suspicious or automated HTTP User-Agent strings.
"""

from detectors.base_detector import BaseDetector


class SuspiciousUserAgentDetector(BaseDetector):

    def __init__(self):

        super().__init__(
            name="Suspicious User-Agent",
            severity="Low"
        )

    def detect(self, packets):

        findings = []
        reported = set()

        signatures = [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "gobuster",
            "dirbuster",
            "wpscan",
            "burpsuite",
            "zgrab",
            "nuclei",
            "hydra",
            "python-requests",
            "curl/",
            "wget/",
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

            # Look for the User-Agent header
            user_agent = None

            for line in decoded_payload.splitlines():

                if line.startswith("user-agent:"):

                    user_agent = line.split(
                        ":", 1
                    )[1].strip()

                    break

            if user_agent is None:
                continue

            for signature in signatures:

                if signature.lower() in user_agent.lower():

                    src, dst = self.get_hosts(packet)

                    key = (
                        src,
                        dst,
                        user_agent
                    )

                    if key not in reported:

                        reported.add(key)

                        findings.append(
                            self.create_finding(
                                src,
                                dst,
                                f"Suspicious User-Agent detected ({user_agent})"
                            )
                        )

                    break

        return findings
