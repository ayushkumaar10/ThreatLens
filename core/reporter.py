"""
core/reporter.py

Displays analysis results.
"""

from pathlib import Path
from rich.console import Console

console = Console()

PORT_NAMES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class Reporter:

    def display(
        self,
        findings,
        packet_count,
        pcap_file,
        detectors_run,
        protocols,
        top_sources,
        top_destinations,
        top_ports,
        unique_hosts,
    ):

        console.rule("[bold cyan]ThreatLens v2.0[/bold cyan]")

        console.print(f"[bold]PCAP File      :[/bold] {Path(pcap_file).name}")
        console.print(f"[bold]Packets Loaded :[/bold] {packet_count}")
        console.print(f"[bold]Detectors Run  :[/bold] {detectors_run}")

        # ---------------- Protocol Statistics ----------------

        console.rule("[bold]Protocol Statistics[/bold]")

        for protocol, count in protocols.items():
            console.print(f"{protocol:<10}: {count}")

        # ---------------- Network Statistics ----------------

        console.rule("[bold]Network Statistics[/bold]")

        console.print(f"Unique Hosts : {unique_hosts}")

        console.print("\nTop Source IPs")

        for ip, count in top_sources:
            console.print(f"  {ip:<18} {count}")

        console.print("\nTop Destination IPs")

        for ip, count in top_destinations:
            console.print(f"  {ip:<18} {count}")

        console.print("\nTop Destination Ports")

        for port, count in top_ports:

            service = PORT_NAMES.get(port, "Unknown")

            console.print(
                f"  {port:<6} {service:<18} {count}"
            )

        # ---------------- Threat Summary ----------------

        console.rule("[bold]Threat Summary[/bold]")

        if not findings:
            console.print("[green]✓ No threats detected.[/green]")
            return

        console.print(f"[bold red]Threats Found: {len(findings)}[/bold red]\n")

        for finding in findings:

            console.print(f"[bold yellow]Detector:[/bold yellow] {finding['detector']}")
            console.print(f"[bold red]Severity:[/bold red] {finding['severity']}")
            console.print(f"Source      : {finding['source']}")
            console.print(f"Destination : {finding['destination']}")
            console.print(f"Message     : {finding['message']}")

            if "ports" in finding:
                console.print(f"Ports       : {finding['ports']}")

            console.rule()
