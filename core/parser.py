from pathlib import Path
from scapy.all import rdpcap


class PacketParser:

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)

    def load_packets(self):

        if not self.file_path.exists():
            raise FileNotFoundError(
                f"PCAP file not found: {self.file_path}"
            )

        return rdpcap(str(self.file_path))
