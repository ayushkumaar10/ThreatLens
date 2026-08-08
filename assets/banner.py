from rich.console import Console
from rich.text import Text

console = Console()


def show_banner():
    banner = Text(
        r"""
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝

              L E N S

        NETWORK THREAT ANALYZER
               V 2.0

        SCAN  •  DETECT  •  ANALYZE
""",
        style="bold red",
    )

    console.print(banner)
