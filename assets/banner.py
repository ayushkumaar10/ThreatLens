from rich.console import Console

console = Console()


def show_banner():
    console.print(
        r"""
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
                    L E N S
""",
        style="bold red",
    )

    console.print("[bold cyan]Network Threat Analyzer[/bold cyan]")
    console.print("[green]Scan • Detect • Analyze[/green]")
