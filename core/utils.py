from rich.console import Console

console = Console()


def section(title):
    console.print(f"\n[bold cyan]{title}[/bold cyan]")
    console.print("[blue]" + "─" * len(title) + "[/blue]")


def info(message):
    console.print(f"[green][+][/green] {message}")


def error(message):
    console.print(f"[bold red][-][/bold red] {message}")
