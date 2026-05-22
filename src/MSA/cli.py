"""Console script for microservice_attack_simulation."""

import typer
from rich.console import Console

from MSA import utils

app = typer.Typer()
console = Console()


@app.command()
def main() -> None:
    """Console script for microservice_attack_simulation."""
    console.print("Replace this message by putting your code into microservice_attack_simulation.cli.main")
    console.print("See Typer documentation at https://typer.tiangolo.com/")
    utils.do_something_useful()


if __name__ == "__main__":
    app()
