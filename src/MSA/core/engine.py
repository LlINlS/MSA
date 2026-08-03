# scenario izpildes engine
# python -m microservice_attack_simulation.core.engine --scenario config/scenarios/jwt_manipulation.yaml

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.table import Table
from MSA.core.config import load_scenario
from MSA.connectors.http_connector import HTTPConnector
from MSA.scenarios.auth.jwt_manipulation import JwtManipulationScenario
from MSA.scenarios.availability.dos_attack import DosAttackScenario
from MSA.scenarios.injection.sql_injection import SqlInjectionScenario
from MSA.scenarios.auth.tls_downgrade import TlsDowngradeScenario
from MSA.scenarios.config.secret_leak import SecretExposureScenario

console = Console()

SCENARIO_REGISTRY = {
    "JWT": JwtManipulationScenario,
    "DoS": DosAttackScenario,
    "InputValidation": SqlInjectionScenario,
    "TLS": TlsDowngradeScenario,
    "SecretManagement": SecretExposureScenario,
}

def run_scenario(scenario_path, output_dir="results", mode="protected"):
    # 1. Konfigurācijas ielāde
    console.print(f"\n[bold]1. Ielādē konfigurāciju:[/bold] {scenario_path}")
    config = load_scenario(scenario_path)
    console.print(f"   Scenārijs: {config.name}")
    console.print(f"   Draudu kategorija: {config.threat_category}")
    console.print(f"   Mērķa mehānisms: {config.target_mechanism}")
    scenario_class = SCENARIO_REGISTRY.get(config.target_mechanism)
    if not scenario_class:
        console.print(f"[red]Nezināms mehānisms: {config.target_mechanism}[/red]")
        sys.exit(1)

    # 2. Savienojuma izveide
    connector = HTTPConnector(timeout=10)
    console.print(f"\n[bold]2. Savienojuma izveide:[/bold] {config.target_service}")
    connection = connector.check_connection(config.target_service)
    if connection.success:
        console.print(f"   [green]✓ Savienojums izveidots ({connection.response_time_ms}ms)[/green]")
    else:
        console.print(f"   [red]✗ Savienojums neizdevās: {connection.error}[/red]")
        return {"error": "connection_failed"}

    # 3. Uzbrukuma izpilde
    console.print(f"\n[bold]3. Uzbrukuma izpilde:[/bold]")
    scenario = scenario_class(config, connector)
    result = scenario.run()
    result.mode = mode

    # 4. Rezultātu attēlošana
    console.print(f"\n[bold]4. Rezultāti:[/bold]")
    table = Table(title=f"Scenārijs: {config.name}")
    table.add_column("Apakšscenārijs", style="bold")
    table.add_column("Apraksts")
    table.add_column("Kods")
    table.add_column("Bloķēts?")

    if result.details and "sub_scenarios" in result.details:
        for sub in result.details["sub_scenarios"]:
            blocked = sub.get("blocked", False)
            status = "[green]✓ Jā[/green]" if blocked else "[red]✗ Nē[/red]"
            table.add_row(sub.get("name", "?"), sub.get("description", ""), str(sub.get("response_code", "?")), status)
    console.print(table)

    # 5. Kopsavilkums
    console.print(f"\n[bold]5. Kopsavilkums:[/bold]")
    console.print(f"   Izpildes laiks: {result.execution_time}ms")
    console.print(f"   Sagaidāmais: {result.expected_result}")
    console.print(f"   Faktiskais: {result.actual_result}")
    match = result.actual_result == result.expected_result
    console.print(f"   [green]✓ Atbilst[/green]" if match else f"   [yellow]⚠ Neatbilst[/yellow]")

    # 6. Saglabā JSON (atskaite)
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = output_path / f"{config.id}_{timestamp}.json"
    report = {
        "scenario_id": config.id, "scenario_name": config.name,
        "threat_category": config.threat_category, "execution_time": result.execution_time,
        "expected_result": result.expected_result, "actual_result": result.actual_result,
        "accurate": match, "details": result.details, "timestamp": timestamp,
        "mode": mode, "completed": result.completed,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    console.print(f"\n   Atskaite: {filename}")

    connector.close()
    return report

def main():
    parser = argparse.ArgumentParser(description="Uzbrukumu imitācijas dzinējs")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--output", default="results")
    parser.add_argument("--mode", default="protected", choices=["protected", "unprotected"])
    args = parser.parse_args()
    run_scenario(args.scenario, args.output, args.mode)

if __name__ == "__main__":
    main()