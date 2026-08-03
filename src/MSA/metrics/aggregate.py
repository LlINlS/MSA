
import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev

from rich.console import Console
from rich.table import Table

try:
    from MSA.metrics.collector import CONTROL_TECHNIQUES
except Exception:
    CONTROL_TECHNIQUES = {"safe_input", "service_availability"}

console = Console()
TOTAL_CATEGORIES = 6


def classify_report(rep: dict) -> dict:
    """Klasifice viena izpildes rezultata (viena scenarija, viena rezima)
    panemienus tp/fp/tn/fn atbilstosi 3. nodalas klasifikacijai."""
    mode = rep.get("mode", "protected")
    vuln_present = (mode == "unprotected")
    tp = fp = tn = fn = c_ok = c_fail = 0
    subs = (rep.get("details") or {}).get("sub_scenarios", [])
    for sub in subs:
        name = sub.get("name", "")
        blocked = bool(sub.get("blocked", False))
        is_control = bool(sub.get("is_control", name in CONTROL_TECHNIQUES))
        if is_control:
            c_fail += 1 if blocked else 0
            c_ok += 0 if blocked else 1
            continue
        vuln_detected = not blocked
        if vuln_present and vuln_detected:
            tp += 1
        elif not vuln_present and vuln_detected:
            fp += 1
        elif vuln_present and not vuln_detected:
            fn += 1
        else:
            tn += 1
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, c_ok=c_ok, c_fail=c_fail,
                attack=tp + fp + tn + fn, total=tp + fp + tn + fn + c_ok + c_fail)


def load_reports(results_dir: str) -> list[dict]:
    reports = []
    for p in sorted(Path(results_dir).glob("*.json")):
        if p.name.startswith("_"):      # skip summary failus
            continue
        try:
            with open(p, encoding="utf-8") as f:
                rep = json.load(f)
            rep["_file"] = p.name
            rep.setdefault("mode", "protected")
            rep.setdefault("completed", True)
            reports.append(rep)
        except Exception as e:
            console.print(f"[yellow]Izlaists {p.name}: {e}[/yellow]")
    return reports


def categories_of(rep: dict) -> set[str]:
    import re
    raw = str(rep.get("threat_category", ""))
    parts = re.split(r"\s+un\s+|\+", raw)
    return {p.strip() for p in parts if p.strip()}

def per_config_table(reports: list[dict], mode: str):
    """Viena rezima tabula, ka darba 3.2. (aizsargata) / 3.3. (neaizsargata) tabula."""
    by_id: dict[str, list[dict]] = defaultdict(list)
    for r in reports:
        if r.get("mode") == mode:
            by_id[r.get("scenario_id", "?")].append(r)

    protected = (mode == "protected")
    virsr = "aizsargata konfiguracija" if protected else "neaizsargata konfiguracija"
    metric_col = "Kludaini poz., %" if protected else "Atklasana, %"
    table = Table(title=f"Scenariju izpildes rezultati ({virsr})")
    for col in ["Scenarija ID", "Draudu kategorija", "Atkart.",
                "Vid. laiks, s", "Std, s", metric_col, "Stabilitate, %"]:
        table.add_column(col, overflow="fold")

    tot_fp = tot_cases = tot_tp = tot_attack = 0
    tot_completed = tot_runs = 0
    times_all: list[float] = []
    for sid in sorted(by_id):
        reps = by_id[sid]
        times = [float(r.get("execution_time", 0.0)) for r in reps]
        conf = [classify_report(r) for r in reps]
        fp = sum(c["fp"] for c in conf)
        cases = sum(c["total"] for c in conf)
        tp = sum(c["tp"] for c in conf)
        attack = sum(c["attack"] for c in conf)
        completed = sum(1 for r in reps if r.get("completed", True))
        cat = ", ".join(sorted(categories_of(reps[0]))) if reps else "-"
        if protected:
            metric = f"{fp / cases * 100:.1f}" if cases else "-"
        else:
            metric = f"{tp / attack * 100:.1f}" if attack else "-"
        table.add_row(
            sid, cat, str(len(reps)),
            f"{mean(times):.3f}" if times else "-",
            f"{pstdev(times):.3f}" if len(times) > 1 else "0.000",
            metric, f"{completed / len(reps) * 100:.1f}" if reps else "-",
        )
        tot_fp += fp; tot_cases += cases; tot_tp += tp; tot_attack += attack
        tot_completed += completed; tot_runs += len(reps); times_all += times

    if protected:
        overall = f"{tot_fp / tot_cases * 100:.1f}" if tot_cases else "-"
    else:
        overall = f"{tot_tp / tot_attack * 100:.1f}" if tot_attack else "-"
    table.add_row(
        "KOPA", "6/6 kategorijas", str(tot_runs),
        f"{mean(times_all):.3f}" if times_all else "-", "",
        overall, f"{tot_completed / tot_runs * 100:.1f}" if tot_runs else "-",
        style="bold",
    )
    return table


def overall_summary(reports: list[dict], steps: int) -> dict:
    cats = set()
    for r in reports:
        cats |= categories_of(r)
    coverage = len(cats) / TOTAL_CATEGORIES * 100

    prot = [r for r in reports if r.get("mode") == "protected"]
    unpr = [r for r in reports if r.get("mode") == "unprotected"]
    fp = cases = 0
    for r in prot:
        c = classify_report(r)
        fp += c["fp"]; cases += c["total"]
    tp = attack = 0
    for r in unpr:
        c = classify_report(r)
        tp += c["tp"]; attack += c["attack"]

    completed = sum(1 for r in reports if r.get("completed", True))
    times = [float(r.get("execution_time", 0.0)) for r in reports]

    return {
        "runs_total": len(reports),
        "avg_time_s": round(mean(times), 4) if times else 0.0,
        "coverage_pct": round(coverage, 1),
        "coverage_ratio": f"{len(cats)}/{TOTAL_CATEGORIES}",
        "false_positive_rate_pct": round(fp / cases * 100, 2) if cases else 0.0,
        "detection_rate_pct": round(tp / attack * 100, 2) if attack else 0.0,
        "stability_pct": round(completed / len(reports) * 100, 1) if reports else 0.0,
        "integration_steps": steps,
    }


def comparison_table(summ: dict):
    """Salidzinajuma tabulas skelets (darba 3.4. tabula). OWASP ZAP / Burp Suite
    vertibas jaievada manuali pec atsevisku merijumu veiksanas ar tiem paskiem scenarijiem."""
    table = Table(title="Uzbrukumu imitacijas pieejas salidzinajums ar DAST rikiem")
    for col in ["Metrika", "Uzbrukumu imitacija", "OWASP ZAP", "Burp Suite"]:
        table.add_column(col, overflow="fold")
    table.add_row("Draudu kategoriju parklajums", f"{summ['coverage_ratio']} ({summ['coverage_pct']} %)", "[...]", "[...]")
    table.add_row("Vid. izpildes laiks, s", f"{summ['avg_time_s']}", "[...]", "[...]")
    table.add_row("Kludaini pozitivo attiecība, %", f"{summ['false_positive_rate_pct']}", "[...]", "[...]")
    table.add_row("Izpildes stabilitate, %", f"{summ['stability_pct']}", "[...]", "[...]")
    table.add_row("Konfiguracijas solu skaits", f"{summ['integration_steps']}", "[...]", "[...]")
    table.add_row("Automatizeta atkartojama izpilde", "Ja", "Daleji / manuali", "Daleji / manuali")
    return table


def main():
    parser = argparse.ArgumentParser(description="Apkopo uzbrukumu imitacijas rezultatus")
    parser.add_argument("--results", default="results", help="rezultatu mape")
    parser.add_argument("--steps", type=int, default=5,
                        help="integracijas solu skaits (N_s), fiksets manuali")
    args = parser.parse_args()

    reports = load_reports(args.results)
    if not reports:
        console.print(f"[red]Mape '{args.results}' nav atrasti rezultatu faili.[/red]")
        return

    console.print(f"[bold]Ieladeti {len(reports)} rezultatu faili no '{args.results}'.[/bold]\n")
    console.print(per_config_table(reports, "protected"))
    console.print()
    console.print(per_config_table(reports, "unprotected"))
    console.print()

    summ = overall_summary(reports, args.steps)
    console.print(comparison_table(summ))
    console.print()

    console.print("[bold]Kopsavilkums:[/bold]")
    console.print(f"  Parklajums:            {summ['coverage_ratio']} ({summ['coverage_pct']} %)")
    console.print(f"  Vid. izpildes laiks:   {summ['avg_time_s']} s")
    console.print(f"  Kludaini pozitivo:     {summ['false_positive_rate_pct']} %")
    console.print(f"  Atklasana (neaizsarg): {summ['detection_rate_pct']} %")
    console.print(f"  Stabilitate:           {summ['stability_pct']} %")
    console.print(f"  Integracijas soli:     {summ['integration_steps']}")

    out = Path(args.results) / "_summary.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summ, f, indent=2, ensure_ascii=False)
    console.print(f"\n[green]Apkopojums saglabats: {out}[/green]")


if __name__ == "__main__":
    main()
