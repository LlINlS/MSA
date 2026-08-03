# gui msa rikam

from __future__ import annotations

import os
import json
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from MSA.connectors.http_connector import HTTPConnector
from MSA.core.config import ScenarioConfig, load_scenario
from MSA.scenarios.auth.jwt_manipulation import JwtManipulationScenario
from MSA.scenarios.availability.dos_attack import DosAttackScenario
from MSA.scenarios.injection.sql_injection import SqlInjectionScenario
from MSA.scenarios.auth.tls_downgrade import TlsDowngradeScenario
from MSA.scenarios.config.secret_leak import SecretExposureScenario

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = PROJECT_ROOT / "config" / "scenarios"
RESULTS_DIR = Path.cwd() / "results"

SCENARIO_REGISTRY = {
    "JWT": JwtManipulationScenario,
    "DoS": DosAttackScenario,
    "InputValidation": SqlInjectionScenario,
    "TLS": TlsDowngradeScenario,
    "SecretManagement": SecretExposureScenario,
}

def _read_mode_from_env():
    # lasa MSA_MODE no ta pasa test_environment/.env, ko izmanto docker
    here = Path(__file__).resolve()
    for base in [here.parent, *here.parents]:
        candidate = base / "test_environment" / ".env"
        if candidate.exists():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("MSA_MODE="):
                    return line.split("=", 1)[1].strip()
    return "protected"

class AttackSimulatorGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("MSA - Attack Simulator")
        self.root.minsize(650, 520)

        self._running = False
        self._last_report: dict | None = None
        self.scenario_files: dict[str, Path] = {}

        self._build_ui()
        self._load_scenarios()

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="Uzbrukumu imitācijas rīks",
            foreground="gray40",
        ).pack(anchor="w", pady=(0, 8))

        config = ttk.LabelFrame(main, text="Konfigurācija", padding=8)
        config.pack(fill="x", pady=(0, 8))

        ttk.Label(config, text="Scenārijs:").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=2)
        self.scenario_var = tk.StringVar()
        self.scenario_combo = ttk.Combobox(
            config, textvariable=self.scenario_var, width=42, state="readonly"
        )
        self.scenario_combo.grid(row=0, column=1, sticky="ew", pady=2)
        self.scenario_combo.bind("<<ComboboxSelected>>", self._on_scenario_selected)

        ttk.Label(config, text="Mērķa URL:").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=2)
        self.url_var = tk.StringVar(value="http://localhost:8080")
        ttk.Entry(config, textvariable=self.url_var, width=44).grid(row=1, column=1, sticky="ew", pady=2)

        ttk.Label(config, text="Timeout (s):").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=2)
        self.timeout_var = tk.StringVar(value="10")
        ttk.Spinbox(config, from_=1, to=120, textvariable=self.timeout_var, width=8).grid(
            row=2, column=1, sticky="w", pady=2
        )

        ttk.Label(config, text="Režīms:").grid(row=3, column=0, sticky="w", padx=(0, 6), pady=2)
        self.mode_var = tk.StringVar(value=_read_mode_from_env())
        ttk.Combobox(
            config, textvariable=self.mode_var,
            # state disabled, jo test environement .env nosaka vai pec _read_mode_from_env kads rezims
            values=["protected", "unprotected"], state="disabled", width=16, 
        ).grid(row=3, column=1, sticky="w", pady=2)

        self.meta_var = tk.StringVar(value="")
        ttk.Label(config, textvariable=self.meta_var, foreground="gray30").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(4, 0)
        )

        config.columnconfigure(1, weight=1)

        actions = ttk.Frame(main)
        actions.pack(fill="x", pady=(0, 8))

        self.test_btn = ttk.Button(actions, text="Pārbaudīt savienojumu", command=self._test_connection)
        self.test_btn.pack(side="left", padx=(0, 6))

        self.run_btn = ttk.Button(actions, text="Palaist scenāriju", command=self._run_scenario)
        self.run_btn.pack(side="left", padx=(0, 6))

        self.save_btn = ttk.Button(actions, text="Saglabāt atskaiti (JSON)", command=self._save_report, state="disabled")
        self.save_btn.pack(side="left")

        results = ttk.LabelFrame(main, text="Rezultāti", padding=8)
        results.pack(fill="both", expand=True, pady=(0, 8))

        columns = ("name", "description", "code", "blocked")
        self.tree = ttk.Treeview(results, columns=columns, show="headings", height=7)
        for col, title, width in (
            ("name", "Apakšscenārijs", 140),
            ("description", "Apraksts", 280),
            ("code", "HTTP kods", 80),
            ("blocked", "Bloķēts", 80),
        ):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="center" if col != "description" else "w")
        self.tree.pack(fill="both", expand=True)

        summary = ttk.LabelFrame(main, text="Kopsavilkums", padding=8)
        summary.pack(fill="x", pady=(0, 8))

        self.time_var = tk.StringVar(value="-")
        self.expected_var = tk.StringVar(value="-")
        self.actual_var = tk.StringVar(value="-")
        self.match_var = tk.StringVar(value="-")

        for col, (label, var) in enumerate(
            [
                ("Laiks:", self.time_var),
                ("Sagaidāmais:", self.expected_var),
                ("Faktiskais:", self.actual_var),
                ("Atbilstība:", self.match_var),
            ]
        ):
            ttk.Label(summary, text=label).grid(row=0, column=col * 2, sticky="w", padx=(0, 4))
            ttk.Label(summary, textvariable=var).grid(row=0, column=col * 2 + 1, sticky="w", padx=(0, 16))

        log_frame = ttk.LabelFrame(main, text="Logs", padding=4)
        log_frame.pack(fill="both", expand=False)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, font=("Consolas", 9), state="disabled")
        self.log_text.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Gatavs")
        ttk.Label(main, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", pady=(6, 0))

    def _load_scenarios(self) -> None:
        files = sorted(SCENARIO_DIR.glob("*.yaml")) if SCENARIO_DIR.exists() else []
        self.scenario_files = {f.stem.replace("_", " ").title(): f for f in files}
        self.scenario_combo["values"] = list(self.scenario_files.keys())
        if self.scenario_files:
            self.scenario_combo.current(0)
            self._on_scenario_selected()

    def _on_scenario_selected(self, _event: object | None = None) -> None:
        path = self.scenario_files.get(self.scenario_var.get())
        if not path:
            self.meta_var.set("")
            return
        try:
            config = load_scenario(path)
            self.url_var.set(config.target_service)
            self.meta_var.set(
                f"Kategorija: {config.threat_category}  |  Mehānisms: {config.target_mechanism}  |  ID: {config.id}"
            )
        except Exception as exc:
            self.meta_var.set(f"Nevar ielādēt konfigurāciju: {exc}")

    def _ui(self, fn) -> None:
        """Thread-safe UI atjauninājums."""
        self.root.after(0, fn)

    def _log(self, message: str) -> None:
        def write() -> None:
            self.log_text.configure(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert("end", f"[{ts}] {message}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self._ui(write)

    def _set_status(self, text: str) -> None:
        self._ui(lambda: self.status_var.set(text))

    def _set_busy(self, busy: bool) -> None:
        def update() -> None:
            state = "disabled" if busy else "normal"
            self._running = busy
            self.run_btn.configure(state=state)
            self.test_btn.configure(state=state)

        self._ui(update)

    def _parse_timeout(self) -> int | None:
        try:
            return max(1, int(self.timeout_var.get()))
        except ValueError:
            messagebox.showerror("Kļūda", "Timeout jābūt veselam skaitlim.")
            return None

    def _selected_config(self) -> ScenarioConfig | None:
        path = self.scenario_files.get(self.scenario_var.get())
        if not path:
            messagebox.showwarning("Scenārijs", "Izvēlies scenāriju.")
            return None
        config = load_scenario(path)
        config.target_service = self.url_var.get().strip()
        if not config.target_service:
            messagebox.showwarning("Mērķis", "Ievadi mērķa URL.")
            return None
        return config

    def _test_connection(self) -> None:
        if self._running:
            return
        timeout = self._parse_timeout()
        if timeout is None:
            return
        config = self._selected_config()
        if config is None:
            return

        self._set_busy(True)
        self._set_status("Pārbauda savienojumu...")

        def worker() -> None:
            try:
                self._log(f"Savienojums ar {config.target_service}...")
                connector = HTTPConnector(timeout=timeout)
                try:
                    conn = connector.check_connection(config.target_service)
                    if conn.success:
                        self._log(f"OK ({conn.response_time_ms} ms)")
                        self._set_status("Savienojums veiksmīgs")
                    else:
                        self._log(f"Neizdevās: {conn.error}")
                        self._set_status("Savienojums neizdevās")
                finally:
                    connector.close()
            except Exception as exc:
                self._log(f"Kļūda: {exc}")
                self._set_status("Kļūda")
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def _clear_results(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.time_var.set("-")
        self.expected_var.set("-")
        self.actual_var.set("-")
        self.match_var.set("-")
        self._last_report = None
        self.save_btn.configure(state="disabled")

    def _run_scenario(self) -> None:
        if self._running:
            return
        timeout = self._parse_timeout()
        if timeout is None:
            return

        config = self._selected_config()
        if config is None:
            return

        self._clear_results()
        self._set_busy(True)
        self._set_status("Izpilda scenāriju...")

        threading.Thread(target=lambda: self._execute(config, timeout), daemon=True).start()

    def _execute(self, config: ScenarioConfig, timeout: int) -> None:
        connector: HTTPConnector | None = None
        try:
            self._log(f"Ielādē: {config.name}")
            scenario_class = SCENARIO_REGISTRY.get(config.target_mechanism)
            if not scenario_class:
                self._log(f"Nezināms mehānisms: {config.target_mechanism}")
                return

            connector = HTTPConnector(timeout=timeout)
            self._log(f"Savienojums ar {config.target_service}...")
            connection = connector.check_connection(config.target_service)
            if not connection.success:
                self._log(f"Savienojums neizdevās: {connection.error}")
                self._set_status("Savienojums neizdevās")
                return

            self._log(f"Savienojums OK ({connection.response_time_ms} ms)")
            self._log("Izpilda uzbrukumu...")

            scenario = scenario_class(config, connector)
            result = scenario.run()

            def show_results() -> None:
                if result.details and "sub_scenarios" in result.details:
                    for sub in result.details["sub_scenarios"]:
                        blocked = sub.get("blocked", False)
                        self.tree.insert(
                            "",
                            "end",
                            values=(
                                sub.get("name", "?"),
                                sub.get("description", ""),
                                sub.get("response_code", "?"),
                                "Jā" if blocked else "Nē",
                            ),
                        )

                exec_ms = round(result.execution_time * 1000, 2)
                match = result.actual_result == result.expected_result
                self.time_var.set(f"{exec_ms} ms")
                self.expected_var.set(str(result.expected_result))
                self.actual_var.set(str(result.actual_result))
                self.match_var.set("Atbilst" if match else "Neatbilst")

                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                self._last_report = {
                    "scenario_id": config.id,
                    "scenario_name": config.name,
                    "threat_category": config.threat_category,
                    "target_service": config.target_service,
                    "execution_time_ms": exec_ms,
                    "expected_result": result.expected_result,
                    "actual_result": result.actual_result,
                    "accurate": match,
                    "details": result.details,
                    "timestamp": timestamp,
                    "mode": self.mode_var.get(),
                    "completed": result.completed,
                    "execution_time": result.execution_time,
                }
                self.save_btn.configure(state="normal")

            self._ui(show_results)
            self._log(f"Pabeigts: {result.actual_result} ({round(result.execution_time * 1000, 2)} ms)")
            self._set_status("Pabeigts" if result.actual_result == result.expected_result else "Pabeigts - neatbilst")

        except Exception as exc:
            self._log(f"Kļūda: {exc}")
            self._set_status("Kļūda")
        finally:
            if connector is not None:
                connector.close()
            self._set_busy(False)

    def _save_report(self) -> None:
        if not self._last_report:
            messagebox.showinfo("Atskaite", "Nav rezultātu, ko saglabāt.")
            return

        RESULTS_DIR.mkdir(exist_ok=True)
        scenario_id = self._last_report.get("scenario_id", "report")
        timestamp = self._last_report.get("timestamp", "unknown")
        path = RESULTS_DIR / f"{scenario_id}_{timestamp}.json"

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._last_report, fh, indent=2, ensure_ascii=False)

        self._log(f"Atskaite saglabāta: {path}")
        messagebox.showinfo("Atskaite", f"Saglabāts:\n{path}")


def main() -> None:
    root = tk.Tk()
    AttackSimulatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
