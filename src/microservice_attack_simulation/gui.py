# tkinter gui rikam # generets ar claude.ai

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import json
from pathlib import Path
from datetime import datetime, timezone

from microservice_attack_simulation.core.config import load_scenario
from microservice_attack_simulation.connectors.http_connector import HTTPConnector
from microservice_attack_simulation.scenarios.auth.jwt_manipulation import JwtManipulationScenario

SCENARIO_REGISTRY = {
    "JWT": JwtManipulationScenario,
}

class AttackSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Microservice Attack Simulator")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#4fc3f7")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Run.TButton", font=("Segoe UI", 12, "bold"), padding=10)
        style.configure("TCombobox", font=("Segoe UI", 10))
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        self._build_ui()

    def _build_ui(self):
        # Virsraksts
        header = ttk.Label(self.root, text="🛡️ Microservice Attack Simulator", style="Header.TLabel")
        header.pack(pady=(15, 5))

        subtitle = ttk.Label(self.root, text="Uzbrukumu imitācijas ietvars mikropakalpju drošības testēšanai")
        subtitle.pack(pady=(0, 10))

        # Konfigurācijas rāmis
        config_frame = ttk.LabelFrame(self.root, text="Konfigurācija", padding=10)
        config_frame.pack(fill="x", padx=15, pady=5)

        # Scenārija izvēle
        ttk.Label(config_frame, text="Scenārijs:").grid(row=0, column=0, sticky="w", padx=5)
        self.scenario_var = tk.StringVar()
        self.scenario_combo = ttk.Combobox(config_frame, textvariable=self.scenario_var, width=40, state="readonly")
        self.scenario_combo.grid(row=0, column=1, padx=5, pady=3)
        self._load_scenarios()

        # Mērķa URL
        ttk.Label(config_frame, text="Mērķa URL:").grid(row=1, column=0, sticky="w", padx=5)
        self.url_var = tk.StringVar(value="http://localhost:8080")
        ttk.Entry(config_frame, textvariable=self.url_var, width=43).grid(row=1, column=1, padx=5, pady=3)

        # Palaist poga
        self.run_btn = ttk.Button(config_frame, text="▶  Palaist scenāriju", style="Run.TButton", command=self._run_scenario)
        self.run_btn.grid(row=0, column=2, rowspan=2, padx=15, pady=3)

        # Rezultātu tabula
        table_frame = ttk.LabelFrame(self.root, text="Rezultāti", padding=10)
        table_frame.pack(fill="both", expand=True, padx=15, pady=5)

        columns = ("name", "description", "code", "blocked")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        self.tree.heading("name", text="Apakšscenārijs")
        self.tree.heading("description", text="Apraksts")
        self.tree.heading("code", text="Kods")
        self.tree.heading("blocked", text="Bloķēts?")
        self.tree.column("name", width=150)
        self.tree.column("description", width=350)
        self.tree.column("code", width=80, anchor="center")
        self.tree.column("blocked", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True)

        # Kopsavilkuma rāmis
        summary_frame = ttk.LabelFrame(self.root, text="Kopsavilkums", padding=10)
        summary_frame.pack(fill="x", padx=15, pady=5)

        self.time_var = tk.StringVar(value="—")
        self.expected_var = tk.StringVar(value="—")
        self.actual_var = tk.StringVar(value="—")
        self.match_var = tk.StringVar(value="—")

        labels = [("Izpildes laiks:", self.time_var), ("Sagaidāmais:", self.expected_var),
                  ("Faktiskais:", self.actual_var), ("Atbilstība:", self.match_var)]
        for i, (label, var) in enumerate(labels):
            ttk.Label(summary_frame, text=label, font=("Segoe UI", 10, "bold")).grid(row=0, column=i*2, padx=5)
            ttk.Label(summary_frame, textvariable=var).grid(row=0, column=i*2+1, padx=(0, 20))

        # Logs
        log_frame = ttk.LabelFrame(self.root, text="Logs", padding=5)
        log_frame.pack(fill="x", padx=15, pady=(5, 15))

        self.log_text = scrolledtext.ScrolledText(log_frame, height=5, bg="#2d2d2d", fg="#00ff00",
                                                   font=("Consolas", 9), state="disabled")
        self.log_text.pack(fill="x")

    def _load_scenarios(self):
        scenario_dir = Path("config/scenarios")
        files = list(scenario_dir.glob("*.yaml")) if scenario_dir.exists() else []
        self.scenario_files = {f.stem.replace("_", " ").title(): f for f in files}
        self.scenario_combo["values"] = list(self.scenario_files.keys())
        if self.scenario_files:
            self.scenario_combo.current(0)

    def _log(self, message):
        self.log_text.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _run_scenario(self):
        # Notīra iepriekšējos rezultātus
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.time_var.set("—")
        self.expected_var.set("—")
        self.actual_var.set("—")
        self.match_var.set("—")

        self.run_btn.configure(state="disabled")
        threading.Thread(target=self._execute, daemon=True).start()

    def _execute(self):
        try:
            # 1. Konfigurācija
            selected = self.scenario_var.get()
            path = self.scenario_files.get(selected)
            if not path:
                self._log("❌ Nav izvēlēts scenārijs")
                return

            self._log(f"📂 Ielādē: {path}")
            config = load_scenario(path)
            config.target_service = self.url_var.get()
            self._log(f"   Scenārijs: {config.name} | Mehānisms: {config.target_mechanism}")

            scenario_class = SCENARIO_REGISTRY.get(config.target_mechanism)
            if not scenario_class:
                self._log(f"❌ Nezināms mehānisms: {config.target_mechanism}")
                return

            # 2. Savienojums
            self._log(f"🔌 Savienojums ar {config.target_service}...")
            connector = HTTPConnector(timeout=10)
            connection = connector.check_connection(config.target_service)

            if not connection.success:
                self._log(f"❌ Savienojums neizdevās: {connection.error}")
                self._log("   Pārbaudi vai Docker vide ir palaista!")
                return

            self._log(f"✅ Savienojums izveidots ({connection.response_time_ms}ms)")

            # 3. Uzbrukums
            self._log("⚔️ Izpilda uzbrukumu...")
            scenario = scenario_class(config, connector)
            result = scenario.run()

            # 4. Rezultāti tabulā
            if result.details and "sub_scenarios" in result.details:
                for sub in result.details["sub_scenarios"]:
                    blocked = sub.get("blocked", False)
                    self.tree.insert("", "end", values=(
                        sub.get("name", "?"),
                        sub.get("description", ""),
                        sub.get("response_code", "?"),
                        "✅ Jā" if blocked else "❌ Nē",
                    ))

            # 5. Kopsavilkums
            exec_time = round(result.execution_time * 1000, 2)
            match = result.actual_result == result.expected_result

            self.time_var.set(f"{exec_time}ms")
            self.expected_var.set(result.expected_result)
            self.actual_var.set(result.actual_result)
            self.match_var.set("✅ Atbilst" if match else "⚠️ Neatbilst")

            self._log(f"📊 Izpildes laiks: {exec_time}ms | Rezultāts: {result.actual_result}")
            self._log(f"{'✅ Atbilst sagaidāmajam' if match else '⚠️ Neatbilst sagaidāmajam'}")

            connector.close()

        except Exception as e:
            self._log(f"❌ Kļūda: {e}")
        finally:
            self.run_btn.configure(state="normal")

def main():
    root = tk.Tk()
    app = AttackSimulatorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()