# metrikas modulis, atbilstosi novertesanas kriterijiem

import time
from dataclasses import dataclass, field

# K_k = 6:
IDENTIFIED_THREAT_CATEGORIES = {
    "Autentifikacijas", "Autorizacijas", "Timekla konteksta",
    "Lietojuma konteksta", "Konfiguracijas", "Pieejamibas",
}

CONTROL_TECHNIQUES = {"safe_input", "service_availability"}


@dataclass
class MetricScenarios:
    scenario_id: str = ""
    scenario_name: str = ""
    threat_category: str = ""
    mode: str = "protected"                 # "protected" | "unprotected" (zinamais patiesais stavoklis)
    execution_time: float = 0.0
    success: bool = field(default=False)    # vai uzbrukuma soli tika izpilditi
    completed: bool = field(default=True)   # vai izpilde pabeigta bez kludas, stabilitatei
    expected_result: str = field(default="")
    actual_result: str = field(default="")
    response_code: int | None = None
    details: dict = field(default_factory=dict)

    @property
    def is_accurate(self) -> bool:
        return self.success and self.expected_result == self.actual_result

    @property
    def sub_scenarios(self) -> list[dict]:
        return self.details.get("sub_scenarios", [])

    def classify(self) -> dict:
        tp = fp = 0
        attack_cases = 0
        controls_ok = controls_fail = 0
        vuln_present = (self.mode == "unprotected")
        for sub in self.sub_scenarios:
            name = sub.get("name", "")
            blocked = bool(sub.get("blocked", False))
            is_control = bool(sub.get("is_control", name in CONTROL_TECHNIQUES))
            if is_control:
                if blocked:
                    controls_fail += 1
                else:
                    controls_ok += 1
                continue
            attack_cases += 1                   
            vuln_detected = not blocked
            if vuln_present and vuln_detected:
                tp += 1                         # patiesi pozitivs
            elif (not vuln_present) and vuln_detected:
                fp += 1                         # kludaini pozitivs
        return {
            "tp": tp, "fp": fp,
            "controls_ok": controls_ok, "controls_fail": controls_fail,
            "attack_cases": attack_cases,
            "total_cases": attack_cases + controls_ok + controls_fail,
        }


class MetricsCollector:
    def __init__(self):
        self._results: list[MetricScenarios] = []
        self._timer_start: float | None = None

    def start_timer(self):
        self._timer_start = time.time()

    def stop_timer(self) -> float:
        if self._timer_start is None:
            raise RuntimeError("Timer has not been started.")
        elapsed = time.time() - self._timer_start
        self._timer_start = None
        return elapsed

    def record(self, metric: MetricScenarios):
        self._results.append(metric)

    @property
    def total_scenarios(self) -> int:
        return len(self._results)

    @property
    def avg_elapsed_time(self) -> float:
        # (3.2): videjais izpildes laiks
        if not self._results:
            return 0.0
        return sum(m.execution_time for m in self._results) / len(self._results)

    @property
    def imitated_categories(self) -> set[str]:
        cats: set[str] = set()
        for m in self._results:
            for c in str(m.threat_category).split("+"):
                c = c.strip()
                if c:
                    cats.add(c)
        return cats

    def coverage(self, total_categories: int = 6) -> float:
        # (3.3): parklajums
        return len(self.imitated_categories) / total_categories * 100

    @property
    def stability(self) -> float:
        # (3.5): stabilitate
        if not self._results:
            return 0.0
        completed = sum(1 for m in self._results if m.completed)
        return completed / len(self._results) * 100

    def confusion(self) -> dict:
        agg = {"tp": 0, "fp": 0,
               "controls_ok": 0, "controls_fail": 0,
               "attack_cases": 0, "total_cases": 0}
        for m in self._results:
            c = m.classify()
            for k in agg:
                agg[k] += c[k]
        return agg

    def false_positive_rate(self) -> float:
        # (3.4): kludaini pozitivo attiecība aizsargataja konfiguracija
        fp = total = 0
        for m in self._results:
            if m.mode != "protected":
                continue
            c = m.classify()
            fp += c["fp"]
            total += c["total_cases"]
        return (fp / total * 100) if total else 0.0

    def detection_rate(self) -> float:
        # papildmetrika == truePositive attiecība neaizsargataja konfiguracija
        tp = total = 0
        for m in self._results:
            if m.mode != "unprotected":
                continue
            c = m.classify()
            tp += c["tp"]
            total += c["attack_cases"]
        return (tp / total * 100) if total else 0.0

    def summary(self) -> dict:
        return {
            "total_scenarios": self.total_scenarios,
            "avg_elapsed_time_s": round(self.avg_elapsed_time, 4),
            "coverage_pct": round(self.coverage(), 1),
            "imitated_categories": sorted(self.imitated_categories),
            "false_positive_rate_pct": round(self.false_positive_rate(), 2),
            "detection_rate_pct": round(self.detection_rate(), 2),
            "stability_pct": round(self.stability, 1),
            "confusion": self.confusion(),
        }

    @property
    def results(self) -> list[MetricScenarios]:
        return self._results
