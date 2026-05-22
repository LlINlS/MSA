# metrikas modulis, atbilstosi novertesanas kriterijiem

import time
from dataclasses import dataclass, field 

@dataclass
class MetricScenarios:
    scenario_id: str
    scenario_name: str
    threat_category: str
    execution_time: float = 0.0
    success: bool = field(default=False)
    expected_result: str = field(default="")
    actual_result: str = field(default="")
    response_code: int | None = None
    details: dict = field(default_factory=dict)

    @property
    def is_accurate(self) -> bool:
        return self.success and self.expected_result == self.actual_result
    

class MetricsCollector:
    def __init__(self):
        self._results: list[MetricScenarios] = []
        self._timer_start: float | None = None

    def start_timer(self):
        self._timer_start = time.time()

    def stop_timer(self) -> float:
        if self._timer_start is None:
            raise RuntimeError("Timer has not been started." + str(0.0)) 
        elapsed_time = time.time() - self._timer_start
        self._timer_start = None
        return elapsed_time
    
    def record(self, metric: MetricScenarios):
        self._results.append(metric)

    @property
    def total_scenarios(self) -> int:
        return len(self._results)
    
    @property
    def accuracy(self) -> float:
        if not self._results:
            return 0.0
        accurate_count = sum(1 for metric in self._results if metric.is_accurate)
        return accurate_count / len(self._results) * 100
    
    @property
    def avg_elapsed_time(self) -> float:
        if not self._results:
            return 0.0
        return sum(metric.execution_time for metric in self._results) / len(self._results)
    
    @property
    def coverage(self) -> set[str]:
        return set(metric.threat_category for metric in self._results if metric.success)

    def summary(self) -> dict: 
        return {
            "total_scenarios": self.total_scenarios,
            "accuracy": self.accuracy,
            "avg_elapsed_time": self.avg_elapsed_time,
            "coverage": list(self.coverage),
            "coverage_ratio": len(self.coverage) / 6,
        }
    
    @property
    def results(self) -> list[MetricScenarios]:
        return self._results
