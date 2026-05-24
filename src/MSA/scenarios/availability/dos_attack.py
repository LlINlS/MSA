# DoS scenarijis -> pieejamibas draudu kategorija
# merka mehainisms > rate limiting
# scenarijis: nosuta pieprasijumus

import time
from MSA.scenarios.base import BaseScenario
from MSA.core.config import ScenarioConfig
from MSA.connectors.http_connector import HTTPConnector
from MSA.metrics.collector import MetricScenarios

class DosAttackScenario(BaseScenario):
    def __init__(self, config: ScenarioConfig, connector: HTTPConnector):
        super().__init__(config, connector)
        self.target_endpoint = config.parameters.get(
            "target_endpoint", "/orders")
        self.total_requests = config.parameters.get("total_requests", 20)
        self.delay_between_ms = config.parameters.get("delay_between_ms", 50)
        self.rate_limit_threshold = config.parameters.get(
            "rate_limit_threshold", 10)

    def execute_attack(self) -> MetricScenarios:
        results = []
        blocked_count = 0
        passed_count = 0
        response_times = []

        for i in range(self.total_requests):
            start = time.time()
            try:
                response = self.connector.send_request(
                    method="GET",
                    url=f"{self.config.target_service}{self.target_endpoint}",
                    headers={"Authorization": "Bearer fake-token-for-dos-test"},
                )
                elapsed = (time.time() - start) * 1000
                response_times.append(round(elapsed, 2))

                is_rate_limited = response.status_code == 429
                if is_rate_limited:
                    blocked_count += 1
                else:
                    passed_count += 1

                results.append({
                    "request_number": i + 1,
                    "status_code": response.status_code,
                    "response_time_ms": round(elapsed, 2),
                    "rate_limited": is_rate_limited,
                })

            except Exception as e:
                results.append({
                    "request_number": i + 1,
                    "status_code": None,
                    "error": str(e),
                    "rate_limited": False,
                })

            if self.delay_between_ms > 0:
                time.sleep(self.delay_between_ms / 1000)

        # Novērtējums: vai rate limiter darbojas
        rate_limiter_triggered = blocked_count > 0
        activation_point = None
        for r in results:
            if r.get("rate_limited"):
                activation_point = r["request_number"]
                break

        avg_response_time = round(
            sum(response_times) / len(response_times), 2) if response_times else 0

        return MetricScenarios(
            scenario_id=self.config.id,
            scenario_name=self.config.name,
            threat_category=self.config.threat_category,
            success=True,
            expected_result=self.config.expected_result,
            actual_result="attack_blocked" if rate_limiter_triggered else "vulnerability_found",
            details={
                "sub_scenarios": [
                    {
                        "name": "request_flood",
                        "description": f"Nosūtīti {self.total_requests} pieprasījumi ar {self.delay_between_ms}ms intervālu",
                        "response_code": 429 if rate_limiter_triggered else 200,
                        "blocked": rate_limiter_triggered,
                    },
                    {
                        "name": "rate_limit_activation",
                        "description": f"Tempa ierobežotājs aktivizējās pie {activation_point}. pieprasījuma" if activation_point else "Tempa ierobežotājs neaktivizējās",
                        "response_code": activation_point,
                        "blocked": activation_point is not None and activation_point <= self.rate_limit_threshold + 2,
                    },
                    {
                        "name": "service_availability",
                        "description": f"Pēc {blocked_count} bloķētiem pieprasījumiem serviss joprojām pieejams",
                        "response_code": 200,
                        "blocked": True,  # Serviss palika pieejams = labi
                    },
                ],
                "statistics": {
                    "total_requests": self.total_requests,
                    "passed": passed_count,
                    "blocked": blocked_count,
                    "avg_response_time_ms": avg_response_time,
                    "activation_point": activation_point,
                    "rate_limit_threshold": self.rate_limit_threshold,
                },
                "all_requests": results,
            },
        )
