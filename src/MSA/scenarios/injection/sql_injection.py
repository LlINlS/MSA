# sql injection scenarijs
# merka mehanisms: input validation, parameterized queries
# scenarijis: nosuta pieprasijums ar SQL injekciju.

import time
from MSA.scenarios.base import BaseScenario
from MSA.core.config import ScenarioConfig
from MSA.connectors.http_connector import HTTPConnector
from MSA.metrics.collector import MetricScenarios


class SqlInjectionScenario(BaseScenario):
    def __init__(self, config: ScenarioConfig, connector: HTTPConnector):
        super().__init__(config, connector)
        self.target_endpoint = config.parameters.get(
            "target_endpoint", "/orders/search")
        self.payloads = config.parameters.get("payloads", [
            {"name": "basic_or", "value": "' OR '1'='1"},
        ])

    def execute_attack(self) -> MetricScenarios:
        results = []

        for payload in self.payloads:
            result = self._test_payload(payload)
            results.append(result)

        all_blocked = all(r["blocked"] for r in results)
        blocked_count = sum(1 for r in results if r["blocked"])

        return MetricScenarios(
            scenario_id=self.config.id,
            scenario_name=self.config.name,
            threat_category=self.config.threat_category,
            success=True,
            expected_result=self.config.expected_result,
            actual_result="attack_blocked" if all_blocked else "vulnerability_found",
            details={
                "sub_scenarios": results,
                "statistics": {
                    "total_payloads": len(self.payloads),
                    "blocked": blocked_count,
                    "passed": len(self.payloads) - blocked_count,
                },
            },
        )

    def _test_payload(self, payload: dict) -> dict:
        name = payload.get("name", "unknown")
        value = payload.get("value", "")
        description = payload.get(
            "description", f"SQL injection: {value[:40]}")

        url = f"{self.config.target_service}{self.target_endpoint}"

        try:
            start = time.time()
            response = self.connector.send_request(
                method="GET",
                url=url,
                params={"q": value},
            )
            elapsed = (time.time() - start) * 1000

            # 400 = validācija bloķēja, 200 = caurlaidis
            blocked = response.status_code == 400

            return {
                "name": name,
                "description": description,
                "payload": value,
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": blocked,
            }

        except Exception as e:
            return {
                "name": name,
                "description": description,
                "payload": value,
                "response_code": None,
                "error": str(e),
                "blocked": False,
            }
