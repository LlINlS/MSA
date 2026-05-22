# JWT manipulation scenarijs auth draudu kategorijai

import time
import base64
import json
import jwt as pyjwt

from MSA.scenarios.base import BaseScenario
from MSA.core.config import ScenarioConfig
from MSA.connectors.http_connector import HTTPConnector
from MSA.metrics.collector import MetricScenarios

class JwtManipulationScenario(BaseScenario):
    def __init__(self, config: ScenarioConfig, connector: HTTPConnector):
        super().__init__(config, connector)
        self.jwt_secret = config.parameters.get("jwt_secret", "test-secret-key-for-development")
        self.target_endpoint = config.parameters.get("target_endpoint", "/orders")
        self.sub_scenarios = config.parameters.get("sub_scenarios", ["invalid_signature"])

    def execute_attack(self) -> MetricScenarios:
        results = []
        for sub in self.sub_scenarios:
            if sub == "invalid_signature":
                results.append(self._attack_invalid_signature())
            elif sub == "expired_token":
                results.append(self._attack_expired_token())
            elif sub == "role_escalation":
                results.append(self._attack_role_escalation())
            elif sub == "algorithm_none":
                results.append(self._attack_algorithm_none())

        all_blocked = all(r["blocked"] for r in results)
        return MetricScenarios(
            scenario_id=self.config.id,
            scenario_name=self.config.name,
            threat_category=self.config.threat_category,
            success=True,
            expected_result=self.config.expected_result,
            actual_result="attack_blocked" if all_blocked else "vulnerability_found",
            details={"sub_scenarios": results},
        )

    def _send_with_token(self, token: str) -> dict:
        url = f"{self.config.target_service}{self.target_endpoint}"
        try:
            response = self.connector.send_request(
                method="GET", url=url,
                headers={"Authorization": f"Bearer {token}"},
            )
            return {"status_code": response.status_code, "body": response.json()}
        except Exception as e:
            return {"status_code": None, "error": str(e)}

    def _attack_invalid_signature(self) -> dict:
        """JWT ar nepareizu parakstu."""
        token = pyjwt.encode(
            {"sub": "attacker", "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600},
            "wrong-secret-key", algorithm="HS256",
        )
        result = self._send_with_token(token)
        return {
            "name": "invalid_signature",
            "description": "JWT ar nederigu parakstu",
            "response_code": result.get("status_code"),
            "blocked": result.get("status_code") == 401,
        }

    def _attack_expired_token(self) -> dict:
        """JWT ar novecojušu tokenu."""
        token = pyjwt.encode(
            {"sub": "test_user", "role": "user", "iat": int(time.time()) - 7200, "exp": int(time.time()) - 3600},
            self.jwt_secret, algorithm="HS256",
        )
        result = self._send_with_token(token)
        return {
            "name": "expired_token",
            "description": "JWT ar novecojušu tokenu",
            "response_code": result.get("status_code"),
            "blocked": result.get("status_code") == 401,
        }

    def _attack_role_escalation(self) -> dict:
        """JWT ar paaugstinatu role (user → admin)."""
        token = pyjwt.encode(
            {"sub": "test_user", "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600},
            self.jwt_secret, algorithm="HS256",
        )
        url = f"{self.config.target_service}/orders"
        try:
            response = self.connector.send_request(
                method="POST", url=url,
                headers={"Authorization": f"Bearer {token}"},
                json={"item": "Malicious Order", "amount": 0},
            )
            return {
                "name": "role_escalation",
                "description": "JWT ar paaugstinatu role (user → admin)",
                "response_code": response.status_code,
                "blocked": response.status_code in (401, 403),
            }
        except Exception as e:
            return {"name": "role_escalation", "error": str(e), "blocked": False}

    def _attack_algorithm_none(self) -> dict:
        """JWT ar alg: none (bez paraksta)."""
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "attacker", "role": "admin",
                        "iat": int(time.time()), "exp": int(time.time()) + 3600}).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}."
        result = self._send_with_token(token)
        return {
            "name": "algorithm_none",
            "description": "JWT ar alg: none (bez paraksta)",
            "response_code": result.get("status_code"),
            "blocked": result.get("status_code") == 401,
        }