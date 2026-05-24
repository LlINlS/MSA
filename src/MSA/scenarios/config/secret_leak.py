# noslepumu nopludinasanas scenarijs
# konfiguracijas draudu kategorija
# merka mehanisms: secret managment
# parbauda vai netiek atklati sensitivi dati 


import time
import requests
from MSA.scenarios.base import BaseScenario
from MSA.core.config import ScenarioConfig  
from MSA.connectors.http_connector import HTTPConnector
from MSA.metrics.collector import MetricScenarios

class SecretExposureScenario(BaseScenario):
    def __init__(self, config: ScenarioConfig, connector: HTTPConnector):
        super().__init__(config, connector)
        self.target_endpoint = config.parameters.get("target_endpoint", "/orders")
        self.sensitive_keywords = config.parameters.get("sensitive_keywords", [
            "password", "secret", "key", "token", "api_key", "private",
            "credential", "jwt_secret", "database", "connection_string",
        ])
        self.sub_scenarios = config.parameters.get("sub_scenarios", [
            "error_leak", "header_leak", "debug_endpoint", "stack_trace",
        ])

    def execute_attack(self) -> MetricScenarios:
        results = []

        for sub in self.sub_scenarios:
            if sub == "error_leak":
                results.append(self._attack_error_leak())
            elif sub == "header_leak":
                results.append(self._attack_header_leak())
            elif sub == "debug_endpoint":
                results.append(self._attack_debug_endpoints())
            elif sub == "stack_trace":
                results.append(self._attack_stack_trace())
            elif sub == "env_exposure":
                results.append(self._attack_env_exposure())

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

    def _contains_sensitive(self, text: str) -> list[str]:
        """Pārbauda vai teksts satur sensitīvus atslēgvārdus."""
        text_lower = text.lower()
        found = []
        for keyword in self.sensitive_keywords:
            if keyword.lower() in text_lower:
                found.append(keyword)
        return found

    def _attack_error_leak(self) -> dict:
        """Nosūta nederīgu pieprasījumu un pārbauda vai kļūdas ziņojums atklāj sensitīvus datus."""
        url = f"{self.config.target_service}{self.target_endpoint}"
        try:
            start = time.time()
            # Nosūta pieprasījumu ar nederīgu Content-Type lai izraisītu kļūdu
            response = requests.post(
                url,
                data="{{invalid json",
                headers={"Content-Type": "application/json", "Authorization": "Bearer invalid"},
                timeout=5,
            )
            elapsed = (time.time() - start) * 1000
            body = response.text

            found_secrets = self._contains_sensitive(body)
            leaked = len(found_secrets) > 0

            return {
                "name": "error_leak",
                "description": "Sensitīvu datu atklāšana kļūdas ziņojumos",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": not leaked,
                "detail": f"Atrasti atslēgvārdi: {found_secrets}" if leaked else "Nav sensitīvu datu kļūdas ziņojumā",
            }
        except Exception as e:
            return {
                "name": "error_leak",
                "description": "Sensitīvu datu atklāšana kļūdas ziņojumos",
                "response_code": None,
                "blocked": True,
                "detail": f"Kļūda: {str(e)[:80]}",
            }

    def _attack_header_leak(self) -> dict:
        """Pārbauda vai HTTP galvenes atklāj servera tehnoloģijas vai versijas."""
        url = f"{self.config.target_service}/health"
        suspicious_headers = ["server", "x-powered-by", "x-debug", "x-aspnet-version"]

        try:
            start = time.time()
            response = requests.get(url, timeout=5)
            elapsed = (time.time() - start) * 1000

            found_headers = {}
            for header in suspicious_headers:
                value = response.headers.get(header)
                if value:
                    found_headers[header] = value

            # Pārbauda arī vai http nav sensitivi dati
            all_headers_text = str(dict(response.headers))
            found_secrets = self._contains_sensitive(all_headers_text)

            leaked = len(found_headers) > 0 or len(found_secrets) > 0

            return {
                "name": "header_leak",
                "description": "Servera informācijas atklāšana HTTP galvenēs",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": not leaked,
                "detail": f"Atklātās galvenes: {found_headers}" if found_headers else "Nav aizdomīgu galveņu",
            }
        except Exception as e:
            return {
                "name": "header_leak",
                "description": "Servera informācijas atklāšana HTTP galvenēs",
                "response_code": None,
                "blocked": True,
                "detail": f"Kļūda: {str(e)[:80]}",
            }

    def _attack_debug_endpoints(self) -> dict:
        """Pārbauda vai ir pieejami debug/admin galapunkti."""
        debug_paths = ["/debug", "/admin", "/env", "/config", "/status",
                       "/.env", "/swagger", "/api-docs", "/metrics"]
        accessible = []

        start = time.time()
        for path in debug_paths:
            url = f"{self.config.target_service}{path}"
            try:
                response = requests.get(url, timeout=3)
                if response.status_code not in (404, 403, 405, 502):
                    accessible.append({"path": path, "status": response.status_code})
            except requests.RequestException:
                pass

        elapsed = (time.time() - start) * 1000
        leaked = len(accessible) > 0

        return {
            "name": "debug_endpoint",
            "description": "Debug/admin galapunktu pieejamības pārbaude",
            "response_code": accessible[0]["status"] if accessible else 404,
            "response_time_ms": round(elapsed, 2),
            "blocked": not leaked,
            "detail": f"Pieejami galapunkti: {[a['path'] for a in accessible]}" if leaked else "Nav pieejamu debug galapunktu",
        }

    def _attack_stack_trace(self) -> dict:
        """Nosūta pieprasījumu kas var izraisīt stack trace atklāšanu."""
        url = f"{self.config.target_service}/orders/search"

        try:
            start = time.time()
            # param kede kas izraisa kludu
            response = requests.get(
                url,
                params={"q": "A" * 10000},
                timeout=5,
            )
            elapsed = (time.time() - start) * 1000
            body = response.text.lower()

            has_trace = any(indicator in body for indicator in [
                "traceback", "stack trace", "exception", "file \"",
                "line ", "error at", "at module", "syntaxerror",
            ])

            return {
                "name": "stack_trace",
                "description": "Stack trace atklāšana kļūdu gadījumā",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": not has_trace,
                "detail": "Stack trace atrasts atbildē" if has_trace else "Nav stack trace atbildē",
            }
        except Exception as e:
            return {
                "name": "stack_trace",
                "description": "Stack trace atklāšana kļūdu gadījumā",
                "response_code": None,
                "blocked": True,
                "detail": f"Kļūda: {str(e)[:80]}",
            }

    def _attack_env_exposure(self) -> dict:
        """Pārbauda vai vides mainīgie ir pieejami caur API."""
        url = f"{self.config.target_service}/health"

        try:
            start = time.time()
            response = requests.get(url, timeout=5)
            elapsed = (time.time() - start) * 1000
            body = response.text

            env_indicators = ["JWT_SECRET", "DATABASE_URL", "API_KEY", "SECRET_KEY", "PASSWORD"]
            found = [ind for ind in env_indicators if ind in body]

            return {
                "name": "env_exposure",
                "description": "Vides mainīgo atklāšana API atbildēs",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": len(found) == 0,
                "detail": f"Atklāti vides mainīgie: {found}" if found else "Nav atklātu vides mainīgo",
            }
        except Exception as e:
            return {
                "name": "env_exposure",
                "description": "Vides mainīgo atklāšana API atbildēs",
                "response_code": None,
                "blocked": True,
                "detail": f"Kļūda: {str(e)[:80]}",
            }