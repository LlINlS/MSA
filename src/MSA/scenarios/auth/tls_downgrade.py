# tls downgrade scenarijs
# merka mehanisms: TLS
# parbauda vai target noraida nedrosus http savienojumus

import time
import ssl
import requests

from MSA.scenarios.base import BaseScenario
from MSA.core.config import ScenarioConfig
from MSA.connectors.http_connector import HTTPConnector
from MSA.metrics.collector import MetricScenarios


class TlsDowngradeScenario(BaseScenario):
    def __init__(self, config: ScenarioConfig, connector: HTTPConnector):
        super().__init__(config, connector)
        self.https_url = config.parameters.get(
            "https_url", "https://localhost:8443")
        self.http_url = config.parameters.get(
            "http_url", "http://localhost:8080")
        self.target_endpoint = config.parameters.get(
            "target_endpoint", "/orders")
        self.sub_scenarios = config.parameters.get("sub_scenarios", [
            "http_plaintext", "missing_hsts", "ssl_verify_disabled"
        ])

    def execute_attack(self) -> MetricScenarios:
        results = []

        for sub in self.sub_scenarios:
            if sub == "http_plaintext":
                results.append(self._attack_http_plaintext())
            elif sub == "missing_hsts":
                results.append(self._attack_missing_hsts())
            elif sub == "ssl_verify_disabled":
                results.append(self._attack_ssl_verify_disabled())
            elif sub == "redirect_check":
                results.append(self._attack_redirect_check())

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

    def _attack_http_plaintext(self) -> dict:
        """Pārbauda vai serviss atbild uz HTTP (nevis HTTPS) pieprasījumiem."""
        url = f"{self.http_url}{self.target_endpoint}"
        try:
            start = time.time()
            response = requests.get(url, timeout=5)
            elapsed = (time.time() - start) * 1000

            # Ja serviss atbild uz HTTP bez pārvirzīšanas uz HTTPS — nedross
            is_redirect_to_https = (
                response.status_code in (301, 302, 307, 308)
                and "https" in response.headers.get("Location", "").lower()
            )

            return {
                "name": "http_plaintext",
                "description": "Pieprasījums pa HTTP (bez TLS šifrēšanas)",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": is_redirect_to_https or response.status_code == 403,
                "detail": "Serviss pārvirza uz HTTPS" if is_redirect_to_https else "Serviss atbild pa HTTP — dati nav šifrēti",
            }
        except requests.ConnectionError:
            return {
                "name": "http_plaintext",
                "description": "Pieprasījums pa HTTP (bez TLS)",
                "response_code": None,
                "blocked": True,
                "detail": "HTTP ports nav pieejams — tikai HTTPS atļauts",
            }

    def _attack_missing_hsts(self) -> dict:
        """Pārbauda vai serviss nosūta HSTS galveni."""
        url = f"{self.http_url}{self.target_endpoint}"
        try:
            start = time.time()
            response = requests.get(url, timeout=5, allow_redirects=True)
            elapsed = (time.time() - start) * 1000

            has_hsts = "strict-transport-security" in {
                k.lower(): v for k, v in response.headers.items()}

            return {
                "name": "missing_hsts",
                "description": "HSTS (Strict-Transport-Security) galvenes pārbaude",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": has_hsts,
                "detail": f"HSTS: {response.headers.get('Strict-Transport-Security', 'NAV ATRASTS')}",
            }
        except requests.ConnectionError:
            return {
                "name": "missing_hsts",
                "description": "HSTS galvenes pārbaude",
                "response_code": None,
                "blocked": False,
                "detail": "Nevar pārbaudīt — savienojums neizdevās",
            }

    def _attack_ssl_verify_disabled(self) -> dict:
        """Pārbauda vai HTTPS serviss izmanto derīgu sertifikātu."""
        url = f"{self.https_url}{self.target_endpoint}"
        try:
            start = time.time()
            # Mēģina savienoties ar SSL verifikāciju
            response = requests.get(url, timeout=5, verify=True)
            elapsed = (time.time() - start) * 1000

            return {
                "name": "ssl_verify_disabled",
                "description": "TLS sertifikāta validācijas pārbaude",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": True,
                "detail": "Derīgs TLS sertifikāts",
            }
        except requests.exceptions.SSLError as e:
            return {
                "name": "ssl_verify_disabled",
                "description": "TLS sertifikāta validācijas pārbaude",
                "response_code": None,
                "blocked": False,
                "detail": f"Nederīgs vai pašparakstīts sertifikāts: {str(e)[:80]}",
            }
        except requests.ConnectionError:
            return {
                "name": "ssl_verify_disabled",
                "description": "TLS sertifikāta validācijas pārbaude",
                "response_code": None,
                "blocked": False,
                "detail": "HTTPS ports nav pieejams — TLS nav konfigurēts",
            }

    def _attack_redirect_check(self) -> dict:
        """Pārbauda vai HTTP pieprasījums tiek pārvirzīts uz HTTPS."""
        url = f"{self.http_url}{self.target_endpoint}"
        try:
            start = time.time()
            response = requests.get(url, timeout=5, allow_redirects=False)
            elapsed = (time.time() - start) * 1000

            redirects_to_https = (
                response.status_code in (301, 302, 307, 308)
                and "https" in response.headers.get("Location", "").lower()
            )

            return {
                "name": "redirect_check",
                "description": "HTTP → HTTPS pārvirzīšanas pārbaude",
                "response_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "blocked": redirects_to_https,
                "detail": f"Pārvirza uz: {response.headers.get('Location', 'nav')}" if redirects_to_https else "Nav pārvirzīšanas uz HTTPS",
            }
        except requests.ConnectionError:
            return {
                "name": "redirect_check",
                "description": "HTTP → HTTPS pārvirzīšanas pārbaude",
                "response_code": None,
                "blocked": True,
                "detail": "HTTP nav pieejams — laba prakse",
            }
