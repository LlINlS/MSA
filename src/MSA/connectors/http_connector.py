# http savienojums ar merka pakalpem

import requests
import time
from dataclasses import dataclass

@dataclass
class HTTPResult:
    success: bool
    url: str
    response_time_ms: float
    status_code: int | None = None
    error: str | None = None

class HTTPConnector:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
    
    def check_connection(self, url: str) -> HTTPResult:
            start_time = time.time()
            try:
                response = self.session.get(f"{url}/health", timeout=self.timeout)
                time_elapsed = (time.time() - start_time) * 1000
                return HTTPResult(
                    success=response.status_code == 200,
                    url=url,
                    response_time_ms=round(time_elapsed, 2),
                    status_code=response.status_code,
                )
            except requests.RequestException as e:
                time_elapsed = (time.time() - start_time) * 1000
                return HTTPResult(
                    success=False,
                    url=url,
                    response_time_ms=round(time_elapsed, 2),
                    error=str(e),
                )
        
            except requests.Timeout:
                time_elapsed = (time.time() - start_time) * 1000
                return HTTPResult(
                    success=False,
                    url=url,
                    response_time_ms=round(time_elapsed, 2),
                    error="timeout",
                )
            
    def send_request(self, method: str, url: str, headers: dict | None = None, json: dict | None = None,
                     params: dict | None = None) -> HTTPResult:
        return self.session.request(
            method=method,
            url=url,
            headers=headers,
            json=json,
            params=params,
            timeout=self.timeout
        )
    
    def close(self):
        self.session.close()
