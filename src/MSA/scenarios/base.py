# unversala izpildes darbplusma no darba
# 1. izvēloties konfigurāciju, 
# 2. izveidojot savienojumu,
# 3. veicot uzbrukuma soļu izpildi, 
# 4. reģistrējot iegūtos rezultātus,
# 5. ģenerējot atskaiti.

from abc import ABC, abstractmethod

from MSA.core.config import ScenarioConfig  
from MSA.connectors.http_connector import HTTPConnector, HTTPResult
from MSA.metrics.collector import MetricsCollector, MetricScenarios

class BaseScenario(ABC):
    def __init__(self, config: ScenarioConfig, connector: HTTPConnector):
        self.config = config
        self.connector = connector
        self.metrics = MetricsCollector()

    def run(self, m_timeout_try: int = 3) -> MetricScenarios:
        # savienojums
        connection = self.establish_connection(m_timeout_try)
        if connection is None:
            return MetricScenarios(
                threat_category=self.config.threat_category,
                scenario_name=self.config.scenario_name,
                success=False,
                expected_result=self.config.expected_result,
                actual_result="Connection Failed",
                response_code=None,
                details={"error": "Unable to establish connection after multiple attempts."},
            )
        
        # uzbrukuma soli + laika metrikas registresana
        self.metrics.start_timer()
        try:
            result = self.execute_attack()
            result.completed = True
        except Exception as e:
            result = MetricScenarios(scenario_id=self.config.id,
                scenario_name=self.config.name, threat_category=self.config.threat_category,
                success=False, completed=False, actual_result="Execution Error",
                details={"error": str(e)})
        result.execution_time = self.metrics.stop_timer()
        # rezultatu registresana
        self.metrics.record(result)
        return result
    
    def establish_connection(self, m_timeout_try: int) -> HTTPResult:
        for attempt in range(m_timeout_try):
                connection = self.connector.check_connection(self.config.target_service)
                if connection.success:
                    return connection
        return connection
            
    @abstractmethod
    def execute_attack(self) -> MetricScenarios:
        # izpildes soli, atkariba no scenarija
        pass
    # ... pagaidam