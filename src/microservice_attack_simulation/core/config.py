# konfiguracijas modulis, ielade yaml failus.

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

class ScenarioConfig(BaseModel):
    #konf modulis
    id: str = Field(..., description="Konfiguracijas ID")
    name: str = Field(..., description="Konfiguracijas nosaukums")
    threat_category: str = Field(..., description="Merka draudu kategorija")
    target_mechanism: str = Field(..., description="Merka drosibas mehanisms")
    target_service: str = Field(..., description="Merka servisa URL")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Parametri")
    steps: list[str] = Field(..., description="izpildes soli")
    expected_result: str = Field(..., description="sagaidamais rezultats")

def load_scenario(path:str | Path) -> ScenarioConfig:
    # ielade yaml failu un atgriez scenario konfiguraciju
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Konfiguracijas fails '{path}' nav atrasts.")
    with open(path, 'r', encoding='utf-8') as file: 
        raw = yaml.safe_load(file)
    return ScenarioConfig(**raw)
