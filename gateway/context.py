from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class Finding:
    scanner:str
    severity:str
    description:str
    matched:str
    score_delta:float
@dataclass
class RequestContext:
    request_id:str
    user_id:str
    role:str
    raw_prompt:str
    clean_prompt:str
    risk_score:float=0.0
    findings:List[Finding]=field(default_factory=list)
    policy_decision:str="pending"
    policy_reason:str=""
    model_used:str=""
    latency_ms:int=0
    timestamp:datetime=field(default_factory=datetime.utcnow)
