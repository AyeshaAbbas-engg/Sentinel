from fastapi import FastAPI
from pydantic import BaseModel
from presidio_analyzer import AnalyzerEngine
from typing import List

app=FastAPI(title="SENTINEL Presidio PII Service")
print("Loading Presidio Analyzer Engine...")
analyzer = AnalyzerEngine()
print("Presidio Analyzer Engine loaded successfully.")

class AnalyzeRequest(BaseModel):
    text: str
    language:str="en"

class EntityResult(BaseModel):
    entity_type:str
    start:int
    end:int
    score:float

@app.post("/analyze", response_model=List[EntityResult])
async def analyze(request:AnalyzeRequest):
    results=analyzer.analyze(
        text=request.text,
        language=request.language,
        entities=[
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "IP_ADDRESS",
            "IBAN_CODE",
            "LOCATION"

        ]
    )
    return [
        EntityResult(
            entity_type=r.entity_type,
            start=r.start,
            end=r.end,
            score=r.score
        )
        for r in results
    ]
@app.get("/health")
async def health():
    return {"status": "ok","service":"sentinel-presidio"}