from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.normalizer.base import BaseNormalizer

app = FastAPI(
    title="OCSF Normalization API",
    version="2.0.0"
)

normalizer = BaseNormalizer()


class NormalizeRequest(BaseModel):
    log: Dict[str, Any]


@app.get("/")
def home():
    return {
        "message": "OCSF Normalization API is running"
    }


@app.post("/api/v2/ocsf/normalize")
def normalize(request: NormalizeRequest):
    try:
        event = normalizer.process_log(request.log)

        if hasattr(event, "model_dump"):
            return event.model_dump()

        return event.dict()

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )