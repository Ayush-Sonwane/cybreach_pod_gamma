from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from pydantic import BaseModel

from app.database import get_db
from app.services.normalizer import normalize_log

router = APIRouter(prefix="/api/v2/normalize", tags=["Log Normalizer Engine"])

class NormalizationRequest(BaseModel):
    organization_id: str
    class_uid: int
    raw_payload: Dict[str, Any]

class BatchNormalizationRequest(BaseModel):
    organization_id: str
    class_uid: int
    raw_payloads: List[Dict[str, Any]]


@router.post("", status_code=status.HTTP_200_OK)
def normalize_event(request: NormalizationRequest, db: Session = Depends(get_db)):
    try:
        result = normalize_log(
            db=db,
            org_id=request.organization_id,
            class_uid=request.class_uid,
            raw_payload=request.raw_payload
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/batch", status_code=status.HTTP_200_OK)
def normalize_batch_events(request: BatchNormalizationRequest, db: Session = Depends(get_db)):
    try:
        normalized_events = []
        for payload in request.raw_payloads:
            event = normalize_log(
                db=db,
                org_id=request.organization_id,
                class_uid=request.class_uid,
                raw_payload=payload
            )
            normalized_events.append(event)
        
        return {
            "total_processed": len(normalized_events),
            "events": normalized_events
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))