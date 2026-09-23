import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel

# Import Wallet instance
from wallet import wallet

app = FastAPI(title="Pod Gamma Re-Validation Service")

class RevalidateRequest(BaseModel):
    action_id: str
    rule_id: str
    evidence_ref: str

class CompareRequest(RevalidateRequest):
    baseline_version: Optional[str] = "v1"

class RevalidationRun(BaseModel):
    run_id: str
    status: str
    verdict: str
    credits_remaining: int

@app.post("/api/v2/revalidate", response_model=RevalidationRun)
def revalidate(request: RevalidateRequest):
    # 1. Debit 1 credit before execution (M8 Requirement)
    if not wallet.debit(1):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Insufficient wallet credits for re-validation."
        )

    try:
        # Core re-validation execution mock/logic
        # Replace 'verdict_result' with actual engine execution output if applicable
        verdict_result = "NoData" 

        # 2. Check for NoData / Inconclusive result to refund credit
        if verdict_result in ["NoData", "Inconclusive"]:
            wallet.refund(1)
            return RevalidationRun(
                run_id="run_1001",
                status="completed",
                verdict=verdict_result,
                credits_remaining=wallet.get_balance()
            )

        return RevalidationRun(
            run_id="run_1001",
            status="completed",
            verdict=verdict_result,
            credits_remaining=wallet.get_balance()
        )

    except Exception as e:
        # Refund credit if processing fails due to an unexpected server error
        wallet.refund(1)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Re-validation execution error: {str(e)}"
        )