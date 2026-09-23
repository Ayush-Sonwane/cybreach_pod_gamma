import asyncio
import time
import httpx

API_URL = "http://localhost:8000/api/v2/normalize/batch"
BATCH_SIZE = 50

WINDOWS_SAMPLE_LOG = {
    "EventID": 4624,
    "IpAddress": "192.168.1.105",
    "TargetUserName": "jdoe",
    "Status": "0x0",
    "WorkstationName": "SEC-DESKTOP-01"
}

# Updated to match endpoint schema validation requirements
PAYLOAD = {
    "organization_id": "org-test-123",
    "class_uid": 3001,  # OCSF Authentication Event Class UID
    "raw_payloads": [WINDOWS_SAMPLE_LOG] * BATCH_SIZE
}

async def run_single_batch(client: httpx.AsyncClient, run_name: str):
    start_time = time.perf_counter()
    response = await client.post(API_URL, json=PAYLOAD)
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    if response.status_code == 200:
        eps = BATCH_SIZE / (latency_ms / 1000)
        print(f"[{run_name}] Success | Status: {response.status_code} | Latency: {latency_ms:.2f} ms | Throughput: {eps:.2f} EPS")
        return latency_ms, eps
    else:
        print(f"[{run_name}] Failed | Status: {response.status_code} | Response: {response.text}")
        return None, 0

async def execute_step1():
    async with httpx.AsyncClient(timeout=None) as client:
        print("=== STEP 1: CACHE COLD-START VS WARM TEST ===")
        
        print("\n1. Executing Run 1 (Cold Start)...")
        cold_lat, cold_eps = await run_single_batch(client, "Cold Start")
        
        await asyncio.sleep(1)
        
        print("\n2. Executing Run 2 (Warm Cache)...")
        warm_lat, warm_eps = await run_single_batch(client, "Warm Cache")

if __name__ == "__main__":
    asyncio.run(execute_step1())