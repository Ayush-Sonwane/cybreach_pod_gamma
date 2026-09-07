import asyncio
import time
import httpx

API_URL = "http://localhost:8000/api/v2/normalize/batch"
BATCH_SIZES = [10, 50, 100, 250, 500, 1000]

WINDOWS_SAMPLE_LOG = {
    "EventID": 4624,
    "IpAddress": "192.168.1.105",
    "TargetUserName": "jdoe",
    "Status": "0x0",
    "WorkstationName": "SEC-DESKTOP-01"
}

async def benchmark_batch_size(client: httpx.AsyncClient, batch_size: int):
    payload = {
        "organization_id": "org-test-123",
        "class_uid": 3001,
        "raw_payloads": [WINDOWS_SAMPLE_LOG] * batch_size
    }
    
    start_time = time.perf_counter()
    response = await client.post(API_URL, json=payload)
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    if response.status_code == 200:
        eps = batch_size / (latency_ms / 1000)
        print(f"Batch Size: {batch_size:<5} | Latency: {latency_ms:>7.2f} ms | Throughput: {eps:>8.2f} EPS")
        return batch_size, latency_ms, eps
    else:
        print(f"Batch Size: {batch_size:<5} | FAILED ({response.status_code})")
        return batch_size, None, 0

async def execute_step2():
    async with httpx.AsyncClient(timeout=None) as client:
        print("=== STEP 2: BATCH SIZE THROUGHPUT BENCHMARK ===")
        # Warm-up request
        await client.post(API_URL, json={
            "organization_id": "org-test-123",
            "class_uid": 3001,
            "raw_payloads": [WINDOWS_SAMPLE_LOG]
        })
        await asyncio.sleep(0.5)
        
        for b_size in BATCH_SIZES:
            await benchmark_batch_size(client, b_size)

if __name__ == "__main__":
    asyncio.run(execute_step2())