import asyncio
import time
import httpx

API_URL = "http://localhost:8000/api/v2/normalize/batch"
BATCH_SIZE = 100

# Adapter Samples
SAMPLE_LOGS = {
    "Windows Event": {
        "class_uid": 3001,
        "sample": {
            "EventID": 4624,
            "IpAddress": "192.168.1.105",
            "TargetUserName": "jdoe",
            "Status": "0x0",
            "WorkstationName": "SEC-DESKTOP-01"
        }
    },
    "Network Firewall": {
        "class_uid": 4001,
        "sample": {
            "src_ip": "10.0.0.15",
            "dest_ip": "192.168.1.1",
            "src_port": 54321,
            "dest_port": 443,
            "protocol": "TCP",
            "action": "ALLOW"
        }
    },
    "Generic Syslog": {
        "class_uid": 1001,
        "sample": {
            "host": "syslog-server-01",
            "facility": "auth",
            "severity": "info",
            "message": "User admin logged in from 10.0.0.5"
        }
    }
}

async def benchmark_adapter(client: httpx.AsyncClient, adapter_name: str, config: dict):
    payload = {
        "organization_id": "org-test-123",
        "class_uid": config["class_uid"],
        "raw_payloads": [config["sample"]] * BATCH_SIZE
    }
    
    start_time = time.perf_counter()
    response = await client.post(API_URL, json=payload)
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    if response.status_code == 200:
        eps = BATCH_SIZE / (latency_ms / 1000)
        print(f"Adapter: {adapter_name:<18} | Status: 200 | Latency: {latency_ms:>6.2f} ms | Throughput: {eps:>8.2f} EPS")
    else:
        print(f"Adapter: {adapter_name:<18} | FAILED ({response.status_code})")

async def execute_step3():
    async with httpx.AsyncClient(timeout=None) as client:
        print("=== STEP 3: ADAPTER EFFICIENCY BENCHMARK ===")
        for adapter_name, config in SAMPLE_LOGS.items():
            await benchmark_adapter(client, adapter_name, config)

if __name__ == "__main__":
    asyncio.run(execute_step3())