import json
import subprocess

import uvicorn
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

def run_kubectl(args):
    try:
        result = subprocess.run(
            ["kubectl"] + args,
            check=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"kubectl error: {e.stderr.strip()}")

@app.get("/trust-status/")
@app.get("/trust-status")
def get_trust_status(pod_name: str = Query(..., description="Name of the pod")):
    # Step 1: Find pod with name pod_name
    try:
        pods_json = run_kubectl(["get", "pods", "-n", "it6-ns",  "-o", "json"])
        pods = json.loads(pods_json)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get pods: {str(e)}")

    pod = next((p for p in pods["items"] if p["metadata"].get("name").startswith(pod_name)), None)
    if not pod:
        raise HTTPException(status_code=404, detail="Pod UID not found")

    pod_name = pod["metadata"]["name"]
    node_name = pod["spec"].get("nodeName")

    if not node_name:
        raise HTTPException(status_code=500, detail="Node name not found for pod")

    agent_name = f"agent-{node_name}"

    # Step 2: Get the Agent CR for the worker
    try:
        agent_json = run_kubectl([
            "get", "agent.attestation.com", agent_name,
            "-n", "attestation-system", "-o", "json"
        ])
        agent = json.loads(agent_json)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent CR: {str(e)}")

    # Step 3: Find pod status inside Agent's `.spec.podStatus` array
    pod_statuses = agent.get("spec", {}).get("podStatus", [])
    pod_status = next((ps for ps in pod_statuses if ps.get("podName") == pod_name), None)

    if not pod_status:
        raise HTTPException(status_code=404, detail="Pod status not found in agent CR")

    return JSONResponse(content={
        "podName": pod_name,
        "nodeName": node_name,
        "agentName": agent_name,
        "status": pod_status.get("status"),
        "reason": pod_status.get("reason"),
        "lastCheck": pod_status.get("lastCheck"),
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
