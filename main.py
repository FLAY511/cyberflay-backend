from fastapi import FastAPI, Query
import socket
import whois
import json

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "CyberFlay Recon API active"}

@app.get("/whois")
def whois_lookup(domain: str = Query(..., description="Domain to lookup")):
    try:
        info = whois.whois(domain)
        return json.loads(json.dumps(info, default=str))
    except Exception as e:
        return {"error": str(e)}

@app.get("/portscan")
def scan_ports(host: str = Query(..., description="Target IP or domain"), ports: str = "80,443,22,21,8080"):
    open_ports = []
    port_list = [int(p.strip()) for p in ports.split(",")]
    for port in port_list:
        try:
            with socket.create_connection((host, port), timeout=1):
                open_ports.append(port)
        except:
            continue
    return {
        "host": host,
        "open_ports": open_ports,
        "scanned_ports": port_list
    }
