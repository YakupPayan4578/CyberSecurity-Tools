import os
import re
import dns.resolver
from fastapi import FastAPI, Query, Security, HTTPException, status, Body
from fastapi.security import APIKeyHeader
from supabase import create_client

app = FastAPI(title="TITAN Security API")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

API_KEY = "titan_secret_key_2026"
api_key_header = APIKeyHeader(name="X-API-Key")

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return api_key

# ----------------- TOOLS -----------------

@app.get("/api/v1/tools/dns-enum", tags=["Reconnaissance"])
def enumerate_subdomains(
    domain: str = Query(..., description="Target domain (e.g., google.com)"),
    api_key: str = Security(verify_api_key)
):
    # Kapsamlı taramalar (exhaustive scans) API'yi yavaşlatır, bu yüzden şimdilik kısa bir liste kullanıyoruz.
    wordlist = ["dev", "api", "test", "vpn", "admin", "staging", "mail", "www", "portal", "old"]
    found = []
    
    for word in wordlist:
        target = f"{word}.{domain}"
        try:
            # A kaydı (A record) için DNS sunucusunu sorgula
            answers = dns.resolver.resolve(target, 'A')
            ips = [rdata.to_text() for rdata in answers]
            found.append({"subdomain": target, "ips": ips})
        except Exception:
            # NXDOMAIN veya Timeout hatalarını yoksay (ignore)
            pass

    return {"status": "success", "target": domain, "found_count": len(found), "data": found}


@app.get("/api/v1/vulnerabilities", tags=["Threat Intelligence"])
def get_critical_vulns(
    api_key: str = Security(verify_api_key),
    min_epss: float = Query(0.0, description="Minimum EPSS score (0.0 to 1.0)")
):
    query = supabase.table("vulnerabilities").select("*")
    if min_epss > 0:
        query = query.gte("epss", min_epss)
    response = query.execute()
    return {"status": "success", "total_records": len(response.data), "data": response.data}


@app.post("/api/v1/tools/log-parser", tags=["Log Analysis"])
def parse_logs(
    logs: str = Body(..., media_type="text/plain", description="Paste raw log lines here"), 
    api_key: str = Security(verify_api_key)
):
    threats = []

    # 1. Detect Brute Force
    failed_logins = len(re.findall(r"Failed password", logs))
    if failed_logins >= 2:
        threats.append({
            "type": "Brute Force", 
            "severity": "High", 
            "details": f"{failed_logins} failed login attempts detected."
        })

    # 2. Detect Log Wiping (Anti-Forensics)
    if re.search(r"cat /dev/null >", logs) or re.search(r"rm -rf /var/log", logs):
        threats.append({
            "type": "Log Wiping", 
            "severity": "Critical", 
            "details": "Attacker attempted to delete log files."
        })

    return {"status": "analyzed", "threats_detected": len(threats), "data": threats}