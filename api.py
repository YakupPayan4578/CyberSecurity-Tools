import os
import re
import dns.resolver
import requests
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

@app.get("/api/v1/tools/header-analyzer", tags=["Vulnerability Scanning"])
def analyze_headers(
    url: str = Query(..., description="Target URL (e.g., https://google.com)"),
    api_key: str = Security(verify_api_key)
):
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        security_headers = {
            "Strict-Transport-Security": "Missing (Vulnerable to MITM)",
            "Content-Security-Policy": "Missing (Vulnerable to XSS)",
            "X-Frame-Options": "Missing (Vulnerable to Clickjacking)",
            "X-Content-Type-Options": "Missing (Vulnerable to MIME Sniffing)"
        }
        
        present_headers = {}
        missing_headers = []
        
        for header, risk in security_headers.items():
            if header in headers:
                present_headers[header] = headers[header]
            else:
                missing_headers.append({header: risk})
                
        return {
            "status": "success",
            "target": url,
            "grade": f"{len(present_headers)}/{len(security_headers)}",
            "present_headers": present_headers,
            "missing_headers": missing_headers
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Request failed: {str(e)}")

@app.get("/api/v1/tools/dns-enum", tags=["Reconnaissance"])
def enumerate_subdomains(
    domain: str = Query(..., description="Target domain (e.g., google.com)"),
    api_key: str = Security(verify_api_key)
):
    wordlist = ["dev", "api", "test", "vpn", "admin", "staging", "mail", "www", "portal", "old"]
    found = []
    
    for word in wordlist:
        target = f"{word}.{domain}"
        try:
            answers = dns.resolver.resolve(target, 'A')
            ips = [rdata.to_text() for rdata in answers]
            found.append({"subdomain": target, "ips": ips})
        except Exception:
            pass

    return {"status": "success", "target": domain, "found_count": len(found), "data": found}

@app.post("/api/v1/tools/iam-analyzer", tags=["Cloud Security"])
def analyze_iam_policy(
    policy: dict = Body(..., description="Paste raw AWS IAM JSON Policy here"),
    api_key: str = Security(verify_api_key)
):
    threats = []
    statements = policy.get("Statement", [])
    
    # If Statement is a single dict, convert to list for iteration
    if isinstance(statements, dict):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        effect = stmt.get("Effect", "")
        action = stmt.get("Action", "")
        resource = stmt.get("Resource", "")

        if effect == "Allow":
            # Check for Action wildcard
            if action == "*" or (isinstance(action, list) and "*" in action):
                threats.append({
                    "statement_id": idx,
                    "vulnerability": "Privilege Escalation",
                    "severity": "Critical",
                    "detail": "Action wildcard '*' allows execution of any AWS command."
                })
            
            # Check for Resource wildcard
            if resource == "*" or (isinstance(resource, list) and "*" in resource):
                threats.append({
                    "statement_id": idx,
                    "vulnerability": "Over-permissive Data Access",
                    "severity": "High",
                    "detail": "Resource wildcard '*' grants access to all resources in the account."
                })

    status_msg = "vulnerable" if threats else "secure"
    return {"status": status_msg, "threat_count": len(threats), "data": threats}

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

    failed_logins = len(re.findall(r"Failed password", logs))
    if failed_logins >= 2:
        threats.append({
            "type": "Brute Force", 
            "severity": "High", 
            "details": f"{failed_logins} failed login attempts detected."
        })

    if re.search(r"cat /dev/null >", logs) or re.search(r"rm -rf /var/log", logs):
        threats.append({
            "type": "Log Wiping", 
            "severity": "Critical", 
            "details": "Attacker attempted to delete log files."
        })

    return {"status": "analyzed", "threats_detected": len(threats), "data": threats}