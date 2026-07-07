from fastapi import FastAPI, Query, Security, HTTPException, status
from fastapi.security import APIKeyHeader
from supabase import create_client

app = FastAPI(title="Vulnerability Intelligence API")

SUPABASE_URL = "https://jgcnhihxaosromoqfevd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpnY25oaWh4YW9zcm9tb3FmZXZkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIzNjY0MjAsImV4cCI6MjA5Nzk0MjQyMH0.irNjK6qo-edDHiZPkbCxxXR-DyUH2lxDdSsIUHOnxeM"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Statik API Anahtarı Tanımlaması (Güvenlik Kalkanı)
API_KEY = "titan_secret_key_2026"
api_key_header = APIKeyHeader(name="X-API-Key")

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz API Anahtarı (Invalid API Key)"
        )
    return api_key

@app.get("/api/v1/vulnerabilities")
def get_critical_vulns(
    api_key: str = Security(verify_api_key),
    min_epss: float = Query(0.0, description="Minimum EPSS score filter (0.0 to 1.0)")
):
    query = supabase.table("vulnerabilities").select("*")
    
    if min_epss > 0:
        query = query.gte("epss", min_epss)
        
    response = query.execute()
    return {"status": "success", "total_records": len(response.data), "data": response.data}