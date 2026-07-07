import requests
import pandas as pd
from supabase import create_client

SUPABASE_URL = "https://jgcnhihxaosromoqfevd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpnY25oaWh4YW9zcm9tb3FmZXZkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIzNjY0MjAsImV4cCI6MjA5Nzk0MjQyMH0.irNjK6qo-edDHiZPkbCxxXR-DyUH2lxDdSsIUHOnxeM"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = requests.get(url).json()
    # Test için ilk 3 zafiyeti alıyoruz (Optimization)
    return [{'cve_id': v['cveID'], 'cisa_kev': True, 'cvss': 9.8} for v in data['vulnerabilities'][:3]]

def fetch_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    data = requests.get(url).json()
    return float(data['data'][0]['epss']) if data.get('data') else None

def run_pipeline():
    print("Pipeline başlatıldı (Execution started)...")
    kev_data = fetch_cisa_kev()
    
    for item in kev_data:
        item['epss'] = fetch_epss(item['cve_id'])
        
    df = pd.DataFrame(kev_data)
    records = df.to_dict(orient='records') # Veriyi JSON formatına çevir
    
    response = supabase.table("vulnerabilities").upsert(records).execute()
    print(f"Başarılı! Veritabanına yazılan kayıt sayısı (Ingested records): {len(response.data)}")

if __name__ == "__main__":
    run_pipeline()