from supabase import create_client

# Supabase panelinden (Project Settings -> API) bilgilerini buraya gir
SUPABASE_URL = "https://jgcnhihxaosromoqfevd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpnY25oaWh4YW9zcm9tb3FmZXZkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIzNjY0MjAsImV4cCI6MjA5Nzk0MjQyMH0.irNjK6qo-edDHiZPkbCxxXR-DyUH2lxDdSsIUHOnxeM"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Pandas ile birleştirdiğimiz örnek veri formatı (Dictionary List)
consolidated_data = [{
    'cve_id': 'CVE-2023-34362',
    'cvss': 9.8,
    'cisa_kev': True,
    'epss': 0.99934
}]

print("Upserting data to Supabase...")

try:
    # 'vulnerabilities' tablosuna veriyi basıyoruz
    response = supabase.table("vulnerabilities").upsert(consolidated_data).execute()
    print("Success! Data successfully written to database.")
    print(response)
except Exception as e:
    print(f"Failed to upsert data: {e}")