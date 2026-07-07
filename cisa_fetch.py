import requests

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
print("Fetching data from CISA KEV...")

response = requests.get(url)
if response.status_code == 200:
    data = response.json()
    total_vulns = data.get("count", 0)
    first_cve = data["vulnerabilities"][0]["cveID"]
    print(f"Success! Total KEV records: {total_vulns}")
    print(f"First exploited CVE found: {first_cve}")
else:
    print(f"Failed! Status Code: {response.status_code}")