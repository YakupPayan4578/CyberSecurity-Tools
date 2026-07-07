import requests

url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1"
print("Fetching data from NVD API...")

response = requests.get(url)
print(f"Status Code: {response.status_code}")

if response.status_code == 200:
    data = response.json()
    cve_id = data["vulnerabilities"][0]["cve"]["id"]
    print(f"Success! First CVE found: {cve_id}")
else:
    print(f"Failed! Output: {response.text}")