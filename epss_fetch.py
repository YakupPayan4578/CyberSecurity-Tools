import requests

url = "https://api.first.org/data/v1/epss?cve=CVE-2023-34362"
print("Fetching EPSS data...")

response = requests.get(url)
if response.status_code == 200:
    data = response.json()
    epss_score = data["data"][0]["epss"]
    print(f"Success! EPSS Score for CVE-2023-34362: {epss_score}")
else:
    print(f"Failed! Status Code: {response.status_code}")