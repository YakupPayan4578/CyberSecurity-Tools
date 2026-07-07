import pandas as pd

# Örnek veriler (Mock datasets)
nvd_data = [{'cve_id': 'CVE-2023-34362', 'cvss': 9.8}]
kev_data = [{'cve_id': 'CVE-2023-34362', 'cisa_kev': True}]
epss_data = [{'cve_id': 'CVE-2023-34362', 'epss': 0.99934}]

df_nvd = pd.DataFrame(nvd_data)
df_kev = pd.DataFrame(kev_data)
df_epss = pd.DataFrame(epss_data)

# Verileri cve_id üzerinden birleştir (Data consolidation / LEFT JOIN)
merged_df = pd.merge(df_nvd, df_kev, on='cve_id', how='left')
merged_df = pd.merge(merged_df, df_epss, on='cve_id', how='left')

print("Birleştirilmiş Veri (Consolidated Data):")
print(merged_df)