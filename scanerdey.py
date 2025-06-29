import requests

def get_cvss_data(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': keyword,
        'startIndex': 0,
        'resultsPerPage': 5
    }

    response = requests.get(url, params=params)
    data = response.json()

    if 'vulnerabilities' in data:
        for vuln in data['vulnerabilities']:
            cve_id = vuln['cve']['id']
            description = vuln['cve']['descriptions'][0]['value']
            cvss = vuln['cve'].get('metrics', {}).get('cvssMetricV31') or vuln['cve'].get('metrics', {}).get('cvssMetricV2')

            if cvss:
                score = cvss[0]['cvssData']['baseScore']
                severity = cvss[0]['cvssData']['baseSeverity']
                print(f"\nCVE: {cve_id}")
                print(f"Severity: {severity} | Score: {score}")
                print(f"Description: {description}")
            else:
                print(f"\nCVE: {cve_id} (No CVSS data)")
                print(f"Description: {description}")
    else:
        print("No data found.")

# Contoh penggunaan
get_cvss_data("apache struts")
