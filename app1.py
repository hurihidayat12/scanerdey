from flask import Flask, render_template, request
import requests

app = Flask(__name__)

def search_cvss(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': keyword, 'resultsPerPage': 5}
    response = requests.get(url, params=params)
    data = response.json()
    results = []

    for item in data.get("vulnerabilities", []):
        cve = item['cve']
        cve_id = cve['id']
        desc = cve['descriptions'][0]['value']
        score = "N/A"
        severity = "Unknown"

        # Cek metric yang tersedia: V3.1, V3.0, atau V2
        metrics = cve.get('metrics', {}).get('cvssMetricV31') \
                  or cve.get('metrics', {}).get('cvssMetricV30') \
                  or cve.get('metrics', {}).get('cvssMetricV2')

        if metrics:
            cvss_data = metrics[0].get('cvssData', {})
            score = cvss_data.get('baseScore', 'N/A')
            severity = cvss_data.get('baseSeverity', 'Unknown')

        results.append({
            'cve_id': cve_id,
            'description': desc,
            'score': score,
            'severity': severity
        })

    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    if request.method == 'POST':
        keyword = request.form['keyword']
        results = search_cvss(keyword)
    return render_template('index1.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
