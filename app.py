from flask import Flask, render_template, request
import requests
from collections import Counter
from datetime import datetime, timedelta

app = Flask(__name__)

def search_cvss(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': keyword, 'resultsPerPage': 10}
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, params=params, headers=headers)
    data = response.json()
    results = []
    severity_counter = Counter()

    for item in data.get("vulnerabilities", []):
        cve = item['cve']
        cve_id = cve['id']
        desc = cve['descriptions'][0]['value']
        score = "N/A"
        severity = "UNKNOWN"

        metrics = cve.get('metrics', {}).get('cvssMetricV31') \
                  or cve.get('metrics', {}).get('cvssMetricV30') \
                  or cve.get('metrics', {}).get('cvssMetricV2')

        if metrics:
            cvss_data = metrics[0].get('cvssData', {})
            score = cvss_data.get('baseScore', 'N/A')
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')

        severity_counter[severity.upper()] += 1

        results.append({
            'cve_id': cve_id,
            'description': desc,
            'score': score,
            'severity': severity.upper()
        })

    return results, severity_counter

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    chart_data = {}
    if request.method == 'POST':
        keyword = request.form['keyword']
        results, counter = search_cvss(keyword)
        chart_data = dict(counter)
    return render_template('index1.html', results=results, chart_data=chart_data)

@app.route('/dashboard')
def dashboard():
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 100
    }
    headers = {"User-Agent": "Mozilla/5.0"}

    response = requests.get(url, params=params, headers=headers)

    # Cek error
    if response.status_code != 200:
        print("⚠️ API Error:", response.status_code)
        print("⚠️ Response Text:", response.text)

        # Gunakan data dummy jika API gagal
        av_matrix = {"NETWORK": 12, "LOCAL": 5, "ADJACENT_NETWORK": 3}
        ac_matrix = {"LOW": 10, "MEDIUM": 7, "HIGH": 2}
        au_matrix = {"NONE": 14, "SINGLE": 3, "MULTIPLE": 1}
        impact_daily = {
            start_date.strftime("%Y-%m-%d"): {"C": 2, "I": 1, "A": 1},
            end_date.strftime("%Y-%m-%d"): {"C": 5, "I": 3, "A": 2}
        }

        return render_template(
            'dashboard.html',
            av_matrix=av_matrix,
            ac_matrix=ac_matrix,
            au_matrix=au_matrix,
            impact_daily=impact_daily
        )

    # Jika berhasil, bisa mulai proses data JSON dari API
    data = response.json()

    # Sementara tetap gunakan data dummy untuk tampilan
    av_matrix = {"NETWORK": 12, "LOCAL": 5, "ADJACENT_NETWORK": 3}
    ac_matrix = {"LOW": 10, "MEDIUM": 7, "HIGH": 2}
    au_matrix = {"NONE": 14, "SINGLE": 3, "MULTIPLE": 1}
    impact_daily = {
        start_date.strftime("%Y-%m-%d"): {"C": 2, "I": 1, "A": 1},
        end_date.strftime("%Y-%m-%d"): {"C": 5, "I": 3, "A": 2}
    }

    return render_template(
        'dashboard.html',
        av_matrix=av_matrix,
        ac_matrix=ac_matrix,
        au_matrix=au_matrix,
        impact_daily=impact_daily
    )

if __name__ == '__main__':
    app.run(debug=True)
