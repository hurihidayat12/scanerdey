import json

with open('hasil-scan.txt') as f:
    for line in f:
        if "CVE" in line and "CRITICAL" in line:
            print(line)
