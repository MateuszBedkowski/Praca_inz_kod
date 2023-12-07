import json

def odczytaj_plik_json(plik_path):
    with open(plik_path, 'r', encoding='utf-8') as plik:
        dane_json = json.load(plik)

        # Wyświetl informacje o CVE ID
        cve_id = dane_json['cveMetadata']['cveId']
        print(f"CVE ID: {cve_id}")

        # Wyświetl informacje o Description
        description = dane_json['containers']['cna']['descriptions'][0]['value']
        print(f"Description: {description}")

        # Wyświetl pierwszy URL
        url = dane_json['containers']['cna']['references'][0]['url']
        print(f"URL: {url}")

# Przykład użycia
plik_path = r'C:\Users\bedko\Downloads\cvelistV5-main\cvelistV5-main\cves\2023\1xxx\CVE-2023-1763.json'
odczytaj_plik_json(plik_path)
