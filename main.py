import requests


def search_cve(keyword):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    search_url = f"{base_url}?keywordSearch={keyword}&keywordExactMatch"

    response = requests.get(search_url)

    if response.status_code == 200:
        data = response.json()
        if 'vulnerabilities' in data:
            cve_items = data['vulnerabilities']
            for cve in cve_items:
                cve_id = cve['cve']['id']
                description = cve['cve']['descriptions'][0]['value']
                print(f"CVE ID: {cve_id}")
                print(f"Description: {description}")
                print("--------------------------------------------------------------\n")
            if not cve_items:
                print(f"No vulnerabilities found for {keyword}")
        else:
            print(f"No vulnerabilities found for {keyword}")
    elif response.status_code == 404:
        print(f"No CVE information found for {keyword}")
    else:
        print(f"Error: {response.status_code}")

if __name__ == "__main__":
    keyword = input("Enter the keyword or software version: ")
    search_cve(keyword)

