import requests

def search_cve(keyword):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    search_url = f"{base_url}?keyword={keyword}"

    response = requests.get(search_url)

    if response.status_code == 200:
        data = response.json()
        if 'result' in data and 'CVE_Items' in data['result']:
            cve_items = data['result']['CVE_Items']
            for cve_item in cve_items:
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                description = cve_item['cve']['description']['description_data'][0]['value']
                print(f"CVE ID: {cve_id}")
                print(f"Description: {description}")
                print("----")
        else:
            print(f"No vulnerabilities found for {keyword}")
    else:
        print(f"Error: {response.status_code}")

if __name__ == "__main__":
    keyword = input("Enter the keyword or software version: ")
    search_cve(keyword)
