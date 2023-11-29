import requests
import time

def search_cve(keyword):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    search_url = f"{base_url}?keywordSearch={keyword}&keywordExactMatch"

    response = requests.get(search_url)

    if response.status_code == 200:
        data = response.json()
        if 'vulnerabilities' in data:
            cve_items = data['vulnerabilities']
            totalResults = data['totalResults']
            
            if totalResults > 0:
                print(f"\nTotal vulberabilities found for {keyword}: {totalResults} \n")
                
            for cve in cve_items:
                cve_id = cve['cve']['id']
                description = cve['cve']['descriptions'][0]['value']
                
                print(f"CVE ID: {cve_id}")
                print(f"Description: {description}")
                print("--------------------------------------------------------------\n")
            if not cve_items:
                print(f"No vulnerabilities found for {keyword}")
                print("--------------------------------------------------------------\n")
        else:
            print(f"No vulnerabilities found for {keyword}")
            print("--------------------------------------------------------------\n")
    elif response.status_code == 404:
        print(f"No CVE information found for {keyword}")
        print("--------------------------------------------------------------\n")
    else:
        print(f"Error: {response.status_code}")
        print("--------------------------------------------------------------\n")

if __name__ == "__main__":
    read_file = "input.txt"
    
    with open(read_file, 'r') as result_file:
        lines = result_file.readlines()

    for line in lines:
        keyword = line.strip()
        search_cve(keyword)
        
        time.sleep(6)
