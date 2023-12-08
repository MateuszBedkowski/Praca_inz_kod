import requests
import time
import re

def search_cve(keyword):
    base_url = "http://vulnagent.rbdeveloper.eu/description"
    search_url = f"{base_url}/{keyword}"

    response = requests.get(search_url)

    if response.status_code == 200:
        data = response.json()

        if data and isinstance(data, list):
            if not data:
                print(f"No vulnerabilities found for {keyword}")
                print("--------------------------------------------------------------\n")
            else:
                print(f"\nTotal vulnerabilities found for {keyword}: {len(data)}\n")

                for cve_info in data:
                    cve_id = cve_info.get('cveId', '')
                    description = cve_info.get('description', '')
                    url = cve_info.get('url', '')

                    print(f"CVE ID: {cve_id}")
                    print(f"Description: {description}")
                    print(f"URL: {url}")
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

    # Dodaj opóźnienie 6 sekund po każdym zapytaniu
    time.sleep(0.1)

def main():
    read_file = "input.txt"
    formatted_lines = []

    with open(read_file, 'r') as result_file:
        lines = result_file.readlines()

        for line in lines:
            # Sprawdź, czy linia zawiera co najmniej jedną wartość przed wysłaniem zapytania
            if line.strip():  # Sprawdź, czy linia nie jest pusta
                line_values = line.split(maxsplit=1)
                software_name = line_values[0]
                formatted_version = line_values[1].strip() if len(line_values) > 1 else ''
                formatted_line = f"{software_name} {formatted_version}\n"
                formatted_lines.append(formatted_line)

                search_cve(f"{software_name} {formatted_version}")

    with open(read_file, 'w') as result_file:
        result_file.writelines(formatted_lines)

if __name__ == "__main__":
    main()
