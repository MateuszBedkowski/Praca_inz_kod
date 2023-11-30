import requests
import subprocess
import time
import re

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None

def search_cve(keyword):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    search_url = f"{base_url}?keywordSearch={keyword}&keywordExactMatch"

    response = requests.get(search_url)

    if response.status_code == 200:
        data = response.json()
        if 'result' in data:
            cve_items = data['result']['CVE_Items']
            totalResults = data['totalResults']
            
            if totalResults > 0:
                print(f"\nTotal vulnerabilities found for {keyword}: {totalResults}\n")
                
            for cve in cve_items:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value']
                
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

    # Add a sleep of 6 seconds after each request
    time.sleep(6)

def main():
    # Run the bash command and save the output to result.txt
    bash_command = "dpkg --list | grep ^ii | awk '{print $2, $3}' > result.txt"
    run_command(bash_command)

    # Read software names from result.txt and search for CVE information
    read_file = "result.txt"
    formatted_lines = []

    with open(read_file, 'r') as result_file:
        lines = result_file.readlines()

        for line in lines:
            # Split the line into software name and version
            software_name, version = line.split()

            # Extract major and minor version components
            version_match = re.match(r'(\S+)(?: (\d+(\.\d+)+))?', line)
            if version_match:
                software_name = version_match.group(1)
                formatted_version = version_match.group(2) or ''
                formatted_line = f"{software_name} {formatted_version}\n"
                formatted_lines.append(formatted_line)

                # Send request only for the formatted name
                search_cve(f"{software_name} {formatted_version}")

    # Write the formatted lines back to result.txt
    with open(read_file, 'w') as result_file:
        result_file.writelines(formatted_lines)

if __name__ == "__main__":
    main()
