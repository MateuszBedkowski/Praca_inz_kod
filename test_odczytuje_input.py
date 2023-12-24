import platform
import requests
import subprocess
import time
import json


MAX_KEYWORDS_PER_REQUEST = 10

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return None

def determine_linux_distribution():
    system = platform.system().lower()

    if system == "linux":
        try:
            with open('/etc/os-release', 'r') as os_release:
                lines = os_release.readlines()
                for line in lines:
                    if line.startswith("ID="):
                        distro_id = line.split('=')[1].strip().lower()
                        if distro_id in ["debian", "ubuntu"]:
                            print("Ubuntu/Debian detected\n")
                            return "ubuntu"
                        elif distro_id == "fedora":
                            print("Fedora detected\n")
                            return "fedora"
                        elif distro_id == "arch":
                            print("Arch Linux detected\n")
                            return "arch"
        except FileNotFoundError:
            print("Unable to read /etc/os-release. No supported package manager found.")
        except Exception as e:
            print(f'Error determining Linux distribution: {e}') 
    print("Unsupported operating system")
    return None

def search_cve(keywords):
    url = "http://vulnagent.rbdeveloper.eu/descriptions"

    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json',
    }

    # Split the keywords into chunks of MAX_KEYWORDS_PER_REQUEST
    for i in range(0, len(keywords), MAX_KEYWORDS_PER_REQUEST):
        chunk_keywords = keywords[i:i + MAX_KEYWORDS_PER_REQUEST]

        payload = json.dumps(chunk_keywords)
        response = requests.post(url, headers=headers, data=payload)

        try:
            response.raise_for_status()

            data = response.json()
            if data and isinstance(data, list):
                if not data:
                    print(f"No vulnerabilities found for {chunk_keywords}")
                else:
                    print(f"\nTotal vulnerabilities found for {chunk_keywords}: {len(data)}\n")

                    for cve_info in data:
                        cve_id = cve_info.get('cveId', '')
                        description = cve_info.get('description', '')
                        url = cve_info.get('url', '')
                        software_name = ''

                        # Extract software name from the description
                        for keyword in chunk_keywords:
                            if keyword.lower() in description.lower():
                                software_name = keyword
                                break

                        print(f"Software: {software_name}")
                        print(f"CVE ID: {cve_id}")
                        print(f"Description: {description}")
                        print(f"URL: {url}")
                        print("--------------------------------------------------------------\n")
            else:
                print(f"No vulnerabilities found for {chunk_keywords}")

        except requests.exceptions.HTTPError as err:
            print(f"HTTP error: {err}")
        except json.JSONDecodeError:
            print(f"No vulnerabilities found for {chunk_keywords}")

        time.sleep(1)

def main():
    # Read from input.txt and write to result.txt
    read_file = "input.txt"
    write_file = "result.txt"

    formatted_lines = []

    with open(read_file, 'r') as input_file:
        lines = input_file.readlines()

        for line in lines:
            formatted_lines.append(line.strip())

    if formatted_lines:
        with open(write_file, 'w') as result_file:
            result_file.write("\n".join(formatted_lines))

        keywords = formatted_lines  # Use the entire list as a bulked JSON array
        search_cve(keywords)
    else:
        print("No software information found in the input file.")

if __name__ == "__main__":
    main()
