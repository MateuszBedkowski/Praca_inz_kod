import platform
import requests
import subprocess
import time
import re
import json


MAX_KEYWORDS_PER_REQUEST = 5

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

def get_package_info():
    distribution = determine_linux_distribution()

    if distribution:
        if distribution == "ubuntu":
            bash_command = "dpkg --list | grep ^ii | awk '{print $2, $3}' > result.txt"
        elif distribution == "fedora":
            bash_command = "rpm -qa --queryformat '%{NAME} %{VERSION}\n' > result.txt"
        elif distribution == "arch":
            bash_command = "pacman -Q > result.txt"
        else:
            print(f"Unsupported distribution: {distribution}")
            return

        run_command(bash_command)
    else:
        print("Unsupported operating system")

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
        print(payload)

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

        # Add a sleep of 6 seconds after each request
        time.sleep(1)

def main():
    try:
        # Read package information from input.txt
        with open("input.txt", 'r') as input_file:
            lines = input_file.readlines()

            formatted_lines = []
            formatted_lines.append(lines)
            for line in lines:
                version_match = re.match(r'(\S+)(?: (\d+(\.\d+)+))?', line)
                if version_match:
                    software_name = version_match.group(1)
                    formatted_version = version_match.group(2) or ''
                    formatted_line = f"{software_name} {formatted_version}"
                    #formatted_lines.append(formatted_line)
                formatted_lines.append(software_name)

        if formatted_lines:
            keywords = formatted_lines  # Use the entire list as a bulked JSON array
            search_cve(keywords)
        else:
            print("No software information found in the input file.")
    except FileNotFoundError:
        print("Error: input.txt not found.")
    except Exception as e:
        print(f"Error reading input file: {e}")

if __name__ == "__main__":
    main()