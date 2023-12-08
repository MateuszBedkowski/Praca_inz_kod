import platform
import requests
import subprocess
import time
import re
import json

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
    base_url = "http://vulnagent.rbdeveloper.eu/description"
    search_url = base_url

    headers = {'Content-Type': 'application/json'}

    # Use the json parameter to encode the data
    response = requests.post(search_url, headers=headers, json={"keywords": keywords})

    if response.status_code == 200:
        data = response.json()

        for keyword, cve_list in data.items():
            print(f"\nTotal vulnerabilities found for {keyword}: {len(cve_list)}\n")

            for cve_info in cve_list:
                cve_id = cve_info.get('cveId', '')
                description = cve_info.get('description', '')
                url = cve_info.get('url', '')

                print(f"CVE ID: {cve_id}")
                print(f"Description: {description}")
                print(f"URL: {url}")
                print("--------------------------------------------------------------\n")

    elif response.status_code == 404:
        print(f"No CVE information found")
        print("--------------------------------------------------------------\n")
    else:
        print(f"Error: {response.status_code}")
        print("--------------------------------------------------------------\n")

    # Add a sleep of 6 seconds after each request
    time.sleep(0.1)


def main():
    get_package_info()

    input_file = "input.txt"
    formatted_lines = []

    with open(input_file, 'r') as input_file:
        lines = input_file.readlines()

        keywords = []
        for line in lines:
            # Split the line into software_name and version
            parts = line.strip().split(maxsplit=1)

            # Check if there is a version, otherwise use an empty string
            software_name = parts[0]
            version = parts[1] if len(parts) > 1 else ""

            # Format the line and append to the list
            formatted_line = f"{software_name} {version}"
            formatted_lines.append(formatted_line)

            # Append to the keywords list
            keywords.append(f'"{formatted_line}"')

    # Join the keywords list into a string
    keywords_str = ", ".join(keywords)

    # Send keywords in the body of the request
    search_cve(keywords_str)

if __name__ == "__main__":
    main()
