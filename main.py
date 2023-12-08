import platform
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

    # Add a sleep of 6 seconds after each request
    time.sleep(0.1)

def main():
    get_package_info()

    read_file = "result.txt"
    formatted_lines = []

    with open(read_file, 'r') as result_file:
        lines = result_file.readlines()

        for line in lines:
            software_name, version = line.split()

            version_match = re.match(r'(\S+)(?: (\d+(\.\d+)+))?', line)
            if version_match:
                software_name = version_match.group(1)
                formatted_version = version_match.group(2) or ''
                formatted_line = f"{software_name} {formatted_version}\n"
                formatted_lines.append(formatted_line)

                search_cve(f"{software_name} {formatted_version}")

    with open(read_file, 'w') as result_file:
        result_file.writelines(formatted_lines)

if __name__ == "__main__":
    main()
