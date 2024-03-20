import platform
import requests
import subprocess
import time
import re
import json

MAX_KEYWORDS_PER_REQUEST = 10
open_file = "xdg-open result.html"

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

def generate_html_table(vulnerabilities):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            table {
                border-collapse: collapse;
                width: 100%;
            }
            th, td {
                border: 1px solid #dddddd;
                text-align: left;
                padding: 8px;
            }
            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>
    <table>
        <tr>
            <th>Software</th>
            <th>CVE ID</th>
            <th>Description</th>
            <th>URL</th>
        </tr>
    """

    for vulnerability in vulnerabilities:
        html_content += f"""
        <tr>
            <td>{vulnerability['software_name']}</td>
            <td>{vulnerability['cve_id']}</td>
            <td>{vulnerability['description']}</td>
            <td><a href="{vulnerability['url']}" target="_blank">{vulnerability['url']}</a></td>
        </tr>
        """

    html_content += """
    </table>
    </body>
    </html>
    """

    with open("result.html", "w") as result_file:
        result_file.write(html_content)

def search_cve(keywords):
    url = "http://vulnagent.rbdeveloper.eu/descriptions"

    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json',
    }

    vulnerabilities = []

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
                        cve_url = cve_info.get('url', '')
                        software_name = ''

                        # Extract software name from the description
                        for keyword in chunk_keywords:
                            if keyword.lower() in description.lower():
                                software_name = keyword
                                break

                        vulnerabilities.append({
                            'software_name': software_name,
                            'cve_id': cve_id,
                            'description': description,
                            'url': cve_url
                        })

            else:
                print(f"No vulnerabilities found for {chunk_keywords}")

        except requests.exceptions.HTTPError as err:
            if response.status_code == 404:
                print(f"No vulnerabilities found for {chunk_keywords}")
            else:
                print(f"HTTP error: {err}")
        except json.JSONDecodeError:
            print(f"No vulnerabilities found for {chunk_keywords}")

        time.sleep(0.5)

    if vulnerabilities:
        generate_html_table(vulnerabilities)

def main():
    get_package_info()

    read_file = "input.txt"
    formatted_lines = []

    with open(read_file, 'r') as result_file:
        lines = result_file.readlines()

        for line in lines:
            version_match = re.match(r'(\S+)(?: (\d+(\.\d+)+))?', line)
            if version_match:
                software_name = version_match.group(1)
                formatted_version = version_match.group(2) or ''
                formatted_line = f"{software_name} {formatted_version}"
                formatted_lines.append(formatted_line)

    if formatted_lines:
        keywords = formatted_lines  # Use the entire list as a bulked JSON array
        search_cve(keywords)
    else:
        print("No software information found in the result file.")
        
    run_command(open_file)

if __name__ == "__main__":
    main()
