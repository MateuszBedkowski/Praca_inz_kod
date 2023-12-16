import requests

url = 'http://vulnagent.rbdeveloper.eu/descriptions'
headers = {
    'accept': '*/*',
    'Content-Type': 'application/json'
}
data = [
    "ubuntu", "apache 1.2.5"
]

response = requests.post(url, headers=headers, json=data)

print("Status Code:", response.status_code)
print("Response:", response.text)
