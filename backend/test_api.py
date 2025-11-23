import requests

url = "http://127.0.0.1:5000/api/vuln-scan"
data = {"url": "https://example.com"}

response = requests.post(url, json=data)
print(response.json())
