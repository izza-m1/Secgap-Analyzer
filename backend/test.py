import requests

try:
    resp = requests.post(
        "http://127.0.0.1:5000/api/vuln-scan",
        json={"url": "https://google.com"}
    )
    print(resp.json())
except Exception as e:
    print("Error:", e)
