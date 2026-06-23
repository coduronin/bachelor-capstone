import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MockResponse:
    def __init__(self, status_code, text, reason):
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self.headers = {}
    
    def json(self):
        return {}

class HttpClient:
    def __init__(self, target_url, method='POST', custom_headers=None):
        self.target_url = target_url
        self.method = method.upper()
        self.headers = custom_headers or {}

    def send_request(self, data, timeout=None):
        try:
            if self.method == 'POST':
                content_type = self.headers.get('Content-Type', '').lower()
                if 'application/json' in content_type:
                    response = requests.post(self.target_url, json=data, headers=self.headers, verify=False, timeout=timeout)
                else:
                    response = requests.post(self.target_url, data=data, headers=self.headers, verify=False, timeout=timeout)
            elif self.method == 'GET':
                response = requests.get(self.target_url, params=data, headers=self.headers, verify=False, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {self.method}")
            return response
        except requests.exceptions.RequestException as e:
            return MockResponse(0, f"Error: {str(e)}", "Network Failure")
