import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NessusClient:
    def __init__(self, base_url, access_key, secret_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json"
        }

    # ------------------------------------------------------------
    # 🔐 AUTH VALIDATION (NEW)
    # ------------------------------------------------------------
    def validate_connection(self):
        """
        Validates Nessus API credentials.
        Uses /scans because it requires authentication.
        Returns True if credentials are valid, else False.
        """
        try:
            response = requests.get(
                f"{self.base_url}/scans",
                headers=self.headers,
                verify=False,
                timeout=5
            )

            # 200 = valid keys
            return response.status_code == 200

        except requests.exceptions.RequestException:
            # Network issue, timeout, SSL error, etc.
            return False

    # ------------------------------------------------------------
    # Existing methods (unchanged)
    # ------------------------------------------------------------
    def get_scans(self):
        r = requests.get(
            f"{self.base_url}/scans",
            headers=self.headers,
            verify=False
        )
        r.raise_for_status()
        return r.json()

    def get_scan_details(self, scan_id):
        r = requests.get(
            f"{self.base_url}/scans/{scan_id}",
            headers=self.headers,
            verify=False
        )
        r.raise_for_status()
        return r.json()

    def get_plugin_output(self, scan_id, host_id, plugin_id):
        r = requests.get(
            f"{self.base_url}/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}",
            headers=self.headers,
            verify=False
        )
        r.raise_for_status()
        return r.json()
