def list_scans(client):
    return client.get_scans().get("scans", [])

def get_scan(client, scan_id):
    return client.get_scan_details(scan_id)
