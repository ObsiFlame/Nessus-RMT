# API Credentials for NESSUS
Access Key: 31e0be9a92343ff52d53af46e791408e811b79cda3d71a5674c2213c11621a82
Secret Key: 8d040355c71f53c05e1b0925c0125a9d6b540e41d937f652d796d6cd0133bb56

curl -H "X-ApiKeys: accessKey={accessKey}; secretKey={secretKey}" https://localhost:8834/scans

1.	Plugin Output - https://192.168.247.140:8834/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
2.	Scan Details - https://192.168.247.140:8834/scans/{scan_id}