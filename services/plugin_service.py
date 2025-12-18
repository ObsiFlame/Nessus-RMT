SEVERITY_MAP = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Info"
}

def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_all_vulnerability(v):
    """
    Used by ALL Vulnerabilities page.
    Nessus does NOT provide CVSS here.
    """
    return {
        "plugin_id": v.get("plugin_id"),
        "plugin_name": v.get("plugin_name"),
        "severity": v.get("severity"),
        "vpr_score": None,
        "cvss3_base_score": None,
        "cvss_base_score": None,
        "cvss3_vector": "N/A",
    }


def normalize_prioritized_plugin(p):
    """
    Used ONLY by Prioritized Vulnerabilities page.
    CVSS data EXISTS here.
    """
    attrs = p.get("pluginattributes", {})
    risk = attrs.get("risk_information", {})

    return {
        "plugin_id": int(p.get("pluginid")),
        "plugin_name": p.get("pluginname"),
        "severity": p.get("severity"),
        "vpr_score": safe_float(attrs.get("vpr_score")),
        "cvss3_base_score": safe_float(risk.get("cvss3_base_score")),
        "cvss_base_score": safe_float(risk.get("cvss_base_score")),
        "cvss3_vector": risk.get("cvss3_vector", "N/A"),
    }

def normalize_prioritized_for_csv(p, epss_map):
    attrs = p.get("pluginattributes", {})
    risk = attrs.get("risk_information", {})

    # CVEs & references
    cves = []
    references = []

    for ref in attrs.get("ref_information", {}).get("ref", []):
        name = ref.get("name")
        values = ref.get("values", {}).get("value", [])

        if name == "cve":
            cves.extend(values)

        for v in values:
            references.append(f"{name.upper()}: {v}")

    plugin_id = int(p.get("pluginid"))

    return {
        "vulnerability_name": p.get("pluginname"),
        "severity": p.get("severity"),
        "cves": ", ".join(cves) if cves else "N/A",
        "references": "; ".join(references) if references else "N/A",

        # ✅ EPSS comes from vulnerabilities[]
        "epss": epss_map.get(plugin_id, "N/A"),

        "remediation": attrs.get("solution", "N/A"),
    }


def normalize_plugin(plugin):
    """
    Normalize a Nessus prioritized plugin object into a
    flat, reusable structure for UI / CSV / DOCX.
    """

    attrs = plugin.get("pluginattributes", {})
    risk = attrs.get("risk_information", {})
    refs = attrs.get("ref_information", {}).get("ref", [])

    # -------------------------------
    # CVEs & References
    # -------------------------------
    cves = []
    references = []

    for r in refs:
        name = r.get("name")
        values = r.get("values", {}).get("value", [])

        for v in values:
            if name == "cve":
                cves.append(v)
            references.append(f"{name}:{v}")

    # -------------------------------
    # Hosts (multi-host aggregation)
    # -------------------------------
    hosts = [
        h.get("host_ip") or h.get("hostname")
        for h in plugin.get("hosts", [])
        if h.get("host_ip") or h.get("hostname")
    ]

    # -------------------------------
    # VPR
    # -------------------------------
    vpr_raw = attrs.get("vpr_score")
    try:
        vpr = float(vpr_raw)
    except (TypeError, ValueError):
        vpr = None

    return {
        # Identity
        "plugin_id": plugin.get("pluginid"),
        "plugin_name": plugin.get("pluginname"),

        # Severity
        "severity": plugin.get("severity"),
        "severity_label": SEVERITY_MAP.get(plugin.get("severity"), "Unknown"),

        # Risk scoring
        "vpr": vpr,
        "cvss3": risk.get("cvss3_base_score"),
        "cvss2": risk.get("cvss_base_score"),
        "cvss3_vector": risk.get("cvss3_vector"),
        "epss": risk.get("epss_score"),

        # Content
        "synopsis": attrs.get("synopsis"),
        "description": attrs.get("description"),
        "solution": plugin.get("solution"),

        # Evidence
        "plugin_output": plugin.get("plugin_output", "Refer Nessus output"),

        # References
        "cves": ", ".join(sorted(set(cves))),
        "references": ", ".join(sorted(set(references))),

        # Hosts
        "hosts": ", ".join(sorted(set(hosts)))
    }

def get_plugin_output(client, scan_id, host_id, plugin_id):
    """
    Wrapper around NessusClient.get_plugin_output()
    Returns only the plugin_output text.
    """
    data = client.get_plugin_output(scan_id, host_id, plugin_id)

    outputs = data.get("outputs", [])
    if outputs:
        return outputs[0].get("plugin_output")

    return None


def get_aggregated_plugin_output(client, scan_id, plugin_id, hosts):
    """
    Fetch plugin output for multiple hosts and aggregate for reports.
    """
    combined = []

    for h in hosts:
        host_id = h.get("host_id")
        host_ip = h.get("hostname") or h.get("host_ip")

        if not host_id:
            continue

        output = get_plugin_output(client, scan_id, host_id, plugin_id)
        if output:
            combined.append(f"{host_ip}:\n{output}")

    return "\n\n".join(combined) if combined else "No plugin output available"
