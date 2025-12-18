from services.plugin_service import normalize_plugin


def get_prioritized_vulns(scan):
    """
    Returns prioritized vulnerabilities using
    scan['prioritization']['plugins'] (correct Nessus structure)
    """

    results = []

    plugins = scan.get("prioritization", {}).get("plugins", [])

    for p in plugins:
        attrs = p.get("pluginattributes", {})

        vpr_raw = attrs.get("vpr_score")

        try:
            vpr = float(vpr_raw)
        except (TypeError, ValueError):
            continue

        normalized = normalize_plugin(p)

        # Optional: skip Info/Low
        if normalized.get("severity", 0) < 2:
            continue

        normalized["vpr"] = vpr
        results.append(normalized)

    # Sort: Severity desc → VPR desc
    print(results[0])
    results.sort(
        key=lambda x: (x.get("severity", 0), x.get("vpr", 0)),
        reverse=True
    )

    return results
