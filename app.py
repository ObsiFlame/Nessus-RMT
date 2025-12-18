from flask import (
    Flask, render_template, redirect,
    session, send_file, request, abort, Response
)
import os, csv
from io import StringIO

from config import NESSUS_URL
from clients.nessus_client import NessusClient
from services import (
    scan_service,
    priority_service,
    plugin_service,
    report_service
)

app = Flask(__name__)
app.secret_key = "CHANGE_ME_TO_A_RANDOM_SECRET"


# -------------------------------------------------------------------
# Helper
# -------------------------------------------------------------------
def get_client():
    if "access_key" not in session or "secret_key" not in session:
        return None

    return NessusClient(
        NESSUS_URL,
        session["access_key"],
        session["secret_key"]
    )


# -------------------------------------------------------------------
# Authentication
# -------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        access_key = request.form.get("access_key", "").strip()
        secret_key = request.form.get("secret_key", "").strip()

        if not access_key or not secret_key:
            error = "Access Key and Secret Key are required."
        else:
            client = NessusClient(
                NESSUS_URL,
                access_key,
                secret_key
            )

            # 🔐 REAL AUTH CHECK (protected endpoint)
            if client.validate_connection():
                session["access_key"] = access_key
                session["secret_key"] = secret_key
                return redirect("/home")
            else:
                error = (
                    "Authentication failed. "
                    "Invalid Nessus API keys or insufficient permissions."
                )

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------
@app.route("/")
def index():
    client = get_client()
    if not client:
        return redirect("/login")

    return redirect("/scans")


# -------------------------------------------------------------------
# Home / Landing Page
# -------------------------------------------------------------------
@app.route("/home")
def home():
    client = get_client()
    if not client:
        return redirect("/login")

    return render_template("home.html")


# -------------------------------------------------------------------
# Scan Browser
# -------------------------------------------------------------------
@app.route("/scans")
def scans():
    client = get_client()
    if not client:
        return redirect("/login")

    scans = scan_service.list_scans(client)
    return render_template("scans.html", scans=scans)


# -------------------------------------------------------------------
# Scan Details
# -------------------------------------------------------------------
@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    client = get_client()
    if not client:
        return redirect("/login")

    scan = scan_service.get_scan(client, scan_id)
    return render_template("scan_detail.html", scan=scan)


# -------------------------------------------------------------------
# All Vulnerabilities (NO CVSS by Nessus design)
# -------------------------------------------------------------------
@app.route("/vulnerabilities/<int:scan_id>")
def vulnerabilities(scan_id):
    client = get_client()
    if not client:
        return redirect("/login")

    scan = scan_service.get_scan(client, scan_id)

    vulns = [
        plugin_service.normalize_all_vulnerability(v)
        for v in scan.get("vulnerabilities", [])
    ]

    # 🔥 SORT BY SEVERITY (Critical → Info)
    vulns.sort(
        key=lambda x: x.get("severity", 0),
        reverse=True
    )

    return render_template(
        "vulnerabilities.html",
        vulns=vulns,
        scan_id=scan_id
    )

# -------------------------------------------------------------------
# Prioritized Vulnerabilities (WITH CVSS)
# -------------------------------------------------------------------
@app.route("/prioritized/<int:scan_id>")
def prioritized(scan_id):
    client = get_client()
    if not client:
        return redirect("/login")

    scan = scan_service.get_scan(client, scan_id)

    vulns = priority_service.get_prioritized_vulns(scan)

    return render_template(
        "prioritized.html",
        vulns=vulns,
        scan_id=scan_id
    )


# -------------------------------------------------------------------
# Custom Report Builder
# -------------------------------------------------------------------
@app.route("/custom_report/<int:scan_id>", methods=["GET", "POST"])
def custom_report(scan_id):
    client = get_client()
    if not client:
        return redirect("/login")

    scan = scan_service.get_scan(client, scan_id)

    prioritized = priority_service.get_prioritized_vulns(scan)

    if request.method == "POST":
        selected_ids = request.form.getlist("plugin_id")
        findings = []

        for host in scan.get("hosts", []):
            host_id = host["host_id"]
            hostname = host.get("hostname") or host.get("ip")

            for v in prioritized:
                if str(v["plugin_id"]) not in selected_ids:
                    continue

                pdata = client.get_plugin_output(
                    scan_id, host_id, v["plugin_id"]
                )

                normalized = plugin_service.normalize_plugin(
                    pdata,
                    v["plugin_id"],
                    hostname
                )

                findings.append(normalized)

        path = report_service.generate_docx(scan_id, findings)
        return send_file(path, as_attachment=True)

    return render_template(
        "custom_report.html",
        vulns=prioritized,
        scan_id=scan_id
    )


# -------------------------------------------------------------------
# Default Prioritized Report
# -------------------------------------------------------------------
@app.route("/generate_report/<int:scan_id>")
def generate_report(scan_id):
    client = get_client()
    if not client:
        return redirect("/login")

    scan = scan_service.get_scan(client, scan_id)

    # ✅ USE PRIORITIZED + NORMALIZED DATA DIRECTLY
    findings = priority_service.get_prioritized_vulns(scan)
    # print("<APP.py>: ", findings[0])

    # 🔥 THIS IS THE KEY PART
    for f in findings:
        f["plugin_output"] = plugin_service.get_aggregated_plugin_output(
            client,
            scan_id,
            f["plugin_id"],
            scan["hosts"]
        )

    path = report_service.generate_docx(scan_id, findings)

    return send_file(
        path,
        as_attachment=True,
        download_name=f"scan_{scan_id}_report.docx"
    )

# -------------------------------------------------------------------
# Reports Management
# -------------------------------------------------------------------
@app.route("/reports")
def reports():
    client = get_client()
    if not client:
        return redirect("/login")

    reports_dir = "reports"
    files = []

    if os.path.exists(reports_dir):
        files = [
            f for f in os.listdir(reports_dir)
            if f.lower().endswith(".docx")
        ]

    return render_template("reports.html", reports=files)


@app.route("/download/<path:filename>")
def download(filename):
    client = get_client()
    if not client:
        return redirect("/login")

    path = os.path.join("reports", filename)
    if not os.path.exists(path):
        abort(404)

    return send_file(path, as_attachment=True)


# -------------------------------------------------------------------
# CSV Export – Prioritized Vulnerabilities
# -------------------------------------------------------------------
@app.route("/export_prioritized_csv/<int:scan_id>")
def export_prioritized_csv(scan_id):
    client = get_client()
    if not client:
        return redirect("/login")

    scan = scan_service.get_scan(client, scan_id)

    # EPSS lookup from vulnerabilities[]
    epss_map = {
        v["plugin_id"]: v["epss_score"]
        for v in scan.get("vulnerabilities", [])
        if v.get("epss_score") is not None
    }

    prioritized_plugins = scan.get("prioritization", {}).get("plugins", [])

    rows = [
        plugin_service.normalize_prioritized_for_csv(p, epss_map)
        for p in prioritized_plugins
        if p.get("pluginattributes", {}).get("vpr_score") is not None
    ]

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Vulnerability Name",
        "Severity",
        "CVEs",
        "References",
        "EPSS",
        "Remediation"
    ])

    for r in rows:
        writer.writerow([
            r["vulnerability_name"],
            r["severity"],
            r["cves"],
            r["references"],
            r["epss"],
            r["remediation"]
        ])

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers[
        "Content-Disposition"
    ] = f"attachment; filename=prioritized_vulnerabilities_scan_{scan_id}.csv"

    return response


# -------------------------------------------------------------------
# Run
# -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
