"""
DPI Engine Web Application.

Author: Vinit Kumar Pandey
"""

from __future__ import annotations

import os
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

# Allow imports from project root
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dpi.blocking_rules import BlockingRules
from dpi.processor import process_pcap
from dpi.report import AUTHOR
from dpi.dpi_types import list_blockable_apps

UPLOAD_DIR = ROOT / "web" / "uploads"
OUTPUT_DIR = ROOT / "web" / "outputs"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(ROOT / "web" / "templates"),
    static_folder=str(ROOT / "web" / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


@app.route("/")
def index():
    return render_template(
        "index.html",
        author=AUTHOR,
        apps=list_blockable_apps(),
    )


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "pcap" not in request.files:
        return jsonify({"success": False, "error": "No PCAP file uploaded"}), 400

    upload = request.files["pcap"]
    if not upload.filename:
        return jsonify({"success": False, "error": "No file selected"}), 400
    if not upload.filename.lower().endswith(".pcap"):
        return jsonify({"success": False, "error": "File must be a .pcap capture"}), 400

    job_id = uuid.uuid4().hex
    input_path = UPLOAD_DIR / f"{job_id}.pcap"
    output_path = OUTPUT_DIR / f"{job_id}_filtered.pcap"
    upload.save(input_path)

    rules = BlockingRules(quiet=True)
    for ip in request.form.get("block_ips", "").split(","):
        ip = ip.strip()
        if ip:
            rules.block_ip(ip)
    for app in request.form.getlist("block_apps"):
        rules.block_app(app)
    for domain in request.form.get("block_domains", "").split(","):
        domain = domain.strip()
        if domain:
            rules.block_domain(domain)

    result = process_pcap(input_path, output_path, rules, quiet=True)

    if not result.success:
        input_path.unlink(missing_ok=True)
        return jsonify({"success": False, "error": result.error}), 400

    payload = {
        "success": True,
        "job_id": job_id,
        "total_packets": result.total_packets,
        "forwarded": result.forwarded,
        "dropped": result.dropped,
        "active_flows": result.active_flows,
        "app_breakdown": result.app_breakdown,
        "detected_domains": result.detected_domains,
        "blocked_events": [asdict(e) for e in result.blocked_events],
    }
    return jsonify(payload)


@app.route("/api/download/<job_id>")
def download(job_id: str):
    if not job_id.isalnum():
        return jsonify({"error": "Invalid job ID"}), 400

    output_path = OUTPUT_DIR / f"{job_id}_filtered.pcap"
    if not output_path.exists():
        return jsonify({"error": "Output file not found"}), 404

    return send_file(
        output_path,
        as_attachment=True,
        download_name="filtered_output.pcap",
        mimetype="application/vnd.tcpdump.pcap",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"DPI Web App by {AUTHOR}")
    print(f"Open http://127.0.0.1:{port} in your browser")
    app.run(host="0.0.0.0", port=port, debug=True)
