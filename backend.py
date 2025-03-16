from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import requests

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# API KEYS (Replace with your own)
VIRUSTOTAL_API_KEY = "33fa7261693b5212e8018303d976050d12558802f71a6e796e3530f8c933bc2c"
ABUSEIPDB_API_KEY = "885beaa799c5eca1cfed8c3169ced76ce0ce271c6a1bbfa8e09469e725ef8314d3c6fa95563dac1f"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyALGAeD1p4LOO2PRnZ_R2_lOjIX6XYTUV4"
SHODAN_API_KEY = "PPz9XqCFp3BXLMQUEjceM5kmuHxSEm2O"

# Initialize the database
def init_db():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            value TEXT,
            severity TEXT,
            description TEXT,
            source TEXT
        )
    """)
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("index.html")

# 🔍 Scan an IP using multiple APIs
@app.route("/scan_ip", methods=["POST"])
def scan_ip():
    data = request.json
    ip_address = data.get("ip")

    severity = "Low"
    description = "No Threats Found"
    sources = []

    # 🛡️ 1. VirusTotal API
    vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    vt_response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=vt_headers)
    if vt_response.status_code == 200:
        vt_data = vt_response.json()
        vt_malicious = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if vt_malicious > 0:
            severity = "High"
            description = "Malicious Activity Detected"
            sources.append("VirusTotal")

    # 🛡️ 2. AbuseIPDB API
    abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    abuse_response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}", headers=abuse_headers)
    if abuse_response.status_code == 200:
        abuse_data = abuse_response.json()
        abuse_score = abuse_data["data"]["abuseConfidenceScore"]
        if abuse_score > 50:
            severity = "High"
            description = "Reported as Abusive IP"
            sources.append("AbuseIPDB")

    # 🛡️ 3. Shodan API (Port scanning & vulnerabilities)
    shodan_response = requests.get(f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}")
    if shodan_response.status_code == 200:
        severity = "Medium"
        description = "Open Ports Detected"
        sources.append("Shodan")

    # Save to database
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO threats (type, value, severity, description, source) VALUES (?, ?, ?, ?, ?)",
                   ("IP", ip_address, severity, description, ", ".join(sources)))
    conn.commit()
    conn.close()

    return jsonify({"message": "IP scanned successfully", "severity": severity, "sources": sources}), 200

# 🔍 Scan a URL using multiple APIs
@app.route("/scan_url", methods=["POST"])
def scan_url():
    data = request.json
    url = data.get("url")

    severity = "Low"
    description = "No Threats Found"
    sources = []

    # 🛡️ 1. VirusTotal API
    vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    vt_response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=vt_headers)
    if vt_response.status_code == 200:
        vt_data = vt_response.json()
        vt_malicious = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if vt_malicious > 0:
            severity = "High"
            description = "Malicious URL Detected"
            sources.append("VirusTotal")

    # 🛡️ 2. Google Safe Browsing API
    gsb_payload = {"client": {"clientId": "yourcompany", "clientVersion": "1.0.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    gsb_response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}", json=gsb_payload)
    if gsb_response.status_code == 200 and gsb_response.json():
        severity = "High"
        description = "Google Safe Browsing Alert"
        sources.append("Google Safe Browsing")

    # Save to database
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO threats (type, value, severity, description, source) VALUES (?, ?, ?, ?, ?)",
                   ("URL", url, severity, description, ", ".join(sources)))
    conn.commit()
    conn.close()

    return jsonify({"message": "URL scanned successfully", "severity": severity, "sources": sources}), 200

@app.route("/get_threats", methods=["GET"])
def get_threats():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats")
    threats = cursor.fetchall()
    conn.close()

    return jsonify([{"id": t[0], "type": t[1], "value": t[2], "severity": t[3], "description": t[4], "source": t[5]} for t in threats])

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
