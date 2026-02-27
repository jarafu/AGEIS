import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VT_API_KEY")
SHODAN_KEY = os.getenv("SHODAN_API_KEY")

# --- Helper: Query AbuseIPDB ---
def query_abuseipdb(ip):
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10
        )
        data = resp.json()
        return f"AbuseIPDB: Confidence={data['data'].get('abuseConfidenceScore')} | Reports={data['data'].get('totalReports')}"
    except Exception as e:
        return f"AbuseIPDB Error: {e}"

# --- Helper: Query VirusTotal ---
def query_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_KEY}
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", "Unknown")
        return f"VirusTotal: Reputation={reputation}"
    except Exception as e:
        return f"VirusTotal Error: {e}"

# --- Helper: Query Shodan ---
def query_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        ports = data.get("ports", [])
        org = data.get("org", "Unknown")
        isp = data.get("isp", "Unknown")
        country = data.get("country_name", "Unknown")

        return f"Shodan: Org={org}, ISP={isp}, Country={country}, OpenPorts={ports}"
    except Exception as e:
        return f"Shodan Error: {e}"

# --- IOC Enrichment Manager ---
def enrich_iocs(input_text):
    """
    Detects IPs in input text and fetches data from AbuseIPDB, VirusTotal, and Shodan.
    Returns a summarized enrichment context for AI analysis.
    """
    import re
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', input_text)
    if not ips:
        return "No IPs found for enrichment."

    enrichment_summary = []
    for ip in ips:
        enrichment_summary.append(f"--- IOC: {ip} ---")
        enrichment_summary.append(query_abuseipdb(ip))
        enrichment_summary.append(query_virustotal(ip))
        enrichment_summary.append(query_shodan(ip))
        enrichment_summary.append("")  # newline
    return "\n".join(enrichment_summary)

