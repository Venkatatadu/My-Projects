import requests
import os
import ipaddress
import logging
import json
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Load API keys securely
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

if not ABUSEIPDB_API_KEY or not VT_API_KEY:
    logging.error("API keys not set. Use environment variables for ABUSEIPDB_API_KEY and VT_API_KEY.")
    sys.exit(1)

# Setup session with retry logic
def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    return session

session = create_session()

def check_abuseipdb(ip):
    """Check IP reputation on AbuseIPDB"""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = session.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "source": "AbuseIPDB",
            "abuse_score": data["data"].get("abuseConfidenceScore"),
            "country": data["data"].get("countryCode"),
            "total_reports": data["data"].get("totalReports")
        }
    except Exception as e:
        logging.warning(f"AbuseIPDB error for IP {ip}: {e}")
        return {"source": "AbuseIPDB", "error": str(e)}

def check_virustotal(ip):
    """Check IP reputation on VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "source": "VirusTotal",
            "malicious_votes": stats.get("malicious"),
            "harmless_votes": stats.get("harmless")
        }
    except Exception as e:
        logging.warning(f"VirusTotal error for IP {ip}: {e}")
        return {"source": "VirusTotal", "error": str(e)}

def validate_ip(ip_input):
    """Validate and normalize IP address"""
    try:
        return str(ipaddress.ip_address(ip_input.strip()))
    except ValueError:
        raise ValueError("Invalid IP format")

def main():
    try:
        ip_input = input("Enter an IP address to check: ")
        ip = validate_ip(ip_input)
    except ValueError as ve:
        logging.error(ve)
        sys.exit(2)

    logging.info(f"Checking reputation for IP: {ip}")

    abuse_result = check_abuseipdb(ip)
    vt_result = check_virustotal(ip)

    report = {
        "IP": ip,
        "AbuseIPDB": abuse_result,
        "VirusTotal": vt_result
    }

    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    main()
