import requests
import os
import ipaddress
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load API keys from environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

if not ABUSEIPDB_API_KEY or not VT_API_KEY:
    logging.error("Missing API keys. Set them as environment variables.")
    exit()

def check_abuseipdb(ip):
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
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        return {
            "source": "AbuseIPDB",
            "abuse_score": data["data"]["abuseConfidenceScore"],
            "country": data["data"]["countryCode"],
            "total_reports": data["data"]["totalReports"]
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"AbuseIPDB API error: {e}")
        return None

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return {
            "source": "VirusTotal",
            "malicious_votes": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
            "harmless_votes": data["data"]["attributes"]["last_analysis_stats"]["harmless"]
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal API error: {e}")
        return None

def main():
    # Validate input
    try:
        ip = input("Enter IP to check: ").strip()
        ip = ipaddress.ip_address(ip)
    except ValueError:
        logging.error("Invalid IP address. Please try again.")
        exit()

    # Query APIs
    logging.info("Querying AbuseIPDB...")
    abuse_result = check_abuseipdb(str(ip))

    logging.info("Querying VirusTotal...")
    vt_result = check_virustotal(str(ip))

    # Combine results
    report = {
        "IP": str(ip),
        "AbuseIPDB": abuse_result,
        "VirusTotal": vt_result
    }

    # Output report
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    main()
