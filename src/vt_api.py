
import os
import requests
from dotenv import load_dotenv

load_dotenv()  # load .env file

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise ValueError("❌ VirusTotal API key missing. Add it to .env")

HEADERS = {"x-apikey": VT_API_KEY}

def vt_request(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        print("Request ->", url, "Status:", response.status_code)  # debug
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print("⚠ Request exception:", e)

    return None



def check_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    data = vt_request(url)

    if not data:
        return {"score": 0, "malware_name": "Unknown"}

    attributes = data["data"]["attributes"]
    score = attributes["last_analysis_stats"]["malicious"]

    results = attributes.get("last_analysis_results", {})
    detected_names = []

    for engine, result in results.items():
        name = result.get("result")
        if name and name not in detected_names:
            detected_names.append(name)

    malware_name = detected_names[0] if detected_names else "Unknown"

    return {"score": score, "malware_name": malware_name}


def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    data = vt_request(url)

    if data:
        return data["data"]["attributes"]["last_analysis_stats"]["malicious"]

    return 0


def check_ip(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    data = vt_request(url)

    if data:
        return data["data"]["attributes"]["last_analysis_stats"]["malicious"]

    return 0


# ------------ MASTER FUNCTION ------------
def check_iocs_with_virustotal(iocs: dict):
    vt_results = {"IPs": {}, "Domains": {}, "Hashes": {}}
    malicious_points = 0

    max_checks = 5  # LIMIT to avoid excessive API calls

    for ip in iocs.get("IPs", [])[:max_checks]:
        score = check_ip(ip)
        vt_results["IPs"][ip] = score
        if score > 0:
            malicious_points += 1

    for domain in iocs.get("Domains", [])[:max_checks]:
        score = check_domain(domain)
        vt_results["Domains"][domain] = score
        if score > 0:
            malicious_points += 1

    for h in iocs.get("Hashes", [])[:max_checks]:
        result = check_hash(h)
        vt_results["Hashes"][h] = result
        if result["score"] > 0:
            malicious_points += 1

    if malicious_points >= 2:
        verdict = "Malicious"
    elif malicious_points == 1:
        verdict = "Suspicious"
    else:
        verdict = "Safe / Clean"

    return vt_results, verdict

