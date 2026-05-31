import re
import requests
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_keyword(banner, service):
    """Extrait un mot-clé précis depuis la bannière."""
    if not banner:
        return service if service != "unknown" else None

    # Apache / nginx — en premier car souvent dans les bannières HTTP
    web = re.search(r'(Apache|nginx)/[\d.]+', banner)
    if web:
        return web.group()

    # VMware
    vmware = re.search(r'VMware\s+\S+\s+[\d.]+', banner)
    if vmware:
        return vmware.group()

    # OpenSSH
    ssh = re.search(r'OpenSSH[_\s][\d.]+', banner)
    if ssh:
        return ssh.group().replace('_', ' ')

    # FTP
    ftp = re.search(r'(FileZilla|vsftpd|ProFTPD)\s+[\d.]+', banner)
    if ftp:
        return ftp.group()

    # Fallback
    return banner[:40]

def search_cve(keyword, max_results=5):
    """
    Interroge l'API NVD avec un mot-clé (ex: "Apache 2.4.49")
    Retourne une liste de CVE avec score et description.
    """
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results
        }
        response = requests.get(NVD_API, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            score = "N/A"
            severity = "N/A"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                severity = "N/A"
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description"
            )
            cves.append({
                "id": cve_id,
                "score": score,
                "severity": severity,
                "description": desc[:120]
            })
        return cves
    except requests.exceptions.RequestException as e:
        return []
