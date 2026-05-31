from datetime import datetime

THREAT_INTEL = {
    21:  "FTP transmet les credentials en clair. Vecteur classique d'interception.",
    22:  "SSH exposé publiquement. Cible privilégiée pour brute-force et CVE OpenSSH.",
    23:  "Telnet — protocole non chiffré obsolète. Présence critique sur tout réseau.",
    80:  "HTTP non chiffré. Exposé aux attaques MitM et injection de contenu.",
    443: "HTTPS. Vérifier la version TLS et les certificats.",
    445: "SMB — vecteur de WannaCry/EternalBlue. Jamais exposé sur internet.",
    135: "RPC Windows. Historiquement exploité pour exécution de code à distance.",
    3306:"MySQL exposé. Risque d'accès direct à la base de données.",
    3389:"RDP — cible massive de brute-force et ransomwares.",
    6379:"Redis sans auth par défaut. Compromission triviale si exposé.",
    27017:"MongoDB sans auth par défaut. Fuites de données massives documentées.",
}

SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2ecc71",
    "N/A":      "#95a5a6",
}

def calculate_risk(results, all_cves):
    """Score de risque global 0-100 basé sur les CVE et ports dangereux."""
    score = 0
    for r in results:
        if r['port'] in THREAT_INTEL:
            score += 10
        cves = all_cves.get(r['port'], [])
        for cve in cves:
            s = cve.get('score', 0)
            if s == "N/A":
                continue
            s = float(s)
            if s >= 9.0:
                score += 20
            elif s >= 7.0:
                score += 10
            elif s >= 4.0:
                score += 5
    return min(score, 100)

def risk_color(score):
    if score >= 70:
        return "#e74c3c"
    elif score >= 40:
        return "#e67e22"
    return "#2ecc71"

def generate_report(host, ip, results, all_cves, elapsed):
    date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    risk_score = calculate_risk(results, all_cves)

    # Section ports
    ports_html = ""
    for r in results:
        banner = r['banner'] or "—"
        banner = banner.replace('\n', ' ').replace('\r', '')[:100]
        threat = THREAT_INTEL.get(r['port'], "")
        threat_html = f'<div class="threat">⚠ {threat}</div>' if threat else ""
        cves = all_cves.get(r['port'], [])

        cve_html = ""
        if cves:
            cve_html = '<table class="cve-table"><tr><th>CVE</th><th>Score</th><th>Sévérité</th><th>Description</th></tr>'
            for cve in cves:
                color = SEVERITY_COLORS.get(cve['severity'], "#95a5a6")
                cve_html += f"""
                <tr>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{cve['id']}" target="_blank">{cve['id']}</a></td>
                    <td><span class="score" style="background:{color}">{cve['score']}</span></td>
                    <td>{cve['severity']}</td>
                    <td>{cve['description']}</td>
                </tr>"""
            cve_html += '</table>'

        ports_html += f"""
        <div class="port-card">
            <div class="port-header">
                <span class="port-num">{r['port']}</span>
                <span class="service">{r['service']}</span>
                <span class="banner">{banner}</span>
            </div>
            {threat_html}
            {cve_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Faune Scanner — {host}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background:#0d1117; color:#c9d1d9; padding:40px; }}
        .header {{ border-bottom:1px solid #30363d; padding-bottom:24px; margin-bottom:32px; }}
        h1 {{ font-size:24px; color:#f0f6fc; margin-bottom:8px; }}
        .meta {{ font-size:13px; color:#8b949e; }}
        .meta span {{ margin-right:24px; }}
        .risk-box {{ display:inline-block; padding:8px 20px; border-radius:6px;
                     background:{risk_color(risk_score)}22; border:1px solid {risk_color(risk_score)};
                     color:{risk_color(risk_score)}; font-weight:600; font-size:20px; margin:16px 0; }}
        .risk-label {{ font-size:12px; color:#8b949e; margin-bottom:4px; }}
        .port-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
                      padding:20px; margin-bottom:16px; }}
        .port-header {{ display:flex; align-items:center; gap:16px; margin-bottom:12px; }}
        .port-num {{ background:#21262d; color:#79c0ff; padding:4px 12px;
                     border-radius:4px; font-weight:600; font-size:16px; }}
        .service {{ color:#7ee787; font-weight:500; }}
        .banner {{ color:#8b949e; font-size:12px; font-family:monospace; }}
        .threat {{ background:#3d1f1f; border-left:3px solid #f85149;
                   padding:8px 12px; margin:8px 0; font-size:13px; color:#ffa198; border-radius:0 4px 4px 0; }}
        .cve-table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }}
        .cve-table th {{ background:#21262d; padding:8px 12px; text-align:left;
                         color:#8b949e; font-weight:500; }}
        .cve-table td {{ padding:8px 12px; border-top:1px solid #21262d; }}
        .cve-table a {{ color:#79c0ff; text-decoration:none; }}
        .cve-table a:hover {{ text-decoration:underline; }}
        .score {{ padding:2px 8px; border-radius:4px; color:#fff; font-weight:600; font-size:12px; }}
        footer {{ margin-top:40px; font-size:12px; color:#484f58; text-align:center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Faune Scanner</h1>
        <div class="meta">
            <span>Cible : <strong style="color:#f0f6fc">{host} ({ip})</strong></span>
            <span>Date : {date}</span>
            <span>Durée : {elapsed}s</span>
            <span>Ports ouverts : {len(results)}</span>
        </div>
        <div class="risk-label">Score de risque global</div>
        <div class="risk-box">{risk_score} / 100</div>
    </div>
    {ports_html}
    <footer>Généré par Faune Scanner — usage éthique uniquement</footer>
</body>
</html>"""

    filename = f"rapport_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename
