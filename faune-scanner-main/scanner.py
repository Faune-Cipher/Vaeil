import argparse
import socket
import time
from modules.tcp import TCPScanner
from modules.cve import search_cve, extract_keyword
from modules.report import generate_report
from rich.console import Console
from rich.table import Table

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Impossible de résoudre : {host}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Faune Scanner — TCP port scanner")
    parser.add_argument("host", help="Cible (IP ou domaine)")
    parser.add_argument("-s", "--start", type=int, default=1)
    parser.add_argument("-e", "--end", type=int, default=1024)
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("-T", "--threads", type=int, default=100)
    parser.add_argument("--cve", action="store_true", help="Recherche CVE pour chaque service détecté")
    args = parser.parse_args()

    ip = resolve_host(args.host)
    console = Console()

    console.print(f"\n  [bold]Faune Scanner[/bold]")
    console.print(f"  Cible   : {args.host} ({ip})")
    console.print(f"  Ports   : {args.start} - {args.end}")
    console.print(f"  CVE     : {'activé' if args.cve else 'désactivé'}\n")

    start_time = time.time()
    scanner = TCPScanner(ip, args.start, args.end, args.timeout, args.threads)
    results = scanner.run()
    elapsed = round(time.time() - start_time, 2)

    all_cves = {}  # ← dict pour collecter les CVE par port

    if results:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Port", width=8)
        table.add_column("Service", width=14)
        table.add_column("Bannière")
        for r in results:
            banner = r['banner'] if r['banner'] else "—"
            banner = banner.replace('\n', ' ').replace('\r', '')[:80]
            table.add_row(str(r['port']), r['service'], banner)
        console.print(table)

        if args.cve:
            console.print("\n  [bold]Recherche CVE...[/bold]\n")
            for r in results:
                keyword = extract_keyword(r['banner'], r['service'])
                if not keyword:
                    continue
                console.print(f"  [bold]Port {r['port']} — {r['service']}[/bold]")
                cves = search_cve(keyword)
                all_cves[r['port']] = cves  # ← stocke les CVE par port
                if cves:
                    cve_table = Table(show_header=True, header_style="dim")
                    cve_table.add_column("CVE ID", width=18)
                    cve_table.add_column("Score", width=7)
                    cve_table.add_column("Sévérité", width=10)
                    cve_table.add_column("Description")
                    for cve in cves:
                        score_str = str(cve['score'])
                        if cve['severity'] == "CRITICAL":
                            score_str = f"[red]{score_str}[/red]"
                        elif cve['severity'] == "HIGH":
                            score_str = f"[orange3]{score_str}[/orange3]"
                        elif cve['severity'] == "MEDIUM":
                            score_str = f"[yellow]{score_str}[/yellow]"
                        cve_table.add_row(
                            cve['id'],
                            score_str,
                            cve['severity'],
                            cve['description']
                        )
                    console.print(cve_table)
                else:
                    console.print("  Aucune CVE trouvée.\n")
                time.sleep(1)
    else:
        console.print("  Aucun port ouvert détecté.")

    console.print(f"\n  Scan terminé en [bold]{elapsed}s[/bold]\n")

    # ← génère le rapport HTML à la fin
    filename = generate_report(args.host, ip, results, all_cves, elapsed)
    console.print(f"  Rapport généré : [bold]{filename}[/bold]\n")

if __name__ == "__main__":
    main()
