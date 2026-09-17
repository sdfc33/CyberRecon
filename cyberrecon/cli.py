import json
import sys
from pathlib import Path

from rich.console import Console

from cyberrecon.dns_check import resolve_dns
from cyberrecon.http_check import check_http
from cyberrecon.subfinder_check import find_subdomains
from cyberrecon.nmap_check import scan_ports
from cyberrecon.nuclei_check import scan_vulnerabilities
from cyberrecon.git_check import check_git_exposure
from cyberrecon.js_check import find_js_files
from cyberrecon.secrets_check import scan_js_for_secrets
from cyberrecon.findings_engine import analyze

console = Console()


def run(target: str) -> None:
    console.print("[bold cyan]CyberRecon[/bold cyan]")
    console.print(f"Target: [bold]{target}[/bold]\n")

    observations = []

    dns_obs = resolve_dns(target)
    observations.extend(dns_obs)
    if any(o.type == "DNS_RECORD" for o in dns_obs):
        console.print("[green][+][/green] DNS resolved")
    else:
        console.print("[red][-][/red] DNS resolution failed")

    http_obs = check_http(target)
    observations.extend(http_obs)
    for o in http_obs:
        scheme = "HTTPS" if o.value.startswith("https") else "HTTP"
        if o.type == "HTTP_SERVICE":
            console.print(f"[green][+][/green] {scheme} reachable")
        else:
            console.print(f"[red][-][/red] {scheme} unreachable")

    sub_obs = find_subdomains(target)
    observations.extend(sub_obs)
    subdomain_count = sum(1 for o in sub_obs if o.type == "SUBDOMAIN")
    if subdomain_count:
        console.print(f"[green][+][/green] Subfinder found {subdomain_count} subdomains")
    elif any(o.type == "TOOL_ERROR" for o in sub_obs):
        console.print("[red][-][/red] Subfinder error (see results JSON)")
    else:
        console.print("[dim][~][/dim] No subdomains found")

    console.print("[dim]Running nmap (this may take a while)...[/dim]")
    port_obs = scan_ports(target)
    observations.extend(port_obs)
    open_ports = sum(1 for o in port_obs if o.type == "OPEN_PORT")
    if open_ports:
        console.print(f"[green][+][/green] Nmap found {open_ports} open ports")
    elif any(o.type == "TOOL_ERROR" for o in port_obs):
        console.print("[red][-][/red] Nmap error (see results JSON)")
    else:
        console.print("[dim][~][/dim] No open ports found")

    console.print("[dim]Running nuclei (this may take a while)...[/dim]")
    nuclei_obs = scan_vulnerabilities(target)
    observations.extend(nuclei_obs)
    match_count = sum(1 for o in nuclei_obs if o.type == "NUCLEI_MATCH")
    if match_count:
        console.print(f"[green][+][/green] Nuclei found {match_count} matches")
    elif any(o.type == "TOOL_ERROR" for o in nuclei_obs):
        console.print("[red][-][/red] Nuclei error (see results JSON)")
    else:
        console.print("[dim][~][/dim] No nuclei matches")

    git_obs = check_git_exposure(target)
    observations.extend(git_obs)
    if any(o.type == "GIT_EXPOSED" for o in git_obs):
        console.print("[red][!][/red] Exposed .git directory found!")
    else:
        console.print("[dim][~][/dim] No exposed .git")

    js_obs = find_js_files(target)
    observations.extend(js_obs)
    js_count = sum(1 for o in js_obs if o.type == "JS_FILE")
    if js_count:
        console.print(f"[green][+][/green] Found {js_count} JS files")
    else:
        console.print("[dim][~][/dim] No JS files found")

    secret_obs = scan_js_for_secrets(js_obs)
    observations.extend(secret_obs)
    if secret_obs:
        console.print(f"[yellow][?][/yellow] {len(secret_obs)} possible secrets found (needs review)")
    else:
        console.print("[dim][~][/dim] No secret patterns matched")

    # --- Findings Engine ---
    findings = analyze(observations)
    if findings:
        console.print(f"\n[bold yellow]Findings:[/bold yellow] {len(findings)}")
        for f in findings:
            console.print(
                f"  [yellow][{f.severity.value}][/yellow] {f.title} "
                f"(confidence: {f.confidence.value}, status: {f.status.value})"
            )
    else:
        console.print("\n[dim]No findings.[/dim]")

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    obs_path = results_dir / f"{target}.json"
    with obs_path.open("w", encoding="utf-8") as f:
        json.dump([o.to_dict() for o in observations], f, indent=2, ensure_ascii=False)

    findings_path = results_dir / f"{target}_findings.json"
    with findings_path.open("w", encoding="utf-8") as f:
        json.dump([fnd.to_dict() for fnd in findings], f, indent=2, ensure_ascii=False)

    console.print(f"\nResults saved to:\n[bold]{obs_path}[/bold]\n[bold]{findings_path}[/bold]")


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] python -m cyberrecon <target>")
        sys.exit(1)
    run(sys.argv[1])