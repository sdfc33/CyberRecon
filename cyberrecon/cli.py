import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from cyberrecon.asset import AssetRegistry
from cyberrecon.dns_check import resolve_dns
from cyberrecon.http_check import check_http
from cyberrecon.subfinder_check import find_subdomains
from cyberrecon.nmap_check import scan_ports
from cyberrecon.nuclei_check import scan_vulnerabilities
from cyberrecon.git_check import check_git_exposure
from cyberrecon.js_check import find_js_files
from cyberrecon.secrets_check import scan_js_for_secrets
from cyberrecon.findings_engine import analyze
from cyberrecon.api_check import find_api_endpoints
from cyberrecon.dependencies_check import find_exposed_manifests
from cyberrecon.report import generate_report
from cyberrecon.correlation_engine import correlate
from cyberrecon.hypothesis_engine import generate_hypotheses
from cyberrecon.validation_engine import generate_validation_plans
from cyberrecon.stratum_check import scan_mining_ports
from cyberrecon.asic_panel_check import check_asic_panel
from cyberrecon.miner_api_check import check_miner_api


console = Console()


def run(target: str) -> None:
    console.print("[bold cyan]CyberRecon[/bold cyan]")
    console.print(f"Target: [bold]{target}[/bold]\n")

    registry = AssetRegistry()
    observations = []

    dns_obs = resolve_dns(target, registry)
    observations.extend(dns_obs)
    if any(o.type == "DNS_RECORD" for o in dns_obs):
        console.print("[green][+][/green] DNS resolved")
    else:
        console.print("[red][-][/red] DNS resolution failed")

    http_obs = check_http(target, registry)
    observations.extend(http_obs)
    for o in http_obs:
        scheme = "HTTPS" if o.value.startswith("https") else "HTTP"
        if o.type == "HTTP_SERVICE":
            console.print(f"[green][+][/green] {scheme} reachable")
        else:
            console.print(f"[red][-][/red] {scheme} unreachable")

    sub_obs = find_subdomains(target, registry)
    observations.extend(sub_obs)
    subdomain_count = sum(1 for o in sub_obs if o.type == "SUBDOMAIN")
    if subdomain_count:
        console.print(f"[green][+][/green] Subfinder found {subdomain_count} subdomains")
    elif any(o.type == "TOOL_ERROR" for o in sub_obs):
        console.print("[red][-][/red] Subfinder error (see results JSON)")
    else:
        console.print("[dim][~][/dim] No subdomains found")

    console.print("[dim]Running nmap (this may take a while)...[/dim]")
    port_obs = scan_ports(target, registry)
    observations.extend(port_obs)
    open_ports = sum(1 for o in port_obs if o.type == "OPEN_PORT")
    if open_ports:
        console.print(f"[green][+][/green] Nmap found {open_ports} open ports")
    elif any(o.type == "TOOL_ERROR" for o in port_obs):
        console.print("[red][-][/red] Nmap error (see results JSON)")
    else:
        console.print("[dim][~][/dim] No open ports found")

    console.print("[dim]Running nuclei (this may take a while)...[/dim]")
    nuclei_obs = scan_vulnerabilities(target, registry)
    observations.extend(nuclei_obs)
    match_count = sum(1 for o in nuclei_obs if o.type == "NUCLEI_MATCH")
    if match_count:
        console.print(f"[green][+][/green] Nuclei found {match_count} matches")
    elif any(o.type == "TOOL_ERROR" for o in nuclei_obs):
        console.print("[red][-][/red] Nuclei error (see results JSON)")
    else:
        console.print("[dim][~][/dim] No nuclei matches")

    git_obs = check_git_exposure(target, registry)
    observations.extend(git_obs)
    if any(o.type == "GIT_EXPOSED" for o in git_obs):
        console.print("[red][!][/red] Exposed .git directory found!")
    else:
        console.print("[dim][~][/dim] No exposed .git")

    js_obs = find_js_files(target, registry)
    observations.extend(js_obs)
    js_count = sum(1 for o in js_obs if o.type == "JS_FILE")
    if js_count:
        console.print(f"[green][+][/green] Found {js_count} JS files")
    else:
        console.print("[dim][~][/dim] No JS files found")

    api_obs = find_api_endpoints(target, registry)
    observations.extend(api_obs)
    api_count = sum(1 for o in api_obs if o.type == "API_ENDPOINT")
    if api_count:
        console.print(f"[yellow][?][/yellow] Found {api_count} accessible API endpoint(s)")
    else:
        console.print("[dim][~][/dim] No common API endpoints found")

    secret_obs = scan_js_for_secrets(js_obs)
    observations.extend(secret_obs)
    if secret_obs:
        console.print(f"[yellow][?][/yellow] {len(secret_obs)} possible secrets found (needs review)")
    else:
        console.print("[dim][~][/dim] No secret patterns matched")

    dep_obs = find_exposed_manifests(target, registry)
    observations.extend(dep_obs)
    dep_count = sum(1 for o in dep_obs if o.type == "DEPENDENCY_MANIFEST_EXPOSED")
    if dep_count:
        console.print(f"[yellow][?][/yellow] Found {dep_count} exposed dependency manifest(s)")
    else:
        console.print("[dim][~][/dim] No exposed dependency manifests")

    console.print("[dim]Scanning mining-related ports...[/dim]")
    mining_obs = scan_mining_ports(target, registry)
    observations.extend(mining_obs)
    stratum_count = sum(1 for o in mining_obs if o.type == "STRATUM_EXPOSED")
    open_count = sum(1 for o in mining_obs if o.type == "MINING_PORT_OPEN")
    if stratum_count:
        console.print(f"[red][!][/red] Confirmed {stratum_count} exposed Stratum service(s)")
    elif open_count:
        console.print(f"[yellow][?][/yellow] {open_count} mining-port(s) open (unconfirmed protocol)")
    else:
        console.print("[dim][~][/dim] No mining ports found")

    asic_obs = check_asic_panel(target, registry)
    observations.extend(asic_obs)
    if any(o.type == "ASIC_DEFAULT_CREDS" for o in asic_obs):
        console.print("[red][!][/red] Default credentials work on ASIC panel!")
    elif any(o.type == "ASIC_PANEL_FOUND" for o in asic_obs):
        console.print("[yellow][?][/yellow] ASIC panel found")
    else:
        console.print("[dim][~][/dim] No ASIC panel found")

    miner_api_obs = check_miner_api(target, registry)
    observations.extend(miner_api_obs)
    if miner_api_obs:
        console.print("[yellow][?][/yellow] Miner API (cgminer/bmminer) exposed")
    else:
        console.print("[dim][~][/dim] No miner API found")

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

    # --- Correlation Engine ---
    chains = correlate(findings)
    if chains:
        console.print(f"\n[bold magenta]Attack Chains:[/bold magenta] {len(chains)}")
        for c in chains:
            console.print(f"  [magenta][{c.severity.value}][/magenta] {c.title}")

    # --- Hypothesis Engine ---
    hypotheses = generate_hypotheses(findings)
    if hypotheses:
        console.print(f"\n[bold blue]Hypotheses:[/bold blue] {len(hypotheses)}")
        for h in hypotheses:
            console.print(f"  [blue][{h.vulnerability_type}][/blue] {h.title}")

    # --- Validation Engine ---
    validation_plans = generate_validation_plans(hypotheses)
    if validation_plans:
        console.print(f"\n[bold green]Validation Plans:[/bold green] {len(validation_plans)}")

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    obs_path = results_dir / f"{target}.json"
    with obs_path.open("w", encoding="utf-8") as f:
        json.dump([o.to_dict() for o in observations], f, indent=2, ensure_ascii=False)

    findings_path = results_dir / f"{target}_findings.json"
    with findings_path.open("w", encoding="utf-8") as f:
        json.dump([fnd.to_dict() for fnd in findings], f, indent=2, ensure_ascii=False)

    assets_path = results_dir / f"{target}_assets.json"
    with assets_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "assets": [a.to_dict() for a in registry.all_assets()],
                "relationships": [r.to_dict() for r in registry.all_relationships()],
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    report_path = results_dir / f"{target}_report.md"
    generate_report(target, findings, report_path)

    chains_path = results_dir / f"{target}_chains.json"
    with chains_path.open("w", encoding="utf-8") as f:
        json.dump([c.to_dict() for c in chains], f, indent=2, ensure_ascii=False)

    hypotheses_path = results_dir / f"{target}_hypotheses.json"
    with hypotheses_path.open("w", encoding="utf-8") as f:
        json.dump([h.to_dict() for h in hypotheses], f, indent=2, ensure_ascii=False)

    validation_path = results_dir / f"{target}_validation_plans.json"
    with validation_path.open("w", encoding="utf-8") as f:
        json.dump([p.to_dict() for p in validation_plans], f, indent=2, ensure_ascii=False)

    console.print(
        f"\nResults saved to:\n[bold]{obs_path}[/bold]\n"
        f"[bold]{findings_path}[/bold]\n[bold]{assets_path}[/bold]\n"
        f"[bold]{report_path}[/bold]\n[bold]{chains_path}[/bold]\n"
        f"[bold]{hypotheses_path}[/bold]\n[bold]{validation_path}[/bold]"
    )


def normalize_target(raw: str) -> str:
    """Приводить ввід користувача до голого домену, без схеми і зайвих слешів."""
    if "://" in raw:
        raw = urlparse(raw).netloc
    return raw.strip().rstrip("/")


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] python -m cyberrecon <target>")
        sys.exit(1)
    target = normalize_target(sys.argv[1])
    run(target)