import dns.resolver
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType


def resolve_dns(target: str, registry: AssetRegistry) -> list[Observation]:
    observations = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)

    try:
        answers = dns.resolver.resolve(target, "A")
        for rdata in answers:
            ip_value = rdata.to_text()

            ip_asset = registry.get_or_create(AssetType.IP, ip_value)
            registry.link(domain_asset, ip_asset, "resolves_to", source="dns_check")

            observations.append(
                Observation(
                    target=target,
                    type="DNS_RECORD",
                    value=ip_value,
                    source="dnspython",
                    evidence={"record_type": "A"},
                )
            )
    except dns.resolver.NXDOMAIN:
        observations.append(
            Observation(
                target=target,
                type="DNS_ERROR",
                value="NXDOMAIN",
                source="dnspython",
                evidence={},
            )
        )
    except Exception as e:
        observations.append(
            Observation(
                target=target,
                type="DNS_ERROR",
                value=str(e),
                source="dnspython",
                evidence={},
            )
        )
    return observations