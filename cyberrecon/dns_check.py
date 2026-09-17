import dns.resolver
from cyberrecon.observation import Observation


def resolve_dns(target: str) -> list[Observation]:
    observations = []
    try:
        answers = dns.resolver.resolve(target, "A")
        for rdata in answers:
            observations.append(
                Observation(
                    target=target,
                    type="DNS_RECORD",
                    value=rdata.to_text(),
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