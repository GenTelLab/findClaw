import ipaddress
from dataclasses import dataclass


@dataclass
class ParsedTarget:
    single_ip_list: list[str]
    cidr_list: list[str]


class IpRangeParser:

    @staticmethod
    def parse(raw: str) -> ParsedTarget:
        single_ip_list: list[str] = []
        cidr_list: list[str] = []

        for token in _tokenize(raw):
            token = token.strip()
            if not token:
                continue

            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                cidr_list.append(str(network))
            elif "-" in token and not token.startswith("-"):
                expanded = _expand_range(token)
                single_ip_list.extend(expanded)
            else:
                ipaddress.ip_address(token)
                single_ip_list.append(token)

        return ParsedTarget(single_ip_list=single_ip_list, cidr_list=cidr_list)

    @staticmethod
    def count_hosts(target: ParsedTarget) -> int:
        count = len(target.single_ip_list)
        for cidr in target.cidr_list:
            network = ipaddress.ip_network(cidr, strict=False)
            count += network.num_addresses
        return count

    @staticmethod
    def expand_all(target: ParsedTarget) -> list[str]:
        result = list(target.single_ip_list)
        for cidr in target.cidr_list:
            network = ipaddress.ip_network(cidr, strict=False)
            result.extend(str(h) for h in network.hosts())
        return result

    @staticmethod
    def contains(target: ParsedTarget, ip: str) -> bool:
        parsed_ip = ipaddress.ip_address(ip)
        if ip in target.single_ip_list:
            return True

        for cidr in target.cidr_list:
            if parsed_ip in ipaddress.ip_network(cidr, strict=False):
                return True

        return False


def _tokenize(raw: str) -> list[str]:
    raw = raw.replace(";", ",").replace("\n", ",")
    return [t.strip() for t in raw.split(",") if t.strip()]


def _expand_range(token: str) -> list[str]:
    parts = token.split("-", 1)
    start_ip = ipaddress.ip_address(parts[0].strip())
    end_part = parts[1].strip()

    if "." in end_part:
        end_ip = ipaddress.ip_address(end_part)
    else:
        octets = str(start_ip).rsplit(".", 1)
        end_ip = ipaddress.ip_address(f"{octets[0]}.{end_part}")

    if int(end_ip) < int(start_ip):
        raise ValueError(f"Invalid range: {token}")

    result: list[str] = []
    current = int(start_ip)
    while current <= int(end_ip):
        result.append(str(ipaddress.ip_address(current)))
        current += 1
    return result
