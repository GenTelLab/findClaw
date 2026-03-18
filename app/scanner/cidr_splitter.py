import ipaddress


class CidrSplitter:

    @staticmethod
    def split(cidr: str, max_prefix: int = 24) -> list[str]:
        network = ipaddress.ip_network(cidr, strict=False)

        if network.prefixlen >= max_prefix:
            return [str(network)]

        return [str(subnet) for subnet in network.subnets(new_prefix=max_prefix)]

    @staticmethod
    def split_all(cidr_list: list[str], max_prefix: int = 24) -> list[str]:
        result: list[str] = []
        for cidr in cidr_list:
            result.extend(CidrSplitter.split(cidr, max_prefix))
        return result
