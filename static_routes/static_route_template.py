class StaticRoute:
    def __init__(self, interface_name, network_uuid, network_name, gateway_host):
        self.static_route = {
            "interfaceName": interface_name,
            "selectedNetworks": [{"type": "Network", "overridable": False, "id": network_uuid, "name": network_name}],
            "gateway": {"literal": {"type": "Host", "value": gateway_host}},
            "metricValue": 1,
            "type": "IPv4StaticRoute",
            "isTunneled": False,
        }

    def to_json(self):
        return self.static_route
