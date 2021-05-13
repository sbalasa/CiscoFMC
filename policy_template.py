class Policy:
    _counter = 0

    def __init__(
        self,
        rule_name,
        source_ports,
        dest_ports,
        source_objects,
        dest_objects,
        source_networks,
        dest_networks,
        ips_name,
        ins_policy_uuid,
    ):
        Policy._counter += 1
        self.count = Policy._counter
        self.policy = {
            "ipsPolicy": {"name": ips_name, "id": ins_policy_uuid, "type": "IntrusionPolicy",},
            "sourceZones": {"objects": source_objects},
            "destinationZones": {"objects": dest_objects},
            "sourceNetworks": {"literals": source_networks},
            "destinationNetworks": {"literals": dest_networks},
            "enableSyslog": True,
            "logBegin": False,
            "logEnd": True,
            "sourcePorts": {"literals": source_ports},
            "destinationPorts": {"literals": dest_ports},
            "sendEventsToFMC": True,
            "enabled": True,
            "type": "AccessRule",
            "action": "ALLOW",
            "name": rule_name,
        }

    def to_json(self):
        return self.policy

    def get_count(self):
        return self.count
