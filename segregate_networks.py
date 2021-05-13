from port_mapping import ports


def split_networks(source, destination):
    def get_host(ip):
        return {"type": "Host", "value": ip}

    def get_network(ip):
        return {"type": "Network", "value": ip}

    def get_range(ips):
        return {"type": "Range", "value": ips}

    def splitter(nic):
        if nic == "any":
            return []
        literals = []
        for i in nic.split(","):
            if "/" in i:
                literals.append(get_network(i))
            elif "-" in i:
                literals.append(get_range(i))
            else:
                literals.append(get_host(i))
        return literals

    return splitter(source), splitter(destination)


def split_zones(source, destination, zones):
    def get_zone(name, uuids):
        _uuid = None
        for i in uuids:
            if i["name"] == name:
                _uuid = i["id"]
        return {"name": name, "type": "SecurityZone", "id": _uuid}

    def splitter(zone, uuids):
        objects = []
        if zone and "," in zone:
            for i in zone.split(","):
                objects.append(get_zone(i, uuids))
        else:
            if zone == "any":
                return []
            else:
                objects.append(get_zone(zone, uuids))
        return objects

    return splitter(source, zones), splitter(destination, zones)


def split_ports(port):
    def get_port(p):
        _value = ports.get(p, None)
        if _value:
            return _value
        else:
            if "/" in p:
                a, b = p.split("/")
                return {"type": "PortLiteral", "port": b, "protocol": "6" if a == "tcp" else "17"}
            else:
                return []

    literals = []
    if "," in port:
        for i in port.split(","):
            value = get_port(i)
            if isinstance(value, list):
                literals.extend(get_port(i))
            else:
                literals.append(get_port(i))
    else:
        value = get_port(port)
        if isinstance(value, list):
            literals.extend(get_port(port))
        else:
            literals.append(get_port(port))
    return literals
