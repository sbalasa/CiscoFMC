"""
Main runner for Cisco FMC Toolkit to update FMC Firewall Policy Access Rules.
"""

import sys
import json
import time
import requests


from pprint import pprint
from more_itertools import chunked
from requests.exceptions import ConnectionError


requests.packages.urllib3.disable_warnings()

# Global
FMC_USER = sys.argv[1]
FMC_PASSWORD = sys.argv[2]


class RestAPI:
    def __init__(self, fmc_host, username, password):
        self.fmc_host = fmc_host
        self.username = username
        self.password = password
        self.headers = {}
        self.domains = []
        self.policies = []
        self.intrusion_policies = []
        self.access_rules = []
        self.bulk_access_rules = []
        self.login()

    def login(self):
        base_url = f"https://{self.fmc_host}"
        login_url = base_url + "/api/fmc_platform/v1/auth/generatetoken"
        _headers = {"Content-Type": "application/json", "Connection": "Keep-Alive"}
        login_response = requests.post(
            login_url, headers=_headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False
        )
        access_token = login_response.headers.get("X-auth-access-token", default=None)
        if access_token:
            self.domains = json.loads(login_response.headers.get("DOMAINS", "[]"))
            self.headers = {"Content-Type": "application/json", "X-auth-access-token": access_token}
        else:
            print("Login Token not found. Exiting...")
            sys.exit(-1)

    def get_request(self, endpoint):
        get_response = requests.get(f"https://{self.fmc_host}/{endpoint}", headers=self.headers, verify=False)
        return get_response

    def fetch_policies(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies")
        if response.status_code == 200:
            self.policies = response.json()["items"]
        else:
            return []

    def fetch_intrusion_policies(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies")
        if response.status_code == 200:
            self.intrusion_policies = response.json()["items"]
        else:
            return []

    def fetch_access_rules(self, domain_uuid, acp_uuid):
        response = self.get_request(
            f"api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{acp_uuid}/accessrules?expanded=True&offset=0&limit=1000"
        )
        if response.status_code == 200:
            self.access_rules = response.json()["items"]
            for i in response.json().get("paging", {}).get("next", []):
                get_response = requests.get(i, headers=self.headers, verify=False)
                if get_response.status_code == 200:
                    self.access_rules.extend(response.json()["items"])
        else:
            return []

    def get_domain_uuid(self, domain_name):
        for i in self.domains:
            if i["name"] == domain_name:
                return i["uuid"]

    def get_policy_uuid(self, policy_name):
        for i in self.policies:
            if i["name"] == policy_name:
                return i["id"]

    def get_intrusion_policy_uuid(self, ins_policy_name):
        for i in self.intrusion_policies:
            if i["name"] == ins_policy_name:
                return i["id"]

    def get_bulk_access_rules(self, ips_uuid):
        for i in self.access_rules:
            try:
                if i["enabled"]:
                    changed = False
                    if i["action"] == "ALLOW":
                        if not i["enableSyslog"]:
                            i["enableSyslog"] = True
                            changed = True
                        if i["logBegin"]:
                            i["logBegin"] = False
                            changed = True
                        if not i["logEnd"]:
                            i["logEnd"] = True
                            changed = True
                        if not i.get("ipsPolicy"):
                            i["ipsPolicy"] = {"id": ips_uuid, "type": "IntrusionPolicy"}
                            changed = True
                        if changed:
                            del i["links"]
                            del i["metadata"]
                            i["sendEventsToFMC"] = True
                            self.bulk_access_rules.append(i)
                    elif i["action"] == "BLOCK":
                        if not any([i["enableSyslog"], i["logBegin"]]):
                            del i["links"]
                            del i["metadata"]
                            i["enableSyslog"] = True
                            i["logBegin"] = True
                            i["sendEventsToFMC"] = True
                            self.bulk_access_rules.append(i)
            except (TypeError, KeyError):
                pass

    def put_access_rules(self, domain_uuid, policy_uuid):
        if len(self.bulk_access_rules) == 0:
            print("Skipping to updated Firewall Rules")
            sys.exit(0)
        else:
            for chunk_rules in chunked(self.bulk_access_rules, 1000):
                self.login()  # To re-login
                endpoint = (
                    f"api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_uuid}/accessrules?bulk=True"
                )
                put_response = requests.put(
                    f"https://{self.fmc_host}/{endpoint}",
                    data=json.dumps(chunk_rules),
                    headers=self.headers,
                    verify=False,
                )
                status_code = put_response.status_code
                if status_code == 200:
                    pprint(f"Bulk rules are successfully updated")
                    self.deploy_devices(domain_uuid)
                else:
                    pprint(f"Error: Bulk rules failed to updated, Status Code: {status_code}")
                    pprint(put_response.json())
                    print("\n")

    def has_deployed(self, url):
        get_response = requests.get(f"{url}", headers=self.headers, verify=False)
        get_response = get_response.json()
        print("\n")
        try:
            while get_response["status"] != "Deployed":
                time.sleep(30)
                print(get_response["message"])
                get_response = requests.get(f"{url}", headers=self.headers, verify=False)
                get_response = get_response.json()
        except KeyError:
            pass
        return True

    def deploy_devices(self, domain_uuid):
        response = self.get_request(
            f"api/fmc_config/v1/domain/{domain_uuid}/deployment/deployabledevices?expanded=true"
        )
        firewall_devices = {}
        if response.status_code == 200:
            for i in response.json().get("items", []):
                if i["canBeDeployed"]:
                    firewall_devices[i["device"]["id"]] = i["version"]
        else:
            return []
        if len(firewall_devices) != 0:
            for k, v in firewall_devices.items():
                payload = {
                    "version": v,
                    "deviceList": [k],
                    "forceDeploy": True,
                    "ignoreWarning": True,
                    "type": "DeploymentRequest",
                }
                endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/deployment/deploymentrequests"
                post_response = requests.post(
                    f"https://{self.fmc_host}/{endpoint}", data=json.dumps(payload), headers=self.headers, verify=False
                )
                domain_name = None
                for i in self.domains:
                    if domain_uuid == i["uuid"]:
                        domain_name = i["name"]
                if post_response.status_code != 202:
                    print(f"Error: {domain_name} failed to deploy devices, Status Code: {post_response.status_code}")
                    pprint(post_response.json())
                else:
                    if self.has_deployed(post_response.json()["metadata"]["task"]["links"]["self"]):
                        print(f"\n{domain_name} successfully deployed the firewall devices")


def rest_setup(fmc_host):
    try:
        fmc_obj = RestAPI(fmc_host, FMC_USER, FMC_PASSWORD)
        return fmc_obj
    except ConnectionError:
        print(f"Unable to login to FMC {fmc_host}\n")
        sys.exit(-1)


def main():
    with open("input.txt", "r") as f:
        inputs = f.readlines()[1:]
    for i in inputs:
        host, domain, acp, ips = i.split()
        fmc_obj = rest_setup(host)
        domain_uuid = fmc_obj.get_domain_uuid(domain)
        fmc_obj.fetch_policies(domain_uuid)
        acp_uuid = fmc_obj.get_policy_uuid(acp)
        fmc_obj.fetch_intrusion_policies(domain_uuid)
        ips_uuid = fmc_obj.get_intrusion_policy_uuid(ips)
        fmc_obj.fetch_access_rules(domain_uuid, acp_uuid)
        fmc_obj.get_bulk_access_rules(ips_uuid)
        fmc_obj.put_access_rules(domain_uuid, acp_uuid)
        del fmc_obj


if __name__ == "__main__":
    main()
