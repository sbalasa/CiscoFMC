"""
Main runner for Cisco FMC Toolkit.
"""

import sys
import json
import time
import pandas
import warnings
import requests


from pprint import pprint
from tabulate import tabulate
from policy_template import Policy
from segregate_networks import split_ports, split_zones, split_networks
from requests.exceptions import ConnectionError


requests.packages.urllib3.disable_warnings()
warnings.simplefilter(action="ignore", category=FutureWarning)


# Global
FMC_HOST = sys.argv[1]
FMC_USER = sys.argv[2]
FMC_PASSWORD = sys.argv[3]
EXCEL_FILE = sys.argv[4]
SHEET_NAME = sys.argv[5]
START_RANGE = int(sys.argv[6]) - 1
END_RANGE = int(sys.argv[7])


class RestAPI:
    def __init__(self, fmc_host, username, password):
        self.fmc_host = fmc_host
        self.access_token = None
        self.refresh_token = None
        self.domains = []
        self.policies = []
        self.zones = []
        self.intrusion_policies = []
        self.login(username, password)

    def login(self, username, password):
        # Url for posting login data
        base_url = f"https://{self.fmc_host}"
        login_url = base_url + "/api/fmc_platform/v1/auth/generatetoken"
        headers = {"Content-Type": "application/json", "Connection": "Keep-Alive"}
        login_response = requests.post(
            login_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False
        )
        self.access_token = login_response.headers.get("X-auth-access-token", default=None)
        self.refresh_token = login_response.headers.get("X-auth-refresh-token", default=None)
        if self.access_token and self.refresh_token:
            self.domains = json.loads(login_response.headers.get("DOMAINS", "[]"))
        else:
            print("Login Token not found. Exiting...")
            sys.exit(-1)

    def get_request(self, endpoint):
        headers = {"Content-Type": "application/json", "X-auth-access-token": self.access_token}
        get_response = requests.get(f"https://{self.fmc_host}/{endpoint}", headers=headers, verify=False)
        return get_response

    def get_zones(self):
        return self.zones

    def fetch_policies(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies")
        if response.status_code == 200:
            self.policies = json.loads(response.text)["items"]
        else:
            return []

    def fetch_zones(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/object/securityzones?offset=0&limit=200")
        if response.status_code == 200:
            self.zones = json.loads(response.text)["items"]
        else:
            return []

    def fetch_intrusion_policies(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies")
        if response.status_code == 200:
            self.intrusion_policies = json.loads(response.text)["items"]
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

    def create_access_rule(self, domain_uuid, policy_uuid, bulk_policies, refresh_token=False):
        if refresh_token:
            headers = {
                "Content-Type": "application/json",
                "X-auth-access-token": self.access_token,
                "X-auth-refresh-token": self.refresh_token,
            }
        else:
            headers = {"Content-Type": "application/json", "X-auth-access-token": self.access_token}
        endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_uuid}/accessrules"
        post_response = requests.post(
            f"https://{self.fmc_host}/{endpoint}", data=json.dumps(bulk_policies), headers=headers, verify=False
        )
        return post_response

    def has_deployed(self, url):
        headers = {"Content-Type": "application/json", "X-auth-access-token": self.access_token}
        get_response = requests.get(f"{url}", headers=headers, verify=False)
        get_response = json.loads(get_response.text)
        print("\n")
        try:
            while get_response["status"] != "Deployed":
                time.sleep(30)
                print(get_response["message"])
                get_response = requests.get(f"{url}", headers=headers, verify=False)
                get_response = json.loads(get_response.text)
        except KeyError:
            pass
        return True

    def deploy_devices(self, domain_uuid):
        response = self.get_request(
            f"api/fmc_config/v1/domain/{domain_uuid}/deployment/deployabledevices?expanded=true"
        )
        firewall_devices = {}
        if response.status_code == 200:
            for i in json.loads(response.text).get("items", []):
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
                headers = {"Content-Type": "application/json", "X-auth-access-token": self.access_token}
                endpoint = f"api/fmc_config/v1/domain/{domain_uuid}/deployment/deploymentrequests"
                post_response = requests.post(
                    f"https://{self.fmc_host}/{endpoint}", data=json.dumps(payload), headers=headers, verify=False
                )
                domain_name = None
                for i in self.domains:
                    if domain_uuid == i["uuid"]:
                        domain_name = i["name"]
                if post_response.status_code != 202:
                    print(f"Error: {domain_name} failed to deploy devices, Status Code: {post_response.status_code}")
                    pprint(post_response.text)
                else:
                    if self.has_deployed(json.loads(post_response.text)["metadata"]["task"]["links"]["self"]):
                        print(f"\n{domain_name} successfully deployed the firewall devices")
            print("\nPlease verify the firewall access rules and device deployment status on FMC Web GUI")


def rest_setup():
    try:
        fmc_obj = RestAPI(FMC_HOST, FMC_USER, FMC_PASSWORD)
        return fmc_obj
    except ConnectionError:
        print(f"Unable to login to FMC {FMC_HOST}\n")
        sys.exit(-1)


def main():
    fmc_obj = rest_setup()
    data = pandas.read_excel(EXCEL_FILE, sheet_name=SHEET_NAME)
    data = data.replace({pandas.np.nan: None})  # Replace all nan values to None in DataFrame
    pandas.option_context("display.max_colwidth", 0)
    domain_uuid = None
    ins_policy_uuid = None
    policy_uuid = None

    print(tabulate(data.iloc[START_RANGE:END_RANGE, [0, 1, 6, 7, 5]], headers="keys", tablefmt="psql", showindex=False))
    if input("Enter ok to create the above Firewall Rules: ") != "ok":
        sys.exit(-1)

    for i in data.values:
        domain_uuid = fmc_obj.get_domain_uuid(i[8])
        fmc_obj.fetch_policies(domain_uuid)
        fmc_obj.fetch_zones(domain_uuid)
        fmc_obj.fetch_intrusion_policies(domain_uuid)
        policy_uuid = fmc_obj.get_policy_uuid(i[9])
        ins_policy_uuid = fmc_obj.get_intrusion_policy_uuid(i[10])
        break

    for i in data.values[START_RANGE:END_RANGE]:
        source_ports, dest_ports = split_ports(i[4]), split_ports(i[5])
        source_networks, dest_networks = split_networks(i[2], i[3])
        source_zones, dest_zones = split_zones(i[6], i[7], fmc_obj.get_zones())
        rule_name = i[1]
        payload = Policy(
            rule_name,
            source_ports,
            dest_ports,
            source_zones,
            dest_zones,
            source_networks,
            dest_networks,
            i[9],
            ins_policy_uuid,
        ).to_json()
        response = fmc_obj.create_access_rule(domain_uuid, policy_uuid, payload)
        status_code = response.status_code
        if status_code == 201:
            pprint(f"{rule_name} is successfully created")
        elif status_code == 401:
            response = fmc_obj.create_access_rule(domain_uuid, policy_uuid, payload, refresh_token=True)
            status_code = response.status_code
            if status_code == 201:
                pprint(f"{rule_name} is successfully created")
            else:
                pprint(f"Error: {rule_name} failed to create, Status Code: {status_code}")
                pprint(response.json())
                print("\n")
        else:
            pprint(f"Error: {rule_name} failed to create, Status Code: {status_code}")
            pprint(response.json())
            print("\n")
    # Deploy to Firewall Devices
    fmc_obj.deploy_devices(domain_uuid)


if __name__ == "__main__":
    main()
