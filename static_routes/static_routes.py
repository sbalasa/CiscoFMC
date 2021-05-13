"""
Runner for Cisco FMC Toolkit to create Static Routes
Author: Santhosh Balasa
"""

import sys
import json
import yaml
import time
import click
import pandas
import warnings
import requests


from pprint import pprint
from tabulate import tabulate
from static_route_template import StaticRoute
from requests.exceptions import ConnectionError

warnings.simplefilter(action="ignore", category=FutureWarning)


# Global
FMC_HOST = None
FMC_USER = None
FMC_PASSWORD = None
EXCEL_FILE = None
SHEET_NAME = None
START_RANGE = None
END_RANGE = None
DEPLOY = True


requests.packages.urllib3.disable_warnings()
warnings.simplefilter(action="ignore", category=FutureWarning)


class RestAPI:
    def __init__(self, fmc_host, username, password):
        self.fmc_host = fmc_host
        self.headers = {}
        self.domains = []
        self.device_records = []
        self.network_objects = []
        self.login(username, password)

    def login(self, username, password):
        # Url for posting login data
        base_url = f"https://{self.fmc_host}"
        login_url = base_url + "/api/fmc_platform/v1/auth/generatetoken"
        _headers = {"Content-Type": "application/json", "Connection": "Keep-Alive"}
        login_response = requests.post(
            login_url, headers=_headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False
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

    def fetch_device_records(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords")
        if response.status_code == 200:
            self.device_records = response.json()["items"]
        else:
            return []

    def fetch_network_objects(self, domain_uuid):
        response = self.get_request(f"api/fmc_config/v1/domain/{domain_uuid}/object/networks?offset=0&limit=1000")
        if response.status_code == 200:
            self.network_objects = response.json()["items"]
            for i in response.json().get("paging", {}).get("next", []):
                get_response = requests.get(i, headers=self.headers, verify=False)
                if get_response.status_code == 200:
                    self.network_objects.extend(get_response.json()["items"])
        else:
            return []

    def get_domain_uuid(self, domain_name):
        for i in self.domains:
            if i["name"] == domain_name:
                return i["uuid"]

    def get_ftd_uuid(self, ftd_ip):
        for i in self.device_records:
            if i["name"] == ftd_ip:
                return i["id"]

    def get_network_uuid(self, network_name):
        for i in self.network_objects:
            if i["name"] == network_name:
                return i["id"]

    def post_request(self, endpoint, body):
        get_response = requests.post(
            f"https://{self.fmc_host}/{endpoint}", data=json.dumps(body), headers=self.headers, verify=False
        )
        return get_response

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
                        print(f"\n{domain_name} successfully deployed the Static Routes")
            print("\nPlease verify the Static Routes and device deployment status on FMC Web GUI")


def rest_setup():
    try:
        fmc_obj = RestAPI(FMC_HOST, FMC_USER, FMC_PASSWORD)
        return fmc_obj
    except ConnectionError:
        print(f"Unable to login to FMC {FMC_HOST}\n")
        sys.exit(-1)


def generate_globals(config_file):
    with open(config_file, "r") as f:
        fmc_info = yaml.safe_load(f)
    global FMC_HOST, FMC_USER, FMC_PASSWORD, EXCEL_FILE, SHEET_NAME, START_RANGE, END_RANGE, DEPLOY
    FMC_HOST = fmc_info["fmc_device"]["host_ip"].strip()
    FMC_USER = fmc_info["fmc_device"]["username"].strip()
    FMC_PASSWORD = fmc_info["fmc_device"]["password"].strip()
    EXCEL_FILE = fmc_info["excel"]["file_path"].strip()
    SHEET_NAME = fmc_info["excel"]["sheet_name"].strip()
    START_RANGE = fmc_info["excel"]["rows_range"]["start"] - 1
    END_RANGE = fmc_info["excel"]["rows_range"]["end"]
    DEPLOY = fmc_info["ftd_deploy"]


@click.command()
@click.option(
    "--config_file",
    type=click.Path(exists=True),
    required=True,
    help="Pass fmc device configs in a yml file Eg: static_config.yml",
)
def main(config_file):
    """
    SRIT: Static Routes Inducer Tool

        This tool is used to create Static Routes in Cisco FMC.
    """
    generate_globals(config_file)
    fmc_obj = rest_setup()
    domain_uuid = None
    ftd_uuid = None
    data = pandas.read_excel(EXCEL_FILE, sheet_name=SHEET_NAME)
    bulk_static_routes = []

    print(tabulate(data.iloc[START_RANGE:END_RANGE, [0, 1, 3, 4, 5]], headers="keys", tablefmt="psql", showindex=False))
    if input("Enter ok to create the above Static Routes: ") != "ok":
        sys.exit(-1)
    print("Processing... Please wait")

    for i in data.values:  # Execute only once
        domain_uuid = fmc_obj.get_domain_uuid(i[2])
        fmc_obj.fetch_device_records(domain_uuid)
        ftd_uuid = fmc_obj.get_ftd_uuid(i[5])
        fmc_obj.fetch_network_objects(domain_uuid)
        break

    for i in data.values[START_RANGE:END_RANGE]:
        static_route = StaticRoute(i[3], fmc_obj.get_network_uuid(i[1]), i[1], i[4]).to_json()
        bulk_static_routes.append(static_route)
    if len(bulk_static_routes) > 1000:
        print("Error: Bulk Static Routes cannot be more than 1000, change the range in static_config.yml")
        sys.exit(-1)

    response = fmc_obj.post_request(
        f"/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ipv4staticroutes?bulk=True",
        bulk_static_routes,
    )
    status_code = response.status_code
    if status_code == 201:
        pprint(f"{len(bulk_static_routes)} Static Routes are successfully created")
    else:
        pprint(f"Error: Bulk Static Routes failed to create, Status Code: {status_code}")
        pprint(response.json())
        print("\n")
    # Deploy to Firewall Devices
    if DEPLOY:
        fmc_obj.deploy_devices(domain_uuid)


if __name__ == "__main__":
    main()
