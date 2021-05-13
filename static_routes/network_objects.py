import sys
import json
import yaml
import click
import pandas
import warnings
import requests


from pprint import pprint
from tabulate import tabulate
from requests.exceptions import ConnectionError

warnings.simplefilter(action="ignore", category=FutureWarning)


# Global
FMC_HOST = None
FMC_USER = None
FMC_PASSWORD = None
FMC_DOMAIN = None
EXCEL_FILE = None
SHEET_NAME = None
START_RANGE = None
END_RANGE = None


requests.packages.urllib3.disable_warnings()
warnings.simplefilter(action="ignore", category=FutureWarning)


class RestAPI:
    def __init__(self, fmc_host, username, password):
        self.fmc_host = fmc_host
        self.access_token = None
        self.refresh_token = None
        self.domains = []
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

    def get_domain_uuid(self, domain_name):
        for i in self.domains:
            if i["name"] == domain_name:
                return i["uuid"]

    def post_request(self, endpoint, body):
        headers = {"Content-Type": "application/json", "X-auth-access-token": self.access_token}
        get_response = requests.post(
            f"https://{self.fmc_host}/{endpoint}", data=json.dumps(body), headers=headers, verify=False
        )
        return get_response


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
    global FMC_HOST, FMC_USER, FMC_PASSWORD, FMC_DOMAIN, EXCEL_FILE, SHEET_NAME, START_RANGE, END_RANGE
    FMC_HOST = fmc_info["fmc_device"]["host_ip"].strip()
    FMC_USER = fmc_info["fmc_device"]["username"].strip()
    FMC_PASSWORD = fmc_info["fmc_device"]["password"].strip()
    FMC_DOMAIN = fmc_info["fmc_device"]["domain"].strip()
    EXCEL_FILE = fmc_info["excel"]["file_path"].strip()
    SHEET_NAME = fmc_info["excel"]["sheet_name"].strip()
    START_RANGE = fmc_info["excel"]["rows_range"]["start"] - 1
    END_RANGE = fmc_info["excel"]["rows_range"]["end"]


@click.command()
@click.option(
    "--config_file",
    type=click.Path(exists=True),
    required=True,
    help="Pass fmc device configs in a yml file Eg: config.yml",
)
def main(config_file):
    """
    This tool is used to create Network Objects in Cisco FMC.
    """
    generate_globals(config_file)
    fmc_obj = rest_setup()
    domain_uuid = fmc_obj.get_domain_uuid(FMC_DOMAIN)
    data = pandas.read_excel(EXCEL_FILE, sheet_name=SHEET_NAME)
    print(tabulate(data.iloc[START_RANGE:END_RANGE, [0, 1, 2]], headers="keys", tablefmt="psql", showindex=False))
    if input("Enter ok to create the above Network Objects: ") != "ok":
        sys.exit(-1)
    body = []
    for i in data.values[START_RANGE:END_RANGE]:
        body.append(
            {
                "name": i[1].strip(),
                "value": i[2].strip(),
                "type": "Network",
            }
        )
    if len(body) > 1000:
        print("Error: Bulk Network Objects cannot be more than 1000")
        sys.exit(-1)
    print("Processing... Please wait")
    response = fmc_obj.post_request(f"/api/fmc_config/v1/domain/{domain_uuid}/object/networks?bulk=True", body)
    status_code = response.status_code
    if status_code != 201:
        print(f"Failed to create Network Objects")
        pprint(response.json())
    elif status_code == 201:
        print(f"{len(body)} Network Objects are created successfully")
    else:
        print(f"Failed with Status Code: {status_code}")
        pprint(response.json())


if __name__ == "__main__":
    main()
