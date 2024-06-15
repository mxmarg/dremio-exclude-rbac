import logging
import dremio_api
from traverse_catalog import traverse_dremio_catalog
import os
import sys
import urllib3
urllib3.disable_warnings()

dir_path = os.path.dirname(os.path.realpath(__file__))

# Configure logging
logging.basicConfig(stream=sys.stdout,
                    format="%(levelname)s\t%(asctime)s - %(message)s",
                    level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_config(config: dict):

    # Validate that config dict contains all expected fields
    EXPECTED_FIELDS = [
        "GRANT PRIVILEGES",
        "ON SCOPE PATH",
        "EXCLUDING FOLDER PATHS",
        "TO ROLES"
        ]
    for f in EXPECTED_FIELDS:
        if f not in config:
            raise KeyError(f"Expected field {f} not found in config: {config}")
    
    # Validate that the excluded folder path(s) are located underneath the defined privilege scope path
    scope_path = config["ON SCOPE PATH"]
    for p in config["EXCLUDING FOLDER PATHS"]:
        if p[:len(scope_path)] != scope_path:
            raise ValueError(f"Folder path exclusion {p} does not match a subtree of the scope path {scope_path}")
        if len(p) == len(scope_path):
            raise ValueError(f"Folder path exclusion {p} cannot be the same depth as the scope path {scope_path}")



if __name__ == '__main__':

    DREMIO_ENDPOINT = ""
    DREMIO_PAT = ""
    
    config = {
        "GRANT PRIVILEGES": [
            "SELECT",
            "ALTER",
            "VIEW REFLECTION"
        ],
        "ON SCOPE PATH": [
            "demo_space",
            "subfolder"
        ],
        "EXCLUDING FOLDER PATHS": [
            [
                "demo_space",
                "subfolder",
                "app1"
            ],
            [
                "demo_space",
                "subfolder",
                "AppFolder2"
            ],
        ],
        "TO ROLES": [
            "User1"
        ]
    }

    api = dremio_api.DremioAPI(DREMIO_PAT, DREMIO_ENDPOINT, timeout=60)
    validate_config(config)
    catalog_entries = traverse_dremio_catalog(api, config)

    # Results
    print("The following folders are in the scope:")
    for c in catalog_entries:
        print(c)
