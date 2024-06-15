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
        
    # Validate if roles exist in AD?
    # TBD

    # Validate folder privileges (Source: https://docs.dremio.com/current/security/rbac/privileges/#folder-privileges)
    DREMIO_FOLDER_PRIVILEGES = {
        "ALTER",
        "ALTER REFLECTION",
        "MANAGE GRANTS",
        "MODIFY",
        "OWNERSHIP",
        "READ METADATA",
        "SELECT",
        "VIEW REFLECTION",
    }
    for p in config["GRANT PRIVILEGES"]:
        if p not in DREMIO_FOLDER_PRIVILEGES:
            raise ValueError(f'Unexpected privilege "{p}" for type folder, please see the Dremio docs for supported privileges: https://docs.dremio.com/current/security/rbac/privileges/#folder-privileges')


def generate_grant_sql(config: dict, catalog_entries: list[dict]):
    privileges: list[str] = config["GRANT PRIVILEGES"]
    grantee_roles: list[str] = config["TO ROLES"]
    sql_statements = []

    for privilege in privileges:
        for c in catalog_entries:
            folder = '"."'.join(c["folder_path"])
            for role in grantee_roles:
                sql_statements.append(f'GRANT {privilege} ON FOLDER "{folder}" TO ROLE "{role}";')
    
    return sql_statements


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
            "demo_space"
        ],
        "EXCLUDING FOLDER PATHS": [
            [
                "demo_space",
                "subfolder",
                "app1"
            ],
            [
                "demo_space",
                "subfolder2",
                "subsubfolder2_2",
                "app2"
            ],
        ],
        "TO ROLES": [
            "Role1",
            "Role2"
        ]
    }

    api = dremio_api.DremioAPI(DREMIO_PAT, DREMIO_ENDPOINT, timeout=60)
    validate_config(config)
    catalog_entries = traverse_dremio_catalog(api, config)
    sql_statements = generate_grant_sql(config, catalog_entries)

    # Results
    print("\n__________")
    print("Pseudo-SQL:")
    print(f"""
          GRANT {config["GRANT PRIVILEGES"]} 
          ON SPACE/FOLDER {config["ON SCOPE PATH"]} 
          EXLCUDING FOLDER(s) {config["EXCLUDING FOLDER PATHS"]} 
          TO ROLE(s) {config["TO ROLES"]};
          """)
    print("The following SQL statements need to be run in order to provide the same scope as the pseudo-SQL above:")
    print("\n__________")
    for sql in sql_statements:
        print(sql)
    print("__________\n")

