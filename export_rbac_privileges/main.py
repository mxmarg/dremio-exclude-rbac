from configparser import ConfigParser
import logging
import dremio_api
import json
import os
import urllib3
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(handlers=[
                        logging.FileHandler("dremio_export_rbac_privileges.log"),
                        logging.StreamHandler()
                    ],
                    format="%(levelname)s\t%(asctime)s - %(message)s",
                    level=logging.DEBUG)
logger = logging.getLogger(__name__)


def generate_grant_sql(data: dict):
    privileges: list[str] = data["rows"]
    sql_statements = []

    for row in privileges:
        privilege = row["privilege"]
        object_type = row["object_type"]
        object_id = row["object_id"]
        grantee_type = row["grantee_type"]
        grantee_id = row["grantee_id"]


        privilege = privilege.replace("_", " ")

        sql = f'GRANT {privilege} ON {object_type} {object_id} TO {grantee_type} "{grantee_id}";'

        if object_type in {"SCRIPT"}:
            continue
        if grantee_type.upper() in {"USER"}:
            logger.warn(f"Skipping user privilege {sql}")
            continue

        sql_statements.append(sql)
    
    return sql_statements


if __name__ == '__main__':

    # Read Dremio credentials and config from files
    filepath_dir = os.path.dirname(os.path.abspath(__file__))
    parser = ConfigParser()
    credentials_file = os.path.join(filepath_dir, "../credentials.cfg")
    logger.info(f"Attempting to read credentials from {credentials_file}")
    _ = parser.read(credentials_file)
    DREMIO_PAT = parser.get('Authentication', 'dremio_pat')
    DREMIO_ENDPOINT = parser.get('Authentication', 'dremio_endpoint')

    api = dremio_api.DremioAPI(DREMIO_PAT, DREMIO_ENDPOINT, timeout=60)
    job_id = api.post_sql_query("SELECT grantee_id, grantee_type, privilege, object_id, object_type FROM sys.privileges;")
    data = api.get_query_data(job_id, limit=500)

    with open("sys.privileges.json", 'w') as f:
        json.dump(data, f)
    
    grant_statements = generate_grant_sql(data)

    filename = 'grant_statements.sql'
    with open(filename, 'w') as f:
        for line in grant_statements:
            f.write(f"{line}\n")

    logger.info(f"Created {filename}")
