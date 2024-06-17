# dremio-exclude-rbac
Dremio RBAC script to automate exclusion for specific subfolders from a given privilege scope

# What problem does this script solve?
- Dremio's RBAC privileges only work additively and are inherited by all child objects in a "top-down" fashion from spaces to folders to views
- Typically, access to high-level spaces is granted broadly to members of certain groups (e.g. organisational units)
- Within spaces, admins may want to be able to prevent access to certain app folders from users that are not part of the corresponding certain app role
- -> _This would require "exclusion" statements for RBAC scopes, which is currently not supported by most RBAC designs_
- "Exclusion RBAC" pseudo-SQL: `GRANT SELECT ON SPACE "workspace1" EXCLUDING FOLDER "workspace1.subfolder.appfolder" TO ROLE "Team1";`
- This script with generate the required set of actual SQL statement to achieve the behavior of "exclusion" RBAC

# How to run
- In `credentials.cfg`, set the values for `dremio_endpoint` (REST endpoint) and `dremio_pat` (Personal Access Token, see: [Dremio Docs](https://docs.dremio.com/current/security/authentication/personal-access-tokens/))
- In `config.json`, specify the privileges, scope, excluded scopes, and grantees.
    Pseudo SQL:
        ```GRANT {config["GRANT PRIVILEGES"]} 
        ON SPACE/FOLDER {config["ON SCOPE PATH"]} 
        EXLCUDING FOLDER(s) {config["EXCLUDING FOLDER PATHS"]} 
        TO ROLE(s) {config["TO ROLES"]};```
- Run the script against the Dremio cluster using `python3 main.py`. The script will generate a series of SQL statements, which can then be verified before they are applied as RBAC.