# Pre-requisites
1. Relevant user and role names are available and can be synched from an external IDP, e.g. Active Directory.

2. Privilege mapping table or view that acts as an ACL per folder and role, e.g.:
```CREATE OR REPLACE VIEW demo_space.app_permission_mapping_table AS 
SELECT DISTINCT * 
FROM ( VALUES 
        ROW('"Workspace1"."A"."Folder x"', 'Role1'),
        ROW('"Workspace1"."B"."Folder y"', 'Role2'),
        ROW('"Workspace2"."A"."Folder y"', 'Role1'),
        ROW('"Workspace2"."C"."Folder c"', 'Role3')
    ) AS v(folder_id_name, role_name);
```

3. Row-access UDF that references the permission mapping table, e.g.:
```CREATE OR REPLACE FUNCTION demo_space.app_permission(lookup_col VARCHAR)
RETURNS BOOLEAN
RETURN SELECT MAX(IS_MEMBER(role_name))
    FROM demo_space.app_permission_mapping_table m
    WHERE m.folder_id_name = lookup_col;
```

4. Views that contain their own folder path (in the same syntax as listed in the `app_permission_mapping_table`) as a lookup column called `lookup_col`, e.g.:
```CREATE OR REPLACE VIEW "Workspace1"."A"."Folder x".app_view1 AS 
SELECT 
    1 AS col1,
    'abc' AS col2,
    '"Workspace1"."A"."Folder x"' AS lookup_col;
```