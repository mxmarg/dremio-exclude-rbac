import dremio_api
import logging

logger = logging.getLogger(__name__)


def match_exclude_folder(object_path: list, config: dict) -> bool:
    if len(object_path) == 0:
        raise ValueError(f"Invalid object path: {object_path}")
    for p in config["EXCLUDING FOLDER PATHS"]:
        if p[:len(object_path)] == object_path:
            return True
    return False


def traverse_dremio_catalog(api: dremio_api.DremioAPI, config: dict) -> list:
    logger.info(f"Retrieving catalog from {api.dremio_url} ...")
    catalog_root = api.get_catalog()
    catalog_entries = []
    for entry in catalog_root['data']:
        container_type = entry.get('containerType')
        if container_type == 'SPACE':
            catalog_id = entry['id']
            if entry['path'][0] != config["ON SCOPE PATH"][0]:
                logger.info(f"Skipping SPACE {entry['path']} based on space scope config.")
            else:
                logger.info(f"Traversing SPACE {entry['path']} ...")
                catalog_entries = traverse_child_folders(api, catalog_entries, catalog_id, config)
        else:
            logger.debug(f"Skipping container type {container_type}")
    return catalog_entries


def traverse_child_folders(api: dremio_api.DremioAPI, catalog_entries: list, catalog_id: str, config: dict) -> list:
    catalog_sub_tree = api.get_catalog(catalog_id)
    for child in catalog_sub_tree['children']:
        container_type = child.get('containerType')
        catalog_id = child['id']
        if child['type'] == 'CONTAINER' and container_type == 'FOLDER':
            folder_path = child['path']
            path_matches_exclude_folder = match_exclude_folder(folder_path, config)
            if path_matches_exclude_folder:
                logger.info(f"Excluding folder path {folder_path} from RBAC privilege scope ...")
                logger.info(f"Traversing FOLDER {child['path']} ...")
                catalog_entries = traverse_child_folders(api, catalog_entries, catalog_id, config)
            else:
                logger.info(f"Adding folder path {folder_path} to RBAC privilege scope ...")
                catalog_entries.append({
                    "id": catalog_id,
                    "folder_path": folder_path
                })
        else:
            logger.debug(f"Skipping non-folder object {container_type} at {child['path']}")

    return catalog_entries

