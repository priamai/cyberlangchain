""""
Stores and manages reports for IOCs. Provides a test set for API response validation.
"""
import os
import json


BASE_DIR = "API_CACHE"

def cache_response(tool: str,  ioc_value: str, ioc_type: str, response: dict):
    """Caches the response from an API call based on the IOC value and type."""


    tool_cache_dir = os.path.join(BASE_DIR, tool)

    if not os.path.exists(tool_cache_dir):
        os.makedirs(tool_cache_dir)

    filename = f"{tool_cache_dir}/{ioc_type.lower()}_{ioc_value}.json"
    
    with open(filename, 'w') as file:
        json.dump(response, file)


def load_cached_response(tool: str ,ioc_value: str, ioc_type: str) -> dict:
    """ Loads a cached API response based on the IOC value and type. """
    
    tool_cache_dir = os.path.join(BASE_DIR, tool)

    filename = f"{tool_cache_dir}/{ioc_type.lower()}_{ioc_value}.json"
    
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return None
