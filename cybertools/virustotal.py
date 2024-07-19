"""Tool for the VirusTotal API v3."""

__author__ = "Paolo Di Prodi"
__copyright__ = "Copyright 2024, Priam Cyber AI ltd"
__credits__ = []
__license__ = "Affero GPL"
__version__ = "0.1"
__maintainer__ = "Paolo Di Prodi"
__email__ = "info@priam.ai"
__status__ = "Development"

from typing import Any, Dict, Optional

import base64
import aiohttp
import requests
from langchain_core.callbacks import (
    AsyncCallbackManagerForToolRun,
    CallbackManagerForToolRun,
)
from langchain_core.pydantic_v1 import Field
from langchain_core.tools import BaseTool
from langchain_core.pydantic_v1 import BaseModel, root_validator
from langchain_core.utils import get_from_dict_or_env
import datetime


class VirusTotalReportTool(BaseTool):
    """Tool that queries IOC reports from the VirusTotal API"""

    name: str = "virustotalapi"
    description: str = (
        "Threat intelligence API provided by virustotal.com"
        "This tool is handy when you need to get reports from indicators of compromise (aka IOC) such as an ip address, a file hash, url, or a domain."
        "To use the tool, you must provide at least two of the following parameters "
        "['ioc_value','ioc_type']."

        " Supports the following IOC types:"
        " 'ipv4address': IP Address (e.g., '1.2.3.4'),'domain': Domain Name (e.g., 'example.com'),'filehash': File Hash (e.g., 'd41d8cd98f00b204e9800998ecf8427e')"
        " 'url': URL ( e.g., 'https://www.priam.ai/blogs/virtual-soc')"
        " 'analysis_id': Analysis ID (e.g., 'd41d8cd98f00b204e9800998ecf8427e')"
        "'threat_categories': Popular Threat Categories"
        " 'attack_tactic': Attack Tactic ID (e.g., 'TA0043')"
        " 'attack_technique': Attack Technique ID (e.g., 'T1548')"
        " 'comments': Comments (e.g., 'malware')"
        "'behavior': Behavior Summary of a File (e.g., 'd41d8cd98f00b204e9800998ecf8427e') " 

        "If a file hash has been given and the behaviour details are asked, then ioc type needs to be behavior "
        "If there is any mention of comments the ioc_type needs be comments " 
        "The IOC value for popular threat categories is none "    
        "For example to get a report about the IP address 1.2.3.4 the parameters are: ['1.2.3.4','ipv4address']"
    )

    base_url: str = "https://www.virustotal.com/api/v3"

    @root_validator()
    def validate_environment(cls, values: Dict) -> Dict:
        """Validate that API key exists in environment."""
        virustotal_api_key = get_from_dict_or_env(
            values, "virustotal_api_key", "VIRUSTOTAL_API_KEY"
        )
        values["virustotal_api_key"] = virustotal_api_key
        return values


    def _run(self, ioc_value: str,ioc_type:str, **kwargs: Any) -> str:
        results = self.results(ioc_value,ioc_type, **kwargs)
        return self._result_as_string(results,"Report")

    async def _arun(self, ioc_value: str,ioc_type:str, **kwargs: Any) -> str:
        results = await self.aresults(ioc_value,ioc_type, **kwargs)
        return self._result_as_string(results)

    def results(self, ioc_value: str,ioc_type:str, **kwargs: Any) -> dict:
        results = self._search_api_results(ioc_value,ioc_type, **kwargs)
        return results

    async def aresults(self, ioc_value: str,ioc_type:str, **kwargs: Any) -> dict:
        results = await self._async_search_api_results(ioc_value,ioc_type, **kwargs)
        return results

    def _prepare_request(self, ioc_value: str,ioc_type:str=None,**kwargs: Any) -> dict:
        """Prepare the request details for each of the VirusTotal API Endpoints based on IOC type and value."""

        ioc_type_mapping = {
            "ipv4address": f"ip_addresses/{ioc_value}",
            "domain": f"domains/{ioc_value}",
            "filehash": f"files/{ioc_value}",
            "url": f"urls/{base64.urlsafe_b64encode(ioc_value.encode()).decode().strip('=')}",
            "analysis_id": f"analyses/{ioc_value}",
            "threat_categories": "popular_threat_categories",
            "attack_tactic": f"attack_tactics/{ioc_value}",
            "attack_technique": f"attack_techniques/{ioc_value}",
            "comments": f"comments?filter=tag%3A{ioc_value}&limit=1",
            "behavior": f"files/{ioc_value}/behaviour_summary",
    }

        if ioc_type not in ioc_type_mapping:
            return {}

        """ Based on the ioc type select from the dic and create the url """
        url = f"{self.base_url}/{ioc_type_mapping[ioc_type]}"

        info = {
        "url": url,
        "headers": {
            "x-apikey": f"{self.virustotal_api_key}",
        },           
        "params": {
            **{key: value for key, value in kwargs.items() if value is not None},
            },
        }
        return info
        
    def _search_api_results(self, ioc_value:str,ioc_type:str, **kwargs: Any) -> dict:
        request_details = self._prepare_request(ioc_value,ioc_type, **kwargs)
        try:
            response = requests.get(
                url=request_details["url"],
                params=request_details["params"],
                headers=request_details["headers"],
            )
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.HTTPError as http_err:
            print(f"Error: The IOC value might be incorrect or not found. HTTP Error: {http_err}")
            return {"error": "Incorrect IOC value or not found"}
        
    async def _async_search_api_results(self, query: str, **kwargs: Any) -> dict:
        """Use aiohttp to send request to SearchApi API and return results async."""
        request_details = self._prepare_request(query, **kwargs)
        try:
            if not self.aiosession:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url=request_details["url"],
                        headers=request_details["headers"],
                        params=request_details["params"],
                        raise_for_status=True,
                    ) as response:
                        results = await response.json()
            else:
                async with self.aiosession.get(
                    url=request_details["url"],
                    headers=request_details["headers"],
                    params=request_details["params"],
                    raise_for_status=True,
                ) as response:
                    results = await response.json()
            return results
        
        except aiohttp.ClientResponseError as http_err:
            print(f"Error: The IOC value might be incorrect or not found. HTTP Error: {http_err}")
            return {"error": "Incorrect IOC value or not found"}
        
    @staticmethod
    def _result_as_string(result: dict, root_key:None) -> str:
        '''
        Conver the json output report into a natural text

        '''

        def case_fix(snake_str:str):
            spaces = snake_str.replace("_"," ")
            return spaces.capitalize()

        # each line of the report
        lines = []

        if len(result.keys()) == 0:
            return "\n".join(lines)

        # reformat the titles
        if root_key:
            title = case_fix(root_key)
            lines.append(title+"\n")

        for key,value in result.items():
            if type(value) == dict:
                new_lines = VirusTotalReportTool._result_as_string(value,key)
                lines.append(new_lines)

            if type(value) == str:
                if key == "id": lines += [f"Indicator value: {value}"]
                elif key == "type": lines += [f"Indicator type: {value}"]
                elif key == "self": lines += [f"Report URL: {value}"]
                else:
                    sub_title  = case_fix(key)
                    lines += [f"{sub_title}: {value}"]
            if type(value) == int:
                if "date" in key or "timestamp" in key:
                    # this could be a datetime
                    dt = datetime.datetime.utcfromtimestamp(value)
                    sub_title  = case_fix(key)
                    lines += [f"{sub_title}: {dt.isoformat()}"]

                else:
                    sub_title = case_fix(key)
                    lines += [f"{sub_title}: {value}"]

            if type(value) == list:

                if len(value)>0:
                    sub_title = case_fix(key)

                    for subvalue in value:
                        if type(subvalue) == str:
                            lines += [f"{sub_title}: {subvalue}"]
                        elif type(subvalue) == dict:
                            new_lines = VirusTotalReportTool._result_as_string(subvalue, key)
                            lines.append(new_lines)
                else:
                    lines += [f"{sub_title}: empty"]

        return "\n".join(lines)


