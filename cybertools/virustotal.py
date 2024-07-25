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
from tiktoken import get_encoding

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
        " 'threat_categories': Popular Threat Categories"
        " 'attack_tactic': Attack Tactic ID (e.g., 'TA0043')"
        " 'attack_technique': Attack Technique ID (e.g., 'T1548')"
        " 'comments': Comments (e.g., 'malware')"
        " 'behavior': Behavior Summary of a File (e.g., 'd41d8cd98f00b204e9800998ecf8427e') " 

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

        """ Based on the ioc type prepare the url """
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
        Convert the json output report into a natural text.
        Depending on the IOC responses might be different

        '''
        def case_fix(snake_str:str):
            spaces = snake_str.replace("_"," ")
            return spaces.capitalize()
        
        def ip_details(result):
            details = []
            attributes = result.get('attributes', {})

            # Extract key IP address information
            details.append(f"IP Address: {result.get('id')}")
            details.append(f"Reputation: {attributes.get('reputation')}")
            details.append(f"Continent: {attributes.get('continent')}")
            details.append(f"Country: {attributes.get('country')}")
            details.append(f"ASN: {attributes.get('asn')}")
            details.append(f"AS Owner: {attributes.get('as_owner')}")

            return f"\nIP Address Analysis Report:\n" + "\n".join(details)
                
        def domain_details(domain_data):
            details = []
            attributes = result.get('attributes', {})

            # Extract General domain information
            details.append(f"id: {domain_data.get('id')}")
            details.append(f"reputation: {attributes.get('reputation')}")
            details.append(f"registrar: {attributes.get('registrar')}")
            details.append(f"Top Level Domain: {attributes.get('tld')}")

            return f"\nDomain Analysis Report:\n" + "\n".join(details)


        def file_details(result):
          details = []
          attributes = result.get('attributes', {})

         #Extract general file information
          details.append(f"id: {result.get('id')}")
          details.append(f"extension: {attributes.get('type_extension')}")
          details.append(f"reputation: {attributes.get('reputation')}")

          return f"\nFile Analysis Report:\n" + "\n".join(details)

        def url_details(url_data):
           
            details = []
            attributes = url_data.get('attributes', {})

            details.append(f"id: {url_data.get('id')}")
            details.append(f"last_final_url: {attributes.get('last_final_url')}")
            details.append(f"reputation: {attributes.get('reputation')}")
            details.append(f"times_submitted: {attributes.get('times_submitted')}")
            details.append(f"total_votes: {attributes.get('total_votes')}")
            details.append(f"last_http_response_code: {attributes.get('last_http_response_code')}")
            details.append(f"last_http_response_content_length: {attributes.get('last_http_response_content_length')} bytes")

            return f"\nURL Analysis Report:\n" + "\n".join(details)

            
        # each line of the report
        lines = []

        if len(result.keys()) == 0:
            return "\n".join(lines)

        # reformat the titles
        if root_key:
            title = case_fix(root_key)
            lines.append(title+"\n")

        ioc_type = result.get("type")
        
        """
            Each response is slightly different depending on the IOC type.
            Extracting to present General information. 
        """

        if ioc_type == "file":  lines.append(file_details(result))
        elif ioc_type == "url": lines.append(url_details(result))
        elif ioc_type == "ip_address": lines.append(ip_details(result))
        elif ioc_type == "domain": lines.append(domain_details(result))
        

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
            report_string = "\n".join(lines)
        
        # Truncate the report string to fit within the token limit
        truncated_report_string = VirusTotalReportTool._truncate_to_token_limit(report_string)
        
        return truncated_report_string
        
    @staticmethod
    def _truncate_to_token_limit( text: str, token_limit: int = 14000) -> str:
        """
        Truncates the report if it exceeds the llm model's token limit
        """
        
        encoding = get_encoding("cl100k_base")
        tokens = encoding.encode(text)
        
        if len(tokens) > token_limit:
            truncated_tokens = tokens[:token_limit]
            truncated_text = encoding.decode(truncated_tokens)
            print("Warning: Output truncated to fit token limit.")
            return truncated_text
        
        return text


