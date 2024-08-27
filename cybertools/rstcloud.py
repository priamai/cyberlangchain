"""Tool for the RST Cloud Threat Intelligence API v1."""


from dateutil import parser
from rstapi import whoisapi, threatfeed, reporthub, noisecontrol, ioclookup
from tiktoken import get_encoding
from typing import Any
from langchain_core.tools import BaseTool
from datetime import datetime
import os
from dotenv import load_dotenv
import cache_util

# RST WHOIS API - (Domain) 
# RST IOC LOOKUP API supports - (IP, Domain, URL, MD5, SHA1, SHA256) 
# RST Noise Control - (allows users to check if a specific indicator of compromise (IOC) is considered benign.) --> DONE
# RST Report HUB - (TI reports for a given date)

load_dotenv()

# Set API KEY from the environment
RSTCLOUD_API_KEY = os.getenv('RSTCLOUD_API_KEY')
if not RSTCLOUD_API_KEY:
    raise EnvironmentError("RSTCLOUD API KEY is not set in environment variables.")

#Initialize API clients with the provided API key for RST Cloud services
whoisapi=whoisapi(APIKEY=RSTCLOUD_API_KEY)
ioclookup=ioclookup(APIKEY=RSTCLOUD_API_KEY)
reporthub=reporthub(APIKEY=RSTCLOUD_API_KEY)
noisecontrol=noisecontrol(APIKEY=RSTCLOUD_API_KEY)
threatfeed=threatfeed(APIKEY=RSTCLOUD_API_KEY)


class RSTcloudReportTool(BaseTool):
    """Tool that queries IOC and Threat Intelligence reports from the RST Cloud API"""

    name: str = "RSTcloudapi"
    description: str = (
        "Threat intelligence API provided by RST cloud. It provides valuable threat intelligence"
        "Available API functionalities:"
        "1. `WHOIS API`: Retrieves WHOIS information for a given domain."
        "2. `IOC Lookup`: Supports queries for IP, Domain, URL, MD5, SHA1, and SHA256."
        "3. `Noise Control`: Checks if a specific IOC is considered benign."
        "4. `Threat Feed`: Provides threat intelligence for IP, Domain, URL, and HASH."
        "5. `Report Hub`: Retrieves threat intelligence reports based on a given date ."

                
        "To use the tool, you must provide  two of the following parameters"
        "['ioc_value','ioc_type']."

        "Supported IOC types:"
        " - 'IP': IP Address (e.g., '1.2.3.4')"
        " - 'DOMAIN': Domain name (e.g., 'example.com')"
        " - 'URL': URL (e.g., 'http://example.com')"
        " - 'HASH': File hash (e.g., 'd41d8cd98f00b204e9800998ecf8427e')"
        " - 'WHOIS': Domain information lookup"


        "To perform a lookup, set the `ioc_type` parameter accordingly:"
        "- Use 'WHOIS' for domain WHOIS lookups."
        "- Use 'BENIGN' to check if an IOC is considered benign."
        "- Use 'REPORT' to retrieve a threat intelligence report."

        "Example usage:"
        "- To get WHOIS information for 'example.com', set `ioc_value='example.com'` and `ioc_type='WHOIS'`."
        "- To check the benign status of an IP address '1.2.3.4', set `ioc_value='1.2.3.4'` and `ioc_type='BENIGN'`."
        "- To retrieve Threat Intelligence report for a specified date 05 th March 2015, always use the yyyymmdd format and set `ioc_value='20150305'` and `ioc_type='REPORT'`."
                        
        )

    API_URL: str = "https://api.rstcloud.net/"  
    API_KEY: str = RSTCLOUD_API_KEY


    def _run(self, ioc_value: str, ioc_type:str, **kwargs: Any) -> str:
        """
        Executes the RST Cloud API query and generates a report.
        """
        if not ioc_value or not ioc_type:
            raise ValueError("IOC value and IOC type not provided")
        
        results = self.results(ioc_value, ioc_type, **kwargs)
        return self.generate_report(results,ioc_type, "RST Cloud Report")
            


    def results(self, ioc_value: str, ioc_type: str, **kwargs: Any) -> dict:
        """
        Prepares the API request based on the appropriate IOC type
        """
        Tool = "RST"
        # Load cached response if available
        cached_response = cache_util.load_cached_response(Tool,ioc_value, ioc_type)

        if cached_response:
            return cached_response

        # Mapping of ioc_type to the corresponding method
        api_methods = {
            'IP': self._ioc_api_results,
            'DOMAIN': self._ioc_api_results,
            'URL': self._ioc_api_results,
            'HASH': self._ioc_api_results,
            'BENIGN': self._noisecontrol_api_results,
            'REPORT': self._reporthub_api_results,
            'WHOIS': self._whois_api_results
        }

        api_method = api_methods.get(ioc_type)

        if api_method is None:
            raise ValueError(f"Unsupported ioc_type: {ioc_type}")

        result =  api_method(ioc_value, ioc_type, **kwargs)
        
        # Cache the API response
        cache_util.cache_response(Tool,ioc_value, ioc_type, result)

        return result
        
    

    def _whois_api_results(self, ioc_value:str,ioc_type:str, **kwargs: Any) -> dict:
        """
        Retrieves WHOIS information for the given domain.
        """
        results = whoisapi.GetDomainInfo(domain=ioc_value)
        return results
    

    def _ioc_api_results(self, ioc_value:str,ioc_type:str, **kwargs: Any) -> dict:
        """
        Performs an IOC lookup for the given value.
        """
        results  = ioclookup.GetIndicator(ioc_value)
        return results
    
    def _reporthub_api_results(self, ioc_value:str,ioc_type:str, **kwargs: Any) -> dict: 
        """
        Retrieves threat intelligence reports based on a given date
        """      
        value = self.normalize_date(ioc_value)
        results = reporthub.GetReports(value)
        return results
    
    def _noisecontrol_api_results(self, ioc_value:str,ioc_type:str, **kwargs: Any) -> dict:
        """
        Checks if the specific IOC is considered benign.
        """

        results = noisecontrol.ValueLookup(ioc_value)
        return results



    @staticmethod
    def generate_report(result: dict, ioc_type, root_key: str = "") -> str:
        """Generates a report based on the API response."""

        
        def case_fix(snake_str:str):
            """Converts a snake_case string to a capitalized string with spaces."""
            spaces = snake_str.replace("_"," ")
            return spaces.capitalize()
        
        lines = []
            
        if not result:
            return ""

        if root_key:
            title = case_fix(root_key)
            lines.append(title+"\n")


        def generate_whois_report(result: dict) -> str:
            """Generate a specific report format for WHOIS API results."""
            
            lines = []
            lines.append("WHOIS Information\n")
            for key, value in result.items():
                lines.append(f"{key.capitalize()}: {value}")
            return "\n".join(lines)

        def generate_benign_report(result: dict) -> str:
            """Generate a specific report format for BENIGN API results."""
            
            lines = []
            lines.append("Benign Information\n")
            for key, value in result.items():
                lines.append(f"{key.capitalize()}: {value}")
            return "\n".join(lines)
        

        def generate_TI_report(result: dict,root_key) -> str:
            """Generate a report for Threat Intelligence Report API."""
            
            lines = []
            lines.append("Threat Intelligence Information\n")

            for item in result:
                if isinstance(item, dict):
                    lines.append(f"{case_fix(root_key)}:\n")
                    for k, v in item.items():
                        if isinstance(v, list):
                            # Directly format the list without recursive call
                            list_items = "\n".join([f"- {elem}" for elem in v])
                            lines.append(f"{case_fix(k)}:\n{list_items}")
                        else:
                            lines.append(f"{case_fix(k)}: {v}")
                elif isinstance(item, str):
                    lines.append(f"{case_fix(root_key)}: {item}")

            return "\n".join(lines)

        """ Create Reports based on different API Functionality
            - IOC LOOKUP
            - WHOIS INFORMATION
            - BENIGN LOOKUP
            - TI REPORTS
        """

        shout = ['IP','DOMAIN','URL','HASH']

        if ioc_type =='WHOIS':            
            lines.append(generate_whois_report(result))
        elif ioc_type =='BENIGN':
            lines.append(generate_benign_report(result))
        elif ioc_type == 'REPORT':
            lines.append(generate_TI_report(result,root_key))
        elif ioc_type in shout:
            lines.append(f"IOC Results")
            lines.append(f"IOC TYPE: {result.get('ioc_type')}")
            lines.append(f"IOC VALUE: {result.get('ioc_value')}\n")
                  
        
            for key,value in result.items():
                        
                    if isinstance(value, dict):
                        new_lines = RSTcloudReportTool.generate_report(value,key)
                        lines.append(new_lines)
                        
                    if isinstance(value, str):
                        sub_title  = case_fix(key)
                        lines += [f"{sub_title}: {value}"]
                        
                    if isinstance(value, int):
                        if "date" in key or "timestamp" in key:
                            dt = datetime.datetime.utcfromtimestamp(value)
                            sub_title  = case_fix(key)
                            lines += [f"{sub_title}: {dt.isoformat()}"]
                        else:
                            sub_title = case_fix(key)
                            lines += [f"{sub_title}: {value}"]
                        
                    if isinstance(value, list):
                            
                        if value:
                            sub_title = case_fix(key)

                            for subvalue in value:
                                if type(subvalue) == str:
                                    lines += [f"{sub_title}: {subvalue}"]
                                elif type(subvalue) == dict:
                                    new_lines = RSTcloudReportTool.generate_report(subvalue, key)
                                    lines.append(new_lines)
                            else:
                                lines.append(f"{sub_title}: empty") 
            
            
                
        report =  "\n".join(lines)
        return RSTcloudReportTool._truncate_to_token_limit(report)
    

    @staticmethod
    def _truncate_to_token_limit( text: str, token_limit: int = 14000) -> str:
        """
        Truncates the report if it exceeds the llm model's token limit
        """
        
        encoding = get_encoding("cl100k_base")
        tokens = encoding.encode(text)
        
        if len(tokens) > token_limit:
            
            truncated_text = encoding.decode(tokens[:token_limit])
            print("Warning: Output truncated to fit token limit.")
            return truncated_text
        
        return text
    
    @staticmethod
    def normalize_date(date_str: str) -> str:
            """Converts a date string into yyyymmdd format."""
            try:
                # Parse the date string into a datetime object
                parsed_date = parser.parse(date_str)
                # Format the datetime object as yyyymmdd
                return parsed_date.strftime('%Y%m%d')
            except ValueError:
                raise ValueError(f"Invalid date format: {date_str}")

