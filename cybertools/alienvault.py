"""Tool for the Alien Vault Threat Intelligence API v2."""

from tiktoken import get_encoding
from typing import Any
from OTXv2 import OTXv2 , IndicatorTypes
from langchain_core.tools import BaseTool
import datetime
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the OTX API key from environment variables
OTX_API_KEY = os.getenv('OTX_API_KEY')
OTX_SERVER = 'https://otx.alienvault.com/'


otx = OTXv2(api_key=OTX_API_KEY,server=OTX_SERVER)


class OTXReportTool(BaseTool):
    """Tool that queries IOC reports and threat Intelligence from the Alient Vault API"""

    name: str = "AlienVaultapi"
    description: str = (
        "Threat intelligence API provided by Alient Vault. It provides valuable threat intelligence"
        "This tool is handy when you need information about cyber threats and when you need to get reports from indicators of compromise (aka IOC) such as an ip address, a file hash, url, or a domain."
        "The tool can also be used to get information about different threat feeds tailored to specific threats or campaigns"
        "and insights into different threat actors and their tactics, technqiues and procedures"
        
        "To use the tool, you must provide at least two of the following parameters "
        "['ioc_value','ioc_type']."

        "Supports the following IOC types:"
        " - 'IPv4': IP Address (e.g., '1.2.3.4')"
        " - 'IPv6': IPv6 Address (e.g., '2001:0db8:85a3:0000:0000:8a2e:0370:7334') "
        " - 'DOMAIN': Domain name (e.g., 'example.com') "
        " - 'HOSTNAME': Hostname (e.g., 'server.example.com') "
        " - 'URL': URL (e.g., 'http://example.com') "
        " - 'FILE_HASH_MD5': MD5 File hash (e.g., 'd41d8cd98f00b204e9800998ecf8427e') "
        " - 'FILE_HASH_SHA1': SHA-1 File hash (e.g., 'a9993e364706816aba3e25717850c26d9c3d') "
        " - 'FILE_HASH_SHA256': SHA-256 File hash (e.g., 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') "
        " - 'CVE': Common Vulnerabilities and Exposures (e.g., 'CVE-2024-12345')."
        " - 'pulses': for any IOC types not explicitly mentioned"

        " Specify the appropriate IOC type and value to retrieve relevant reports and information about associated threat groups or campaigns."
        
        " the 'pulses' IOC type parameter Leverages powerful keyword search to explore threat intelligence based on topics, campaigns, or threat actor names. "
        " When any of the keywords below are queried the ioc_type needs to be 'pulses' Here are some examples:"
        " - Threat Group Names: e.g., 'APT28', 'Lazarus Group', 'Fancy Bear', ' Emotet', 'TrickBot'."
        " - Attack Types: e.g., 'phishing', 'ransomware', 'DDoS', 'cryptojacking,' 'zero-day exploit,' 'supply chain attack'"
        " - General Keywords: e.g., 'malware', 'cyber attack', 'data breach', 'ransomware as a service,' 'phishing lures,' 'dark web activity'."

        )


    def _run(self, ioc_value: str,ioc_type:str, **kwargs: Any) -> str:
        try:
            results = self.results(ioc_value, ioc_type, **kwargs)
            return self._result_as_string(results, "Alient Vault Report")
        except Exception as e:
            return f"An error occurred: {str(e)}"


    def results(self, ioc_value: str,ioc_type:str, **kwargs: Any) -> dict:
        
        supported_types = ['IPv4','IPv6', 'DOMAIN','HOSTNAME','URL','FILE_HASH_MD5','FILE_HASH_SHA1',
            'FILE_HASH_SHA256','CVE']

        if ioc_type in supported_types:
            return self._search_api_results(ioc_value,ioc_type, **kwargs)
        elif ioc_type == 'pulses':
            return self._search_pulses(ioc_value)
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
    


    def _search_api_results(self, ioc_value:str,ioc_type:str, **kwargs: Any) -> dict:
        """Get details for each of the OTX API Endpoints based on IOC type and value.
       
        The IOC types supported by the API

        supported_api_types = [
            IPv4,
            IPv6,
            DOMAIN,
            HOSTNAME,
            URL,
            FILE_HASH_MD5,
            FILE_HASH_SHA1,
            FILE_HASH_SHA256,
            CVE
        ]
        
        """
        try:
            indicator_type = getattr(IndicatorTypes, ioc_type)
            return otx.get_indicator_details_full(indicator_type, ioc_value)
        except AttributeError:
            raise ValueError(f"Invalid IOC type: {ioc_type}")
        except Exception as e:
            raise RuntimeError(f"Failed to fetch API results: {str(e)}")
        

    def _search_pulses(self,ioc_value: str):
        """
        Function to search for keyword indicators.

        list of supported IOC types for pulse indicators:
        all_types = [
                IPv4,
                IPv6,
                DOMAIN,
                HOSTNAME,
                EMAIL,
                URL,
                URI,
                FILE_HASH_MD5,
                FILE_HASH_SHA1,
                FILE_HASH_SHA256,
                FILE_HASH_PEHASH,
                FILE_HASH_IMPHASH,
                CIDR,
                FILE_PATH,
                MUTEX,
                CVE
            ]
        """
        try:
            return otx.search_pulses(ioc_value)
        except Exception as e:
            raise RuntimeError(f"Failed to search pulses: {str(e)}")



    @staticmethod 
    def _result_as_string(result: dict, root_key) -> str:
        '''
        Convert the json output report into a natural text.
        Depending on the IOC responses might be different

        '''

        def case_fix(snake_str:str):
            spaces = snake_str.replace("_"," ")
            return spaces.capitalize()
        
        lines = []

        if not result:
            return ""

        if root_key:
            title = case_fix(root_key)
            lines.append(title+"\n")
        
        
            for key,value in result.items():
                if type(value) == dict:
                    new_lines = OTXReportTool._result_as_string(value,key)
                    lines.append(new_lines)

                if type(value) == str:
                    if key == "id": lines += [f"Indicator value: {value}"]
                    elif key == "type": lines += [f"Indicator type: {value}"]
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

                    if value:
                        sub_title = case_fix(key)

                        for subvalue in value:
                            if type(subvalue) == str:
                                lines += [f"{sub_title}: {subvalue}"]
                            elif type(subvalue) == dict:
                                new_lines = OTXReportTool._result_as_string(subvalue, key)
                                lines.append(new_lines)
                        else:
                            lines.append(f"{sub_title}: empty")
        
        # Join lines and truncate to token limit
        report_string = "\n".join(lines)
        return OTXReportTool._truncate_to_token_limit(report_string)

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









