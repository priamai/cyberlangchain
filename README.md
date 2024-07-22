# Cyber + LangChain
Are you using LangChain in your copilots?

Are you lacking the most common tools to make those agents more useful?

You are in the right place then!

This project's goal is to add a set of useful tools for making agentic decision on sources like threat intelligence and alerts.

# Setup
Install the requirements.

Create an .env file with the tools directory containig:


````
VIRUSTOTAL_API_KEY=yourkey
OPENAI_API_KEY=yourkey
````
# Virus Total

Go inside the example folder and you can find one example:

````
response = agent("Is this IP 1.2.3.4 malicious according to Virus Total?")

Thought: I can provide the final response to the user now.
Action:
```
{
  "action": "Final Answer",
  "action_input": "The IP address 1.2.3.4 is not malicious according to the VirusTotal report."
}
```

> Finished chain.
{'input': 'Is this IP 1.2.3.4 malicious according to Virus Total?', 'chat_history': [], 'output': 'The IP address 1.2.3.4 is not malicious according to the VirusTotal report.'}

````

Other Use Cases: Domain, URL, File

## Domain

````
response = agent("Is this domain example.com malicious according to Virus Total?")

Thought:The IP address 1.2.3.4 is classified as a legitimate IP that doesn't serve any malicious purpose according to the VirusTotal report. It has a reputation score of -11 and is associated with various harmless results from different engines. The analysis indicates that it is not considered malicious.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The IP address 1.2.3.4 is not malicious according to VirusTotal."
}
```


> Finished chain.
{'input': 'is the IP 1.2.3.4 malicious according to Virus Total ?', 'chat_history': [], 'output': 'The IP address 1.2.3.4 is not malicious according to VirusTotal.'}

````

## File


````
response = agent("Is the File dc476ae39effdd80399b6e36f1fde92c216a5bbdb6b8b2a7ecbe753e91e4c993 malicious according to VirusTotal ?")

Thought:The file with the hash dc476ae39effdd80399b6e36f1fde92c216a5bbdb6b8b2a7ecbe753e91e4c993 is considered malicious according to VirusTotal analysis. It has been detected by multiple engines as malicious, categorized as a joke or time-related malware. The file is named traveler.exe and is associated with the ASPack packer and Borland Delphi compiler. It is advised to handle this file with caution.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The file dc476ae39effdd80399b6e36f1fde92c216a5bbdb6b8b2a7ecbe753e91e4c993 is considered malicious according to VirusTotal analysis. It is categorized as a trojan.joke/changetime."
}
```


> Finished chain.
{'input': 'Is the File dc476ae39effdd80399b6e36f1fde92c216a5bbdb6b8b2a7ecbe753e91e4c993 malicious according to VirusTotal ?', 'chat_history': [], 'output': 'The file dc476ae39effdd80399b6e36f1fde92c216a5bbdb6b8b2a7ecbe753e91e4c993 is considered malicious according to VirusTotal analysis. It is categorized as a trojan.joke/changetime.'}


````

## URL


````
response = agent("Is the url "{http://117.248.172.130:50994/bin.sh}" malicious according to VirusTotal ?")

Thought:The URL "{http://117.248.172.130:50994/bin.sh}" has been identified as malicious by several engines, including Sophos and Webroot, categorizing it as malware. The analysis indicates that it is associated with the Mozi botnet, known for infecting systems through brute-forcing SSH and Telnet ports. It is recommended to avoid accessing this URL to prevent potential security risks.

Thought: I have the information needed to provide a final response to the user's query.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The URL http://117.248.172.130:50994/bin.sh is considered malicious according to VirusTotal analysis."
}
```

> Finished chain.
{'input': 'Is the url http://117.248.172.130:50994/bin.sh malicious according to VirusTotal ?', 'chat_history': [], 'output': 'The URL http://117.248.172.130:50994/bin.sh is considered malicious according to VirusTotal analysis.'}


````

## Attack Technique


````
response = agent("Provide me details about the attack technique T1567 ?")

Thought: I have retrieved detailed information about the attack technique T1567, which involves exfiltration over a web service. The technique description includes the use of legitimate external web services for data exfiltration, providing cover due to pre-existing network communication with these services. Additionally, adversaries may leverage SSL/TLS encryption for added protection.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The attack technique T1567 involves exfiltration over a web service, where adversaries may use legitimate external web services for data exfiltration, leveraging SSL/TLS encryption for added protection."
}
``` 



> Finished chain.
{'input': 'Provide me details about the attack technique T1567 ?', 'chat_history': [], 'output': 'The attack technique T1567 involves exfiltration over a web service, where adversaries may use legitimate external web services for data exfiltration, leveraging SSL/TLS encryption for added protection.'}


````
