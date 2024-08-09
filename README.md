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
LANGCHAIN_API_KEY=yourkey
OTX_API_KEY=yourkey
````

Some common examples are given below:


# Virus Total


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


````
response = agent("is the domain 0-01x-merchandise.554217.xyz malicious according to Virus Total ?")

Thought:The domain 0-01x-merchandise.554217.xyz has been analyzed by VirusTotal, and the results show that it has a reputation score of 0, indicating that it is considered clean and harmless by most of the engines. There are no malicious findings associated with this domain according to the report.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The domain 0-01x-merchandise.554217.xyz is clean and not considered malicious according to VirusTotal."
}
```

> Finished chain.


````




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

# Alien Vault


````
response = agent("Find relevant  information about the  threat groups APT28 and APT34  threat groups from alien vault. specify only the commonalities between them.")

Thought: I need to use the AlienVault API to gather information about the threat groups APT28 and APT34 and then identify their commonalities.

Action:
```
{
  "action": "Final Answer",
  "action_input": "APT28 and APT34 are both threat groups involved in cyber espionage. APT28, also known as Sofacy, Fancy Bear, and Sednit, has been active since around 2008 and targets military and government entities worldwide, with a focus on NATO countries. APT34, on the other hand, is suspected to be an Iranian threat group operational since at least 2014, conducting cyber espionage largely focused on reconnaissance efforts to benefit Iranian nation-state interests. Both groups have conducted attacks in the Middle East and have targeted various industries, including government and energy sectors."
}
```

> Finished chain.

````


````
response = agent("What is the usual method of propagation for `Emotet` according to Alien Vault?")

Thought:The usual method of propagation for `Emotet` according to Alien Vault is through a widespread phishing campaign with PDF attachments that contain a link to various sites with malicious JavaScript files. This campaign targets email addresses associated with .UK TLDs and uses fake billing notification emails to deliver the malware.

Thought: The information provided gives insight into how Emotet spreads through phishing campaigns with malicious attachments.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The usual method of propagation for Emotet according to Alien Vault is through a phishing campaign with PDF attachments containing links to sites with malicious JavaScript files."
}
```

> Finished chain.


````



````
response = agent("Have there been any new `zero-day exploits` reported that target windows 11 operating system recently according to Alien Vault?")

Thought: The user is inquiring about any new zero-day exploits targeting the Windows 11 operating system, specifically looking for information from Alien Vault.



Action:
```
{
  "action": "Final Answer",
  "action_input": "No new zero-day exploits targeting Windows 11 operating system have been reported recently according to Alien Vault."
}


> Finished chain.


````


````
response = agent("What campaigns are associated with the domain 0-01x-merchandise.554217.xyz according to Alien Vault ?")

Thought: The user is asking for information about campaigns associated with a specific domain according to Alien Vault.

Action:
```
{
  "action": "Final Answer",
  "action_input": "There are no campaigns associated with the domain 0-01x-merchandise.554217.xyz according to Alien Vault."
}
```

> Finished chain.


````


````

response = agent("According to Alien Vault How severe is the threat posed by this `CVE-2019-12345` vulnerability? ")


Thought: The user is asking about the severity of the CVE-2019-12345 vulnerability according to Alien Vault. I should use the AlienVaultapi tool to gather this information.


Thought: The AlienVault report provides detailed information about the CVE-2019-12345 vulnerability, including severity metrics and related data points.

Action:
```
{
  "action": "Final Answer",
  "action_input": "The severity of the CVE-2019-12345 vulnerability is rated as MEDIUM according to AlienVault."
}
``` 



> Finished chain.

  

````