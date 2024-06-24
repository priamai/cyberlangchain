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

More to come!