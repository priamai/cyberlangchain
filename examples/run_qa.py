import os

from cybertools import VirusTotalReportTool, OTXReportTool,RSTcloudReportTool

from langchain_openai import OpenAI
from langchain.agents import initialize_agent, Tool
from langchain.agents import AgentType
from langchain_community.chat_models import ChatOpenAI
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langchain_openai import ChatOpenAI


# Set env var OPENAI_API_KEY or load from a .env file:
import dotenv

dotenv.load_dotenv()

# set up to send all agents's traces to langsmith
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = f"cyberlangchain"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
os.environ["LANGCHAIN_API_KEY"] = "<LANGCHAIN_API_KEY>" 



system_msg = """AVA is a security copilot developed by Priam AI.
A few import rules related to threat intelligence:
1) a reputation score is an integer 
2) a negative reputation score means that the community members have marked the indicator as bad
3) a positive reputation score means that the community hmembers have marked the indicator as good
"""

agent_kwargs = {
        "system_message": system_msg,
    }

# initialize LLM (we use ChatOpenAI because we'll later define a `chat` agent)
llm = ChatOpenAI(
        temperature=0,
        model_name='gpt-3.5-turbo'
)

# initialize conversational memory
conversational_memory = ConversationBufferWindowMemory(
        memory_key='chat_history',
        k=5,
        return_messages=True
)

tools = [VirusTotalReportTool(),RSTcloudReportTool(),OTXReportTool()]


# initialize agent with tools
agent = initialize_agent(
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    tools=tools,
    llm=llm,
    verbose=True,
    max_iterations=3,
    early_stopping_method='generate',
    agent_kwargs=agent_kwargs,
    memory=conversational_memory,
    return_intermediate_steps=True
)

prefix="""You are a cybersecurity expert specialized in helping SOC analysts, threat analysts, and threat intelligence analysts. Based on the provided context and query, provide a detailed and accurate response. You will help in the best way possible.

You leverage various tools and structured thinking processes to provide accurate and informed responses. You will ALWAYS have to verify whether do you need to use any tools, if you don't need respond to the user directly.

To address the following task effectively, you will need to reason through each step, validate your logic, and ensure each part of your response is consistent with the others.

This conclusion will represent a comprehensive analysis, backed by rigorous reasoning and a thorough examination of all available evidence.

You have access to the following tools:

"""


instructions="""

The way you use the tools is by specifying a json blob.  

Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should primarily contain a SINGLE action. However, if a thorough analysis requires it, you may consider multiple actions, but only after carefully evaluating the need and potential consequences. Here is an example of a valid $JSON_BLOB:

```

{{{{

"action": $TOOL_NAME,

"action_input": $INPUT

}}}}

```

ALWAYS use the following format:

Question: the input question you must answer.

Thought: Assess the context of the security incident or threat. Consider the potential impact of different actions.Evaluate alternative actions if necessary, especially when dealing with high-risk or ambiguous scenarios.

Action: Specify the action to take using the JSON format. Ensure the action is precise and directly related to the query.When multiple actions are required, each should be well-justified based on the context and prior observations.
  
```

$JSON_BLOB

```
Observation: Carefully analyze the results from the action. Determine if the results align with expectations or if further investigation is required.Consider potential security implications, false positives, or gaps in the data.

... (this Thought/Action/Observation can repeat N times)

Thought: Reflect on the new information gained from the observation. Decide if additional actions are necessary or if the final conclusion can be drawn.

Final Answer: Provide the final analysis or recommendation based on the cumulative insights and observations. Ensure the answer is actionable, accurate, and aligned with cybersecurity best practices

"""

suffix="""Begin! Reminder to ALWAYS respond with a valid json blob of a single action. Your response should be clear, concise,

Always use the exact characters `Final Answer` when responding "
"""

new_prompt = agent.agent.create_prompt(
    tools=tools, prefix=prefix, suffix=suffix, format_instructions=instructions
)

agent.agent.llm_chain.prompt = new_prompt
agent.tools = tools


#Prompt user for input and get agent response
while True:

   user_input = input("How may I assist you?\n")
   if user_input == 'exit':  # Perform Evalution on a dataset instead of taking user inputs
                break
   response = agent( user_input)




