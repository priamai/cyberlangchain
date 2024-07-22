import os
from cybertools import VirusTotalReportTool
from langchain_openai import OpenAI
from langchain.agents import initialize_agent, Tool
from langchain.agents import AgentType
from langchain_community.chat_models import ChatOpenAI
from langchain.chains.conversation.memory import ConversationBufferWindowMemory

# Set env var OPENAI_API_KEY or load from a .env file:
import dotenv

dotenv.load_dotenv()

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

tools = [VirusTotalReportTool()]

# initialize agent with tools
agent = initialize_agent(
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    tools=tools,
    llm=llm,
    verbose=True,
    max_iterations=3,
    early_stopping_method='generate',
    agent_kwargs=agent_kwargs,
    memory=conversational_memory
)

new_prompt = agent.agent.create_prompt(
    tools=tools
)

agent.agent.llm_chain.prompt = new_prompt
agent.tools = tools

response = agent(input("How may I assist you?\n"))

print(response)

