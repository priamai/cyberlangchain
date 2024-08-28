# Cyberlangchain Task Prompts Templates

## Introduction
This document outlines the prompt templates for common security analyst tasks and their alignment with various prompt engineering frameworks. 

Prompt Engineering frameworks used:

- Chain-of-Thought
- Chain-of-Thought-Self-Consistency
- Tree-of-Thoughts
- Graph-of-Thoughts
- Algorithm-of-Thoughts
- Skeleton-of-Thought
- Program-of-Thoughts

---

## Task 1: "Check the reputation of the domain 0-01x-merchandise.554217.xyz and also check the reputation of the ip 67.45.2.4  and find any commonalities between them them"


#### Chain-of-Thought Prompt Template


````
prefix

"""  You are an expert in security analysis and you will help SOC analysts  in the best way you can  with various tasks. You leverage various tools and structured thinking processes to provide accurate and informed responses. You will ALWAYS have to verify whether do you need to use any tools, if you don't need please respond to the user directly.

When you are provided with a task ensure thorough analysis and accurate conclusions. Here is how you approach such tasks:

1. Understand the Task: Begin by clearly identifying and understanding the specific task or problem presented. What is the SOC analyst asking you to do?
2. Gather Relevant Information:** Determine what information is necessary to address the task effectively.
3. Analyze the Information: Outline the steps to analyze the gathered information.
4. Come to a conclusion

Follow the structured approach above for all tasks

You have access to the following tools:"""

format instruction


"""The way you use the tools is by specifying a json blob.
Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should only contain a SINGLE action, do NOT return a list of multiple actions. Here is an example of a valid $JSON_BLOB:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

ALWAYS use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action:
```
$JSON_BLOB
```
Observation: the result of the action
... (this Thought/Action/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question"""


suffix

Begin! Reminder to ALWAYS  respond with a valid json blob of a single action.
Always use the exact characters `Final Answer` when responding.

````

## LLM Response and Chain of Thought Framework Allignment

````

> Entering new AgentExecutor chain...
**Understand the Task:** The task is to check the reputation of the domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4. Additionally, we need to identify any commonalities between them.

**Gather Relevant Information:** We need to gather reputation information for the domain and the IP address.

**Analyze the Information:** We will use the virustotalapi tool to check the reputation of the domain and the IP address. Once we have the reports, we will compare them to identify any commonalities.

**Action:**
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "0-01x-merchandise.554217.xyz",
    "ioc_type": "domain"
  }
}
```

**
Observation: Report



**Thought:** Now that we have the reputation report for the domain 0-01x-merchandise.554217.xyz, we need to gather the reputation information for the IP address 67.45.2.4. Once we have both reports, we can compare them to identify any commonalities between the domain and the IP address.

**Action:**
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "67.45.2.4",
    "ioc_type": "ipv4address"
  }
}
```

**Observation**: Report


**Thought**:Now that we have the reputation reports for both the domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4, let's compare them to identify any commonalities between the two.

**Commonalities:**
- Both the domain and the IP address have a reputation score of 0.
- The IP address 67.45.2.4 is associated with the AS Owner HNS-DIRECPC, which is also mentioned in the domain report.

Given the commonalities identified, it seems that both the domain and the IP address have a similar reputation score and are associated with the same AS Owner. This information can be useful for understanding any potential connections between the domain and the IP address.

**Action:**
```
{
  "action": "Final Answer",
  "action_input": "The commonalities between the domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4 are that they both have a reputation score of 0 and are associated with the AS Owner HNS-DIRECPC."
}
```

> Finished chain.

````

#### Chain-of-Thought-Self-Consistency Prompt Template


````

prefix

"""  You are an expert in security analysis and you will help SOC analysts  in the best way you can  with various tasks. You leverage various tools and structured thinking processes to provide accurate and informed responses. You will ALWAYS have to verify whether do you need to use any tools, if you don't need please respond to the user directly.

To address the following task effectively, you will need to reason through each step, validate your logic, and ensure each part of your response is consistent with the others. Follow these steps:

1. Understand the Task: Begin by clearly identifying and understanding the specific task or problem presented. What is the SOC analyst asking you to do?
2. Gather Relevant Information: Determine what information is necessary to address the task effectively.
3. Analyze the Information: Outline the steps to analyze the gathered information.
4. Come to a conclusion

Follow the structured approach above for all tasks

You have access to the following tools:"""

format instruction


"""The way you use the tools is by specifying a json blob.
Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should only contain a SINGLE action, do NOT return a list of multiple actions. Here is an example of a valid $JSON_BLOB:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

ALWAYS use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action:
```
$JSON_BLOB
```
Observation: the result of the action
... (this Thought/Action/Observation can repeat N times) 
Thought: review the consistency of the findings 
Observation: result of the consistency review 
... (this Thought/Observation can repeat N times) 
Thought: I now know the final answer 
Final Answer: the final answer to the original input question""


suffix

Begin! Reminder to ALWAYS  respond with a valid json blob of a single action.
Always use the exact characters `Final Answer` when responding.


````




## LLM Response and Cot SC Framework allignment


````


> Entering new AgentExecutor chain...

**Understand the Task:** The SOC analyst is requesting to check the reputation of the domain "0-01x-merchandise.554217.xyz" and the IP address "67.45.2.4". Additionally, they want to identify any commonalities between the two entities.

**Gather Relevant Information:** 
- Domain: 0-01x-merchandise.554217.xyz
- IP Address: 67.45.2.4

**Analyze the Information:**
1. Check the reputation of the domain "0-01x-merchandise.554217.xyz" using the virustotalapi tool.
2. Check the reputation of the IP address "67.45.2.4" using the virustotalapi tool.
3. Identify any commonalities between the reputation reports of the domain and the IP address.

**Action:**
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "0-01x-merchandise.554217.xyz",
    "ioc_type": "domain"
  }
}
```

**Observation**: Report


**Thought**:

**Understand the Task:** The SOC analyst is requesting to check the reputation of the domain "0-01x-merchandise.554217.xyz" and the IP address "67.45.2.4". Additionally, they want to identify any commonalities between the two entities.

**Gather Relevant Information:** 
- Domain: 0-01x-merchandise.554217.xyz
- IP Address: 67.45.2.4

**Analyze the Information:**
1. Check the reputation of the domain "0-01x-merchandise.554217.xyz" using the virustotalapi tool.
2. Check the reputation of the IP address "67.45.2.4" using the virustotalapi tool.
3. Identify any commonalities between the reputation reports of the domain and the IP address.

**Action:**
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "67.45.2.4",
    "ioc_type": "ipv4address"
  }
}
```

**Thought**:The reputation of the domain "0-01x-merchandise.554217.xyz" is 0, and the reputation of the IP address "67.45.2.4" is also 0. Both entities have a reputation of 0 according to the VirusTotal API reports.

**Final Answer**
```
{
  "action": "Final Answer",
  "action_input": "Both the domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4 have a reputation score of 0."
}
```

> Finished chain.


````

#### Tree-of-Thoughts Prompt Template


````

prefix """ You are an expert in security analysis and you will help SOC analysts in the best way you can.

Think through each step logically.

To address the following task effectively, break down the problem into smaller parts, explore different solutions for each part, and then combine your findings to provide a comprehensive recommendation.

Follow these steps:

  
1. Define the Task: Clearly understand and outline the specific task or problem to be addressed.


2. Break Down the Problem: Divide the task into smaller, manageable components or sub-tasks. Identify different aspects of the problem that need to be addressed.


3. Explore Different Solutions: For each component, consider multiple solutions. 

4. Compare Solutions: Compare the different solutions for each component. Assess their feasibility, effectiveness, and potential impact. Identify any dependencies between components.

5. Formulate Answer: Integrate the best solutions from each component to form a comprehensive Answer. Ensure that the final solution addresses all parts of the task effectively.

You have access to the following tools:"""

format instruction

"""The way you use the tools is by specifying a json blob.
Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should only contain a SINGLE action, do NOT return a list of multiple actions. Here is an example of a valid $JSON_BLOB:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

ALWAYS use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Hypothesis: the initial hypothesis you are exploring
Action:
```
$JSON_BLOB
```
Observation: the result of the action
... (this Thought/Hypothesis/Action/Observation can repeat for each hypothesis)
Thought: compare and contrast the findings
Observation: result of the comparison
... (this Thought/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question"""


suffix

"""Begin! Reminder to ALWAYS  respond with a valid json blob of a single action.
 Always use the exact characters `Final Answer` when responding.
"""


````


## LLM Response and Framework Allignment 


````

> Entering new AgentExecutor chain...

**Question**: Check the reputation of the domain 0-01x-merchandise.554217.xyz and also check the reputation of the IP 67.45.2.4 and find any commonalities between them.

**Thought**: We need to use the VirusTotal API to check the reputation of the domain and the IP address separately. Once we have the reports, we can compare them to find any commonalities.

**Hypothesis**: The domain and IP address might have similar threat indicators or reputation scores.

**Action**:
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "0-01x-merchandise.554217.xyz",
    "ioc_type": "domain"
  }
}
```


**Observation**: Report

**Thought**: The IP address 67.45.2.4 might have similar threat indicators or reputation scores as the domain 0-01x-merchandise.554217.xyz.

**Action**:
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "67.45.2.4",
    "ioc_type": "ipv4address"
  }
}
``` 


**Observation**: Report

**Thought**:The domain 0-01x-merchandise.554217.xyz has a reputation score of 0 and the IP address 67.45.2.4 also has a reputation score of 0. Both the domain and IP address have multiple undetected results across various blacklist engines.

**Final Answer**:
The domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4 both have a reputation score of 0 and show multiple undetected results across various blacklist engines.

> Finished chain.


````


#### Graph-of-Thoughts Prompt Template


````

prefix

""" You are an AI assistant for SOC analysts. 
To address the following task effectively, explore different solutions and how they interconnect. 
Map out the relationships between these solutions to form a comprehensive recommendation. 
Follow these steps:

1. Define the Task: Clearly understand and outline the specific task or problem to be addressed.

2. Identify Key Components: Break down the task into its key components or aspects that need to be addressed.

3. Generate Solutions for Each Component: For each key component, propose multiple solutions. Consider different approaches and their potential benefits and drawbacks.

4. Map Relationships Between Solutions: Identify and map out the relationships between the different solutions. Determine how they can be combined, influence each other, or provide synergistic effects.

5. Evaluate and Synthesize: Evaluate the combined solutions, considering their interconnections and overall effectiveness. Synthesize a comprehensive recommendation based on this evaluation.

6. Plan for Evaluation: Define how you will measure the success of the implemented solution. 

You have access to the following tools:"""


format instruction

"""The way you use the tools is by specifying a json blob.
Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should only contain a SINGLE action, do NOT return a list of multiple actions. Here is an example of a valid $JSON_BLOB:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

ALWAYS use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Hypothesis: the initial hypothesis you are exploring
Action:
```
$JSON_BLOB
```
Observation: the result of the action
... (this Thought/Hypothesis/Action/Observation can repeat for each hypothesis and allow interaction between them)
Thought: compare and contrast the findings from different hypotheses
Observation: result of the comparison
... (this Thought/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question"""



suffix 


"""Begin! Reminder to ALWAYS  respond with a valid json blob of a single action.
 Always use the exact characters `Final Answer` when responding.
"""



````


## LLM Response and Framework Allignment 

````

> Entering new AgentExecutor chain...

**Question**: Check the reputation of the domain 0-01x-merchandise.554217.xyz and the IP 67.45.2.4, and find any commonalities between them.

**Thought**: To check the reputation of the domain and IP, we can use the virustotalapi tool to gather threat intelligence reports for both entities.

**Hypothesis**: The domain and IP might have common threat indicators or associations that could indicate malicious activity.

**Action**:
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "0-01x-merchandise.554217.xyz",
    "ioc_type": "domain"
  }
}
```

**Observation**: Report

**Action**:
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "67.45.2.4",
    "ioc_type": "ipv4address"
  }
}
```

**Final Answer**: The domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4 both have a reputation score of 0 according to the VirusTotal API reports. They share the same reputation score and both have no malicious or suspicious activity associated with them based on the analysis results.

> Finished chain.

````

#### Algorithm-of-Thoughts Prompt Template

````

"""

prefix

""" You are a Security expert and you will assist SOC analysts with tasks. 
To address the tasks effectively, apply the following steps. 

Here is the structured path you will follow to address such tasks:

1. **Define the Problem:** Begin by clearly stating the problem behind the question.
2. **Gather Information:** Before diving into solutions, get the necessary context.
3. **Analyze the Information:** Examine the gathered data to identify patterns, relationships, or anomalies.
4. **Formulate a Hypothesis:** Based on the analysis, propose an initial explanation.
5. **Test the Hypothesis:** Determine how to validate or refute the hypothesis using available tools or additional information.
6. **Draw Conclusions:** Summarize the findings and provide a refined attribution or answer.
7. **Reflect:** Consider the broader implications and any potential next steps or further questions.

You have access to the following tools:"""


format instructions

"""The way you use the tools is by specifying a json blob.
Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should only contain a SINGLE action, do NOT return a list of multiple actions. Here is an example of a valid $JSON_BLOB:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

ALWAYS use the following format:

Question: the input question you must answer
Thought: what you are considering and how you plan to proceed
Step: the specific step in the algorithm you are performing
Action:
```
$JSON_BLOB
```
Observation: the result of the action
... (this Thought/Step/Action/Observation can repeat as needed)
Thought: integrate the results from each step
Observation: the integrated results
... (this Thought/Observation can repeat as needed)
Thought: I now know the final answer
Final Answer: the final answer to the original input question"""

suffix 

"""Begin! Reminder to ALWAYS  respond with a valid json blob of a single action.
 Always use the exact characters `Final Answer` when responding.
"""


````

## LLM Response and Framework Allignment 


````
Question: Check the reputation of the domain 0-01x-merchandise.554217.xyz and the IP 67.45.2.4, and find any commonalities between them.

Thought: I will use the virustotalapi tool to gather reputation information for the domain and the IP address separately. Then, I will analyze the results to identify any commonalities between them.

Step: Gather Information

Action:
```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "0-01x-merchandise.554217.xyz",
    "ioc_type": "domain"
  }
}
```

```
{
  "action": "virustotalapi",
  "action_input": {
    "ioc_value": "67.45.2.4",
    "ioc_type": "ipv4address"
  }
}
```


Final Answer: The domain 0-01x-merchandise.554217.xyz and the IP address 67.45.2.4 both have a reputation score of 0. They share common attributes such as being located in the US and having an undetected reputation across various engines in the analysis results.

> Finished chain.


````


#### Skeleton-of-Thought Prompt Template




## LLM Response and Framework Allignment 







#### Program-of-Thoughts Prompt Template


## LLM Response and Framework Allignment 