
from langsmith.evaluation import evaluate
from langsmith import Client 
from langchain import hub
from langchain_openai import ChatOpenAI
from run_qa import agent


"""
AGENT EVALUATOR

The evalutor evaluates the agent's final response.
It iterates the dataset on langsmith and performs evaluation.

"""


## Listing the Dataset
# Ensure the dataset exists and retrieve its ID
client = Client()
dataset_name = "Virus Total Dataset"
datasets = list(client.list_datasets(dataset_name=dataset_name))
dataset_id = None

if datasets:
    dataset_id = datasets[0].id
    

## function to get the agent's response to a given question.
def predict_agent_answer(example: dict):
  
    user_input = example["input"]
    result = agent(user_input)
    response = result['output']
    return {"response": response}


## Use a LLM to grade the agent's response
# Grade prompt
grade_prompt_answer_accuracy = prompt = hub.pull("langchain-ai/rag-answer-vs-reference")


# Function that performs the evaluation
def answer_evaluator(run, example) -> dict:
    
    # Get question, ground truth answer, RAG chain answer
    input_question = example.inputs['input']
    reference = example.outputs['output']
    prediction = run.outputs['response']

    # LLM grader
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)

    # Structured prompt
    answer_grader = grade_prompt_answer_accuracy | llm

    # Run evaluator
    score = answer_grader.invoke({"question": input_question,
                                  "correct_answer": reference,
                                  "student_answer": prediction})
    score = score["Score"]

    return {"key": "answer_v_reference_score", "score": score}



### Create Evaluation
# The evaluate function iterates over each example in the dataset.
experiment_results = evaluate(
    predict_agent_answer,
    data=dataset_id,
    evaluators=[answer_evaluator],
    experiment_prefix="Cyberlangchain-response-v-reference",
    num_repetitions=3,
    metadata={"version": "1.0.0"},
)
