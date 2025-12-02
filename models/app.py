from fastapi import FastAPI
from pydantic import BaseModel
from llama_cpp import Llama
import threading

# Model
model = None
lock = threading.Lock()

# Load once
def load_model():
    global model
    model = Llama(
        model_path="tinyllama-1.1b-chat-v1.0.Q4_0.gguf",  # FIXED PATH
        n_ctx=512,
        n_threads=2,
        verbose=False
    )

# FastAPI
app = FastAPI()
class CodeRequest(BaseModel):
    task: str
    language: str = "python"

@app.on_event("startup")
def startup():
    load_model()
    print("Model loaded and ready.")

@app.get("/")
def home():
    return {"ready": model is not None}


@app.post("/code")
def generate_code(req: CodeRequest):
    task = req.task
    language = req.language

    formatted_prompt = f"Write {language} code for: {task}\n\n```{language}\n"
    
    with lock:
        result = model(
            formatted_prompt,
            max_tokens=200,
            temperature=0.1,
            stop=["```", "\n\n\n"],
            echo=False
        )
    
    code = result['choices'][0]['text'].strip()
    if code.endswith("```"):
        code = code[:-3]

    return {"code": code, "language": language}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)