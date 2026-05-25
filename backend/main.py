from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from judge import judge_submission

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Simple OJ Running"}

@app.post("/submit")
def submit(language: str = Form(...), code: str = Form(...), problem_id: str = Form(...)):
    return judge_submission(language, code, problem_id)