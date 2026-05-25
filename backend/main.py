from pathlib import Path

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

PROBLEM_INFO = {
    "1001": {
        "title": "A + B Problem",
        "description": "讀入兩個整數 a 與 b，輸出 a + b。",
    }
}


def build_problem_item(problem_id: str, problem_dir: Path):
    info = PROBLEM_INFO.get(
        problem_id,
        {"title": f"Problem {problem_id}", "description": "尚無題目敘述。"},
    )

    sample_input_file = problem_dir / "input1.txt"
    sample_output_file = problem_dir / "output1.txt"
    sample_input = sample_input_file.read_text(encoding="utf-8").strip() if sample_input_file.exists() else ""
    sample_output = sample_output_file.read_text(encoding="utf-8").strip() if sample_output_file.exists() else ""

    return {
        "id": problem_id,
        "title": info["title"],
        "description": info["description"],
        "sample_input": sample_input,
        "sample_output": sample_output,
    }


@app.get("/")
def root():
    return {"message": "Simple OJ Running"}


@app.get("/problems")
def list_problems():
    problems_root = Path(__file__).resolve().parent / "problems"
    if not problems_root.exists():
        return []

    problem_items = []
    for problem_dir in sorted(path for path in problems_root.iterdir() if path.is_dir()):
        problem_items.append(build_problem_item(problem_dir.name, problem_dir))

    return problem_items


@app.post("/submit")
def submit(language: str = Form(...), code: str = Form(...), problem_id: str = Form(...)):
    return judge_submission(language, code, problem_id)
