import os
import uuid
import subprocess
import shutil
import glob

TEMP_DIR = "/sandbox-temp"
PROBLEM_DIR = "/problems"

os.makedirs(TEMP_DIR, exist_ok=True)

TIME_LIMIT = 2  # seconds
JUDGE_IMAGE = os.getenv("JUDGE_IMAGE", "onlineoj-sandbox")  # 你的沙箱鏡像名稱


def judge_submission(language, code, problem_id):
    submission_id = str(uuid.uuid4())
    work_dir = os.path.join(TEMP_DIR, submission_id)
    os.makedirs(work_dir)

    try:
        problem_path = os.path.join(PROBLEM_DIR, problem_id)
        input_files = sorted(glob.glob(os.path.join(problem_path, "input*.txt")))

        if not input_files:
            return {"status": "ERROR", "message": "No testcases found"}

        testcases = []
        for input_file in input_files:
            output_file = input_file.replace("input", "output")
            if not os.path.exists(output_file):
                return {"status": "ERROR", "message": f"Missing output for {input_file}"}
            testcases.append((input_file, output_file))

        if language == "c":
            return judge_c(code, testcases, work_dir, problem_path)

        if language == "cpp":
            return judge_cpp(code, testcases, work_dir, problem_path)

        return {"status": "ERROR", "message": "Unsupported language"}

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_in_sandbox(work_dir, problem_dir, cmd, timeout=TIME_LIMIT, stdin_text=None):
    """
    在沙箱容器內執行 cmd，並回傳 subprocess.CompletedProcess
    """
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--cpus", "1",
        "--memory", "512m",
        "--pids-limit", "128",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "1000:1000",
        "-v", f"{work_dir}:/work:rw",
        "-v", f"{problem_dir}:/problems:ro",
        "-w", "/work",
        JUDGE_IMAGE,
    ] + cmd

    return subprocess.run(
        docker_cmd,
        input=stdin_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout
    )


def judge_c(code, testcases, work_dir, problem_dir):
    source_file = os.path.join(work_dir, "main.c")
    with open(source_file, "w") as f:
        f.write(code)

    compile_cmd = ["clang", "main.c", "-O2", "-std=c11", "-o", "main"]
    compile_result = run_in_sandbox(work_dir, problem_dir, compile_cmd, timeout=5)

    if compile_result.returncode != 0:
        return {"status": "CE", "error": compile_result.stderr}

    run_cmd = ["./main"]
    return execute_all_testcases(run_cmd, testcases, work_dir, problem_dir)


def judge_cpp(code, testcases, work_dir, problem_dir):
    source_file = os.path.join(work_dir, "main.cpp")
    with open(source_file, "w") as f:
        f.write(code)

    compile_cmd = ["clang++", "main.cpp", "-O2", "-std=c++17", "-o", "main"]
    compile_result = run_in_sandbox(work_dir, problem_dir, compile_cmd, timeout=5)

    if compile_result.returncode != 0:
        return {"status": "CE", "error": compile_result.stderr}

    run_cmd = ["./main"]
    return execute_all_testcases(run_cmd, testcases, work_dir, problem_dir)


def execute_all_testcases(run_cmd, testcases, work_dir, problem_dir):
    for idx, (input_file, output_file) in enumerate(testcases, start=1):
        with open(input_file, "r") as f:
            testcase_input = f.read()

        with open(output_file, "r") as f:
            expected_output = f.read().strip()

        result = execute_and_compare(run_cmd, testcase_input, expected_output, idx, work_dir, problem_dir)
        if result["status"] != "AC":
            return result

    return {"status": "AC"}


def execute_and_compare(run_cmd, testcase_input, expected_output, idx, work_dir, problem_dir):
    try:
        result = run_in_sandbox(
            work_dir, problem_dir, run_cmd, timeout=TIME_LIMIT, stdin_text=testcase_input
        )
    except subprocess.TimeoutExpired:
        return {"status": "TLE", "case": idx}

    if result.returncode != 0:
        return {"status": "RE", "case": idx, "error": result.stderr}

    user_output = result.stdout.strip()

    if user_output == expected_output:
        return {"status": "AC"}

    return {
        "status": "WA",
        "case": idx,
        "expected": expected_output,
        "got": user_output
    }