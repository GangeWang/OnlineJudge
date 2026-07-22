import os
import uuid
import subprocess
import shutil
import glob

BASE_DIR = "/app"
HOST_BASE_DIR = os.getenv("HOST_BACKEND_DIR", BASE_DIR)
TEMP_DIR = os.path.join(BASE_DIR, "temp")
PROBLEM_DIR = os.path.join(BASE_DIR, "problems")
TIME_LIMIT = 2
JUDGE_IMAGE = os.getenv("JUDGE_IMAGE", "onlineoj-sandbox:latest")


def judge_submission(language, code, problem_id):
    submission_id = str(uuid.uuid4())

    work_dir = os.path.join(TEMP_DIR, submission_id)
    os.makedirs(work_dir, exist_ok=True)
    os.chmod(work_dir, 0o777)

    try:
        problem_path = os.path.join(PROBLEM_DIR, problem_id)

        input_files = sorted(glob.glob(os.path.join(problem_path, "input*.txt")))
        if not input_files:
            return {"status": "ERROR", "message": "No testcases"}

        testcases = []
        for inp in input_files:
            out = inp.replace("input", "output")
            if not os.path.exists(out):
                return {"status": "ERROR", "message": f"Missing {out}"}
            testcases.append((inp, out))

        if language == "cpp":
            return judge_cpp(code, testcases, work_dir)

        if language == "c":
            return judge_c(code, testcases, work_dir)

        return {"status": "ERROR", "message": "Unsupported language"}

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_in_sandbox(work_dir, cmd, stdin_text=None, timeout=TIME_LIMIT):
    rel = os.path.relpath(work_dir, BASE_DIR)
    host_work_dir = os.path.join(HOST_BASE_DIR, rel)
    container_name = f"oj-{uuid.uuid4()}"
    docker_cmd = [
        "docker", "run", "--rm",
        "--init",
        "--name",
        container_name,
        "-i",
        "--network", "none",
        "--cpus", "1",
        "--memory", "512m",
        "--pids-limit", "32",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "1000:1000",
        "-v", f"{host_work_dir}:/work",
        "-w", "/work",
        JUDGE_IMAGE,

    ] + cmd

    try:
        return subprocess.run(
            docker_cmd,
            input=stdin_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:

        subprocess.run(
            [
                "docker",
                "kill",
                container_name
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        raise


def judge_cpp(code, testcases, work_dir):
    src = os.path.join(work_dir, "main.cpp")
    with open(src, "w") as f:
        f.write(code)

    compile = run_in_sandbox(work_dir, [
        "clang++", "main.cpp", "-O2",
        "-std=c++17", "-o", "main"
    ])
    if compile.returncode != 0:
        return {"status": "CE", "error": compile.stderr}

    os.chmod(os.path.join(work_dir, "main"), 0o755)
    return run_tests(["./main"], testcases, work_dir)


def judge_c(code, testcases, work_dir):
    src = os.path.join(work_dir, "main.c")
    with open(src, "w") as f:
        f.write(code)

    compile = run_in_sandbox(work_dir, ["clang", "main.c", "-O2", "-std=c11", "-o", "main"])
    if compile.returncode != 0:
        return {"status": "CE", "error": compile.stderr}

    os.chmod(os.path.join(work_dir, "main"), 0o755)
    return run_tests(["./main"], testcases, work_dir)


def run_tests(run_cmd, testcases, work_dir):
    for i, (inp, outp) in enumerate(testcases, 1):
        with open(inp) as f:
            stdin_text = f.read()
        expected = open(outp).read().strip()

        try:
            res = run_in_sandbox(work_dir, run_cmd, stdin_text)
        except subprocess.TimeoutExpired:
            return {"status": "TLE", "case": i}

        if res.returncode == 137:
            return {"status": "MLE", "case": i}
        if res.returncode != 0:
            return {"status": "RE", "case": i, "error": res.stderr}
        if res.stdout.strip() != expected:
            return {"status": "WA", "case": i, "expected": expected, "got": res.stdout.strip()}

    return {"status": "AC"}