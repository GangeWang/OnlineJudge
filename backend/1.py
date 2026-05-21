import sys
import os

def split_from_two_files(question_file, answer_file, out_dir="problems/1001"):
    with open(question_file, "r", encoding="utf-8") as f:
        questions = [line.strip() for line in f if line.strip()]

    with open(answer_file, "r", encoding="utf-8") as f:
        answers = [line.strip() for line in f if line.strip()]

    if len(questions) != len(answers):
        raise ValueError(f"題目數({len(questions)}) 與答案數({len(answers)}) 不一致")

    os.makedirs(out_dir, exist_ok=True)

    # input.txt.txt / output.txt
    with open(os.path.join(out_dir, "input.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(questions) + "\n")

    with open(os.path.join(out_dir, "output.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(answers) + "\n")

    # inputN/outputN
    for i, (q, a) in enumerate(zip(questions, answers), start=1):
        with open(os.path.join(out_dir, f"input{i}.txt"), "w", encoding="utf-8") as f:
            f.write(q + "\n")
        with open(os.path.join(out_dir, f"output{i}.txt"), "w", encoding="utf-8") as f:
            f.write(a + "\n")

    print(f"done: {len(questions)} cases -> {out_dir}/input.txt.txt output.txt + inputN/outputN")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: 1.py input.txt output.txt")
        sys.exit(1)

    split_from_two_files(sys.argv[1], sys.argv[2])