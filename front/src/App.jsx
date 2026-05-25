import { useEffect, useMemo, useState } from "react";
import CodeEditor from "./components/CodeEditor";
import "./App.css";

const defaultCode = `#include <stdio.h>

int main() {
    int a,b;
    if (scanf("%d %d", &a, &b) != 2) return 0;
    printf("%d", a + b);
    return 0;
}
`;

export default function App() {
    const [language, setLanguage] = useState("c");
    const [code, setCode] = useState(defaultCode);
    const [result, setResult] = useState("");
    const [problems, setProblems] = useState([]);
    const [problemId, setProblemId] = useState("");

    useEffect(() => {
        const fetchProblems = async () => {
            const res = await fetch("/api/problems");
            const data = await res.json();
            setProblems(data);
            if (data.length > 0) {
                setProblemId(data[0].id);
            }
        };

        fetchProblems();
    }, []);

    const currentProblem = useMemo(
        () => problems.find((problem) => problem.id === problemId),
        [problems, problemId],
    );

    const submitCode = async () => {
        setResult("Judging...");

        const formData = new FormData();
        formData.append("language", language);
        formData.append("code", code);
        formData.append("problem_id", problemId);

        const res = await fetch("/api/submit", {
            method: "POST",
            body: formData,
        });

        const data = await res.json();
        setResult(JSON.stringify(data, null, 2));
    };

    return (
        <div className="container">
            <h1>Simple OJ</h1>

            <div className="selectors">
                <div>
                    <label>題目：</label>
                    <select value={problemId} onChange={(e) => setProblemId(e.target.value)}>
                        {problems.map((problem) => (
                            <option key={problem.id} value={problem.id}>
                                {problem.id} - {problem.title}
                            </option>
                        ))}
                    </select>
                </div>

                <div>
                    <label>Language:</label>
                    <select value={language} onChange={(e) => setLanguage(e.target.value)}>
                        <option value="c">C</option>
                        <option value="cpp">C++</option>
                    </select>
                </div>
            </div>

            {currentProblem && (
                <section className="problem-panel">
                    <h2>{currentProblem.title}</h2>
                    <p>{currentProblem.description}</p>
                    <div className="sample-grid">
                        <div>
                            <h3>範例輸入</h3>
                            <pre>{currentProblem.sample_input || "(無)"}</pre>
                        </div>
                        <div>
                            <h3>範例輸出</h3>
                            <pre>{currentProblem.sample_output || "(無)"}</pre>
                        </div>
                    </div>
                </section>
            )}

            <CodeEditor value={code} onChange={setCode} language={language} />

            <button onClick={submitCode} disabled={!problemId}>Submit</button>

            <pre>{result}</pre>
        </div>
    );
}
