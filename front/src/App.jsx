import { useState } from "react";
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

    const submitCode = async () => {
        setResult("Judging...");

        const formData = new FormData();
        formData.append("language", language);
        formData.append("code", code);
        formData.append("problem_id", "1001");

        const res = await fetch("http://localhost:8000/submit", {
            method: "POST",
            body: formData,
        });

        const data = await res.json();
        setResult(JSON.stringify(data, null, 2));
    };

    return (
        <div className="container">
            <h1>Simple OJ</h1>

            <label>Language:</label>
            <select value={language} onChange={(e) => setLanguage(e.target.value)}>
                <option value="c">C</option>
                <option value="cpp">C++</option>
            </select>

            <CodeEditor value={code} onChange={setCode} language={language} />

            <button onClick={submitCode}>Submit</button>

            <pre>{result}</pre>
        </div>
    );
}