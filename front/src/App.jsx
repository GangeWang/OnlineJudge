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

const postForm = async (url, fields) => {
    const formData = new FormData();
    Object.entries(fields).forEach(([key, value]) => formData.append(key, value));

    const res = await fetch(url, { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || "Request failed");
    }
    return data;
};

export default function App() {
    const [language, setLanguage] = useState("c");
    const [code, setCode] = useState(defaultCode);
    const [result, setResult] = useState("");
    const [problems, setProblems] = useState([]);
    const [problemId, setProblemId] = useState("");
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [currentUser, setCurrentUser] = useState(null);
    const [authMessage, setAuthMessage] = useState("");
    const [submissions, setSubmissions] = useState([]);

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

    const credentials = { username, password };

    const loadSubmissions = async () => {
        if (!username || !password) return;
        const data = await postForm("/api/submissions", credentials);
        setSubmissions(data);
    };

    const handleAuth = async (mode) => {
        setAuthMessage(mode === "register" ? "Creating account..." : "Logging in...");
        try {
            const data = await postForm(`/api/${mode}`, credentials);
            setCurrentUser(data.user);
            setAuthMessage(`${mode === "register" ? "註冊" : "登入"}成功：${data.user.username}`);
            await loadSubmissions();
        } catch (error) {
            setAuthMessage(error.message);
        }
    };

    const submitCode = async () => {
        if (!currentUser) {
            setResult("請先登入或註冊帳號後再提交");
            return;
        }

        setResult("Judging...");

        try {
            const data = await postForm("/api/submit", {
                language,
                code,
                problem_id: problemId,
                ...credentials,
            });
            setResult(JSON.stringify(data, null, 2));
            await loadSubmissions();
        } catch (error) {
            setResult(error.message);
        }
    };

    return (
        <div className="container">
            <header className="app-header">
                <h1>Simple OJ</h1>
                <section className="auth-panel">
                    <div className="auth-fields">
                        <input
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="帳號"
                            autoComplete="username"
                        />
                        <input
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="密碼"
                            type="password"
                            autoComplete="current-password"
                        />
                    </div>
                    <div className="auth-actions">
                        <button onClick={() => handleAuth("login")}>登入</button>
                        <button onClick={() => handleAuth("register")} className="secondary-button">
                            建立帳號
                        </button>
                    </div>
                    {currentUser && <p className="current-user">目前使用者：{currentUser.username}</p>}
                    {authMessage && <p className="auth-message">{authMessage}</p>}
                </section>
            </header>

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

            <section className="history-panel">
                <div className="history-header">
                    <h2>答題紀錄</h2>
                    <button onClick={loadSubmissions} className="secondary-button" disabled={!currentUser}>
                        重新整理
                    </button>
                </div>
                {submissions.length === 0 ? (
                    <p className="empty-history">尚無答題紀錄。</p>
                ) : (
                    <table>
                        <thead>
                            <tr>
                                <th>時間</th>
                                <th>題號</th>
                                <th>語言</th>
                                <th>結果</th>
                            </tr>
                        </thead>
                        <tbody>
                            {submissions.map((submission) => (
                                <tr key={submission.id}>
                                    <td>{submission.submitted_at}</td>
                                    <td>{submission.problem_id}</td>
                                    <td>{submission.language}</td>
                                    <td>{submission.status}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </section>
        </div>
    );
}
