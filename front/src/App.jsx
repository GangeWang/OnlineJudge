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

const getClientFingerprint = () => {
    try {
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");
        if (ctx) {
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("OJ-AntiCheat", 2, 15);
            ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctx.fillText("OJ-AntiCheat", 4, 17);
        }
        const dataUrl = canvas.toDataURL ? canvas.toDataURL() : "";
        const screenInfo = typeof screen !== "undefined" ? `${screen.width}x${screen.height}x${screen.colorDepth}` : "";
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
        const cores = navigator.hardwareConcurrency || "";
        const raw = `${dataUrl}|${screenInfo}|${tz}|${cores}`;
        let hash = 0;
        for (let i = 0; i < raw.length; i++) {
            hash = ((hash << 5) - hash) + raw.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(16);
    } catch {
        return "";
    }
};

const postForm = async (url, fields) => {
    const formData = new FormData();
    Object.entries(fields).forEach(([key, value]) => formData.append(key, value));

    const res = await fetch(url, {
        method: "POST",
        body: formData,
        credentials: "include",
        headers: {
            "X-Client-Fingerprint": getClientFingerprint(),
        },
    });
    const data = await res.json();
    if (!res.ok) {
        const error = new Error(data.detail || "Request failed");
        error.status = res.status;
        throw error;
    }
    return data;
};

// Value for <input type="datetime-local"> in the viewer's local time zone.
const toLocalInput = (iso) => {
    if (!iso) return "";
    const date = new Date(iso);
    const pad = (n) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
};

const formatLocal = (iso) => (iso ? new Date(iso).toLocaleString("zh-TW", { hour12: false }) : "");

const formatDuration = (ms) => {
    const total = Math.max(0, Math.floor(ms / 1000));
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(Math.floor(total / 3600))}:${pad(Math.floor((total % 3600) / 60))}:${pad(total % 60)}`;
};

// Same rules as the backend, evaluated against the server clock.
const examPhaseAt = (exam, serverNowMs) => {
    if (!exam || !exam.start_at || !exam.end_at) return "open";
    if (serverNowMs < Date.parse(exam.start_at)) return "not_started";
    if (serverNowMs < Date.parse(exam.end_at)) return "running";
    return "ended";
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
    const [loginAlerts, setLoginAlerts] = useState([]);
    const [problemsMessage, setProblemsMessage] = useState("");
    const [exam, setExam] = useState(null);
    const [serverOffsetMs, setServerOffsetMs] = useState(0);
    const [nowMs, setNowMs] = useState(Date.now());
    const [examForm, setExamForm] = useState({ start: "", end: "" });
    const [adminMessage, setAdminMessage] = useState("");

    const loadExam = async () => {
        try {
            const res = await fetch("/api/exam", { credentials: "include" });
            if (!res.ok) return;
            const data = await res.json();
            setServerOffsetMs(Date.parse(data.server_now) - Date.now());
            setExam(data);
        } catch {
            // Keep the last known schedule; the server still enforces it.
        }
    };

    const clearLogin = () => {
        setCurrentUser(null);
        setSubmissions([]);
        setLoginAlerts([]);
    };

    const loadProblems = async () => {
        try {
            const res = await fetch("/api/problems", { credentials: "include" });
            const data = await res.json();
            if (!res.ok) {
                // 401: the server no longer accepts this login, e.g. it predates the exam window.
                if (res.status === 401) clearLogin();
                setProblems([]);
                setProblemId("");
                setProblemsMessage(data.detail || "無法載入題目");
                return;
            }
            setProblems(data);
            setProblemsMessage("");
            setProblemId((current) => (data.some((problem) => problem.id === current) ? current : data[0]?.id || ""));
        } catch {
            setProblemsMessage("無法載入題目");
        }
    };

    useEffect(() => {
        let active = true;
        const restoreSession = async () => {
            await loadExam();
            try {
                const response = await fetch("/api/session", { credentials: "include" });
                if (!response.ok) throw new Error("無法恢復登入狀態，請重新登入");
                const data = await response.json();
                if (active && data.user) {
                    setCurrentUser(data.user);
                    setLoginAlerts(data.login_alerts);
                    const history = await postForm("/api/submissions", {});
                    if (active) setSubmissions(history);
                }
            } catch (error) {
                if (active) setAuthMessage(error.message);
            }
            if (active) await loadProblems();
        };
        restoreSession();
        return () => { active = false; };
    }, []);

    // Tick the countdown every second and pick up schedule changes every 30 seconds.
    useEffect(() => {
        const tick = setInterval(() => setNowMs(Date.now()), 1000);
        const poll = setInterval(loadExam, 30000);
        return () => {
            clearInterval(tick);
            clearInterval(poll);
        };
    }, []);

    const serverNowMs = nowMs + serverOffsetMs;
    const phase = examPhaseAt(exam, serverNowMs);
    const isAdmin = Boolean(currentUser?.is_admin);
    const submissionClosed = (phase === "not_started" || phase === "ended") && !isAdmin;

    // Reload problems when the exam starts or the schedule changes.
    useEffect(() => {
        if (exam) loadProblems();
    }, [phase, exam?.start_at, exam?.end_at]);

    useEffect(() => {
        setExamForm({ start: toLocalInput(exam?.start_at), end: toLocalInput(exam?.end_at) });
    }, [exam?.start_at, exam?.end_at]);

    const saveExam = async (clear) => {
        setAdminMessage("儲存中...");
        try {
            if (!clear && (!examForm.start || !examForm.end)) {
                throw new Error("請填寫開始與結束時間");
            }
            const data = await postForm("/api/admin/exam", clear
                ? { start_at: "", end_at: "" }
                : {
                    start_at: new Date(examForm.start).toISOString(),
                    end_at: new Date(examForm.end).toISOString(),
                });
            setServerOffsetMs(Date.parse(data.server_now) - Date.now());
            setExam(data);
            setAdminMessage(clear ? "已取消考試，改回練習模式" : "考試時間已更新");
        } catch (error) {
            setAdminMessage(error.message);
        }
    };

    const currentProblem = useMemo(
        () => problems.find((problem) => problem.id === problemId),
        [problems, problemId],
    );

    const loadSubmissions = async () => {
        if (!currentUser) return;
        const data = await postForm("/api/submissions", {});
        setSubmissions(data);
    };

    const handleAuth = async (mode) => {
        setAuthMessage(mode === "register" ? "Creating account..." : "Logging in...");
        try {
            const data = await postForm(`/api/${mode}`, { username, password });
            setCurrentUser(data.user);
            setLoginAlerts(data.login_alert ? [data.login_alert] : []);
            setAuthMessage(`${mode === "register" ? "註冊" : "登入"}成功：${data.user.username}`);
            const history = await postForm("/api/submissions", {});
            setSubmissions(history);
            await loadProblems();
        } catch (error) {
            setAuthMessage(error.message);
        }
    };

    const handleLogout = async () => {
        try {
            await postForm("/api/logout", {});
        } catch {
            // The server clears the cookie even when the session was already gone.
        }
        setCurrentUser(null);
        setSubmissions([]);
        setLoginAlerts([]);
        setResult("");
        setPassword("");
        setAdminMessage("");
        setAuthMessage("已登出");
        await loadProblems();
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
            });
            setResult(JSON.stringify(data, null, 2));
            await loadSubmissions();
        } catch (error) {
            setResult(error.message);
            if (error.status === 401) {
                clearLogin();
                setAuthMessage(error.message);
            }
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
                        {currentUser && (
                            <button onClick={handleLogout} className="secondary-button">
                                登出
                            </button>
                        )}
                    </div>
                    {currentUser && <p className="current-user">目前使用者：{currentUser.username}</p>}
                    {authMessage && <p className="auth-message">{authMessage}</p>}
                    {loginAlerts.length > 0 && (
                        <section className="login-alert" role="alert">
                            <strong>異地登入警告</strong>
                            {loginAlerts.map((alert) => (
                                <p key={alert.id}>
                                    偵測到不同裝置登入：{alert.first_ip_address}（先登入）與 {alert.second_ip_address}（後登入）。
                                </p>
                            ))}
                        </section>
                    )}
                </section>
            </header>

            {phase !== "open" && (
                <section className={`exam-banner exam-${phase}`} role="status">
                    {phase === "not_started" && (
                        <>
                            <strong>考試尚未開始</strong>
                            <span>開始時間：{formatLocal(exam.start_at)}，倒數 {formatDuration(Date.parse(exam.start_at) - serverNowMs)}</span>
                        </>
                    )}
                    {phase === "running" && (
                        <>
                            <strong>考試進行中</strong>
                            <span>結束時間：{formatLocal(exam.end_at)}，剩餘 {formatDuration(Date.parse(exam.end_at) - serverNowMs)}</span>
                        </>
                    )}
                    {phase === "ended" && (
                        <>
                            <strong>考試已結束</strong>
                            <span>結束於 {formatLocal(exam.end_at)}，可以查看題目，但不能再提交</span>
                        </>
                    )}
                </section>
            )}

            {isAdmin && (
                <section className="admin-panel">
                    <h2>考試時間設定（管理者）</h2>
                    <p className="admin-hint">
                        時間以這台電腦的時區輸入，伺服器以自己的時鐘判斷。未設定時為練習模式，任何人都能看題目與提交。
                    </p>
                    <div className="admin-fields">
                        <label>
                            開始時間
                            <input
                                type="datetime-local"
                                value={examForm.start}
                                onChange={(e) => setExamForm((form) => ({ ...form, start: e.target.value }))}
                            />
                        </label>
                        <label>
                            結束時間
                            <input
                                type="datetime-local"
                                value={examForm.end}
                                onChange={(e) => setExamForm((form) => ({ ...form, end: e.target.value }))}
                            />
                        </label>
                    </div>
                    <div className="admin-actions">
                        <button onClick={() => saveExam(false)}>儲存考試時間</button>
                        <button onClick={() => saveExam(true)} className="secondary-button">
                            取消考試（改回練習模式）
                        </button>
                    </div>
                    {adminMessage && <p className="auth-message">{adminMessage}</p>}
                </section>
            )}

            {problemsMessage && <p className="problems-message">{problemsMessage}</p>}

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

            <button onClick={submitCode} disabled={!problemId || submissionClosed}>Submit</button>

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
