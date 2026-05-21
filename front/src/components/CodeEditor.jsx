import Editor from "@monaco-editor/react";

export default function CodeEditor({ value, onChange, language = "cpp" }) {
    return (
        <div style={{ height: "70vh", border: "1px solid #333" }}>
            <Editor
                height="100%"
                language={language}
                value={value}
                theme="vs-dark"
                onChange={(v) => onChange(v ?? "")}
                options={{
                    fontSize: 14,
                    minimap: { enabled: true },
                    automaticLayout: true,
                    tabSize: 2,
                    wordWrap: "on",
                }}
            />
        </div>
    );
}