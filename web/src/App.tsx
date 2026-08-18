import { useState } from "react";
import "./App.css";

const API = "http://localhost:8000";

type ScanResult = {
  assessment: {
    band: string;
    score: number;
    confidence: number;
    category: string;
    indicators: { code: string; severity: string }[];
  };
  explanation: { headline: string; why: string[]; actions: string[]; limitation_notice: string };
  extracted: {
    text: string;
    source: string;
    char_count: number;
    ocr_quality: number | null;
  };
  entities: { kind: string; value_redacted: string }[];
  timing_ms: number;
  model_version: string;
  rule_version: string;
};

const BAND_LABEL: Record<string, string> = {
  low: "No strong warning signs",
  caution: "Caution",
  high: "High risk",
  unable_to_assess: "Unable to assess",
};

type Mode = "text" | "url" | "image";

const TAB_LABEL: Record<Mode, string> = {
  text: "Message",
  url: "Link",
  image: "Screenshot",
};

const UPLOAD_ERROR: Record<number, string> = {
  413: "That image is larger than 5 MB. Try a smaller screenshot.",
  415: "That file could not be read as a PNG, JPEG or WebP image.",
  422: "No image was selected.",
};

export default function App() {
  const [mode, setMode] = useState<Mode>("text");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const ready = mode === "image" ? file !== null : text.trim().length > 0;

  async function scan(e: React.FormEvent) {
    e.preventDefault();
    setPending(true);
    setError(null);
    setResult(null);
    try {
      let res: Response;
      if (mode === "image") {
        const form = new FormData();
        form.append("file", file!);
        res = await fetch(`${API}/api/v1/scan/image`, { method: "POST", body: form });
      } else {
        res = await fetch(`${API}/api/v1/scan/${mode}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(mode === "text" ? { text, lang: "en" } : { url: text, lang: "en" }),
        });
      }
      if (!res.ok) throw new Error(UPLOAD_ERROR[res.status] ?? `Scan failed (${res.status})`);
      setResult(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="wrap">
      <h1>ScamSathi AI</h1>
      <p className="sub">Paste a suspicious message to check it.</p>

      <div className="tabs" role="tablist" aria-label="What to check">
        {(["text", "url", "image"] as const).map((m) => (
          <button
            key={m}
            role="tab"
            type="button"
            aria-selected={mode === m}
            className={mode === m ? "tab on" : "tab"}
            onClick={() => {
              setMode(m);
              setResult(null);
              setError(null);
              setFile(null);
            }}
          >
            {TAB_LABEL[m]}
          </button>
        ))}
      </div>

      <form onSubmit={scan}>
        <label htmlFor="msg">
          {mode === "text" ? "Message" : mode === "url" ? "Link (URL)" : "Screenshot"}
        </label>
        {mode === "text" && (
          <textarea
            id="msg"
            rows={6}
            value={text}
            onChange={(e) => setText(e.target.value)}
            maxLength={10000}
            placeholder="Paste the message here..."
            required
          />
        )}
        {mode === "url" && (
          <input
            id="msg"
            type="text"
            inputMode="url"
            value={text}
            onChange={(e) => setText(e.target.value)}
            maxLength={2048}
            placeholder="example.com/login"
            required
          />
        )}
        {mode === "image" && (
          <>
            {/* capture= opens the camera directly on a phone. */}
            <input
              id="msg"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              required
            />
            <p className="hint">PNG, JPEG or WebP, up to 5 MB. One image per scan.</p>
          </>
        )}
        <button type="submit" disabled={pending || !ready}>
          {pending ? "Scanning..." : "Scan"}
        </button>
      </form>

      <div aria-live="polite">
        {error && <p className="error">{error}</p>}

        {result && (
          <section className="result">
            <p className={`band band-${result.assessment.band}`}>
              {BAND_LABEL[result.assessment.band] ?? result.assessment.band}
            </p>
            <h2>{result.explanation.headline}</h2>

            {result.extracted.source === "image" && (
              <div className="ocr">
                <h3>Text we read from your screenshot</h3>
                <p className="ocr-text">
                  {result.extracted.text || "Nothing readable was found."}
                </p>
                <p className="hint">
                  If this is wrong or incomplete, paste the message into the Message tab
                  instead.
                </p>
              </div>
            )}

            <h3>What we noticed</h3>
            <ul>
              {result.explanation.why.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>

            <h3>What to do now</h3>
            <ol>
              {result.explanation.actions.map((a) => (
                <li key={a}>{a}</li>
              ))}
            </ol>

            <p className="notice">{result.explanation.limitation_notice}</p>

            <details>
              <summary>Technical details</summary>
              <p>
                Confidence {result.assessment.confidence} · score {result.assessment.score} ·{" "}
                {result.timing_ms} ms · model {result.model_version} · rules{" "}
                {result.rule_version}
              </p>
              <ul>
                {result.assessment.indicators.map((i) => (
                  <li key={i.code}>
                    <code>{i.code}</code> <span className="sev">{i.severity}</span>
                  </li>
                ))}
              </ul>
              {result.entities.length > 0 && (
                <>
                  <p>Detected items (masked):</p>
                  <ul>
                    {result.entities.map((e, n) => (
                      <li key={n}>
                        {e.kind}: <code>{e.value_redacted}</code>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </details>
          </section>
        )}
      </div>
    </main>
  );
}
