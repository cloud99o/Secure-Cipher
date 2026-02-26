import { useState, useEffect, useRef } from "react";

// ─── Web Crypto AES-256-GCM + Custom Salt (Pepper) ───────────────────────────
//
// Salt architecture:
//   • randomSalt (16 bytes) — generated fresh per message, stored in ciphertext
//   • customPepper (user-provided) — hashed with SHA-256, XORed into randomSalt
//   • effectiveSalt = randomSalt XOR SHA-256(pepper)[0:16]
//
// This means decryption requires BOTH the ciphertext AND the correct pepper.
// The pepper is never stored anywhere — it must be shared out-of-band.
//
// Without the pepper, even with the ciphertext and password, decryption fails.

const subtle = window.crypto.subtle;

async function hashPepper(pepper) {
  const enc = new TextEncoder();
  const buf = await subtle.digest("SHA-256", enc.encode(pepper));
  return new Uint8Array(buf).slice(0, 16);
}

function xorBytes(a, b) {
  return a.map((byte, i) => byte ^ b[i]);
}

async function deriveKey(password, effectiveSalt) {
  const enc = new TextEncoder();
  const keyMaterial = await subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt: effectiveSalt, iterations: 310000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(plaintext, password, pepper) {
  const enc        = new TextEncoder();
  const randomSalt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv         = window.crypto.getRandomValues(new Uint8Array(12));

  const effectiveSalt = pepper
    ? new Uint8Array(xorBytes(randomSalt, await hashPepper(pepper)))
    : randomSalt;

  const key = await deriveKey(password, effectiveSalt);

  const cipherBuf = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );

  // Pack: randomSalt(16) + iv(12) + ciphertext+tag
  // Note: we store randomSalt (not effectiveSalt) — pepper stays secret
  const combined = new Uint8Array(16 + 12 + cipherBuf.byteLength);
  combined.set(randomSalt, 0);
  combined.set(iv, 16);
  combined.set(new Uint8Array(cipherBuf), 28);

  return btoa(String.fromCharCode(...combined));
}

async function decryptMessage(b64, password, pepper) {
  const bytes      = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const randomSalt = bytes.slice(0, 16);
  const iv         = bytes.slice(16, 28);
  const cipher     = bytes.slice(28);

  const effectiveSalt = pepper
    ? new Uint8Array(xorBytes(randomSalt, await hashPepper(pepper)))
    : randomSalt;

  const key = await deriveKey(password, effectiveSalt);

  const plainBuf = await subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return new TextDecoder().decode(plainBuf);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function passwordStrength(pw) {
  if (!pw) return { score: 0, label: "", color: "#1a2040" };
  let score = 0;
  if (pw.length >= 12) score++;
  if (pw.length >= 20) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score <= 1) return { score, label: "WEAK",   color: "#ff4444" };
  if (score <= 2) return { score, label: "FAIR",   color: "#ffaa00" };
  if (score <= 3) return { score, label: "GOOD",   color: "#88cc00" };
  return             { score, label: "STRONG", color: "#00ffaa" };
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function SecureCipher() {
  const [mode, setMode]               = useState("encrypt");
  const [plaintext, setPlaintext]     = useState("");
  const [ciphertext, setCiphertext]   = useState("");
  const [password, setPassword]       = useState("");
  const [showPass, setShowPass]       = useState(false);
  const [pepper, setPepper]           = useState("");
  const [showPepper, setShowPepper]   = useState(false);
  const [saltEnabled, setSaltEnabled] = useState(false);
  const [output, setOutput]           = useState("");
  const [status, setStatus]           = useState(null);
  const [loading, setLoading]         = useState(false);
  const [copied, setCopied]           = useState(false);
  const [saltInfo, setSaltInfo]       = useState(null);
  const [scanLine, setScanLine]       = useState(0);
  const scanRef = useRef();

  const strength = passwordStrength(password);

  useEffect(() => {
    scanRef.current = setInterval(() => setScanLine(p => (p + 1) % 100), 25);
    return () => clearInterval(scanRef.current);
  }, []);

  async function handleEncrypt() {
    if (!plaintext.trim()) return setStatus({ type: "err", msg: "Enter a message to encrypt." });
    if (!password)         return setStatus({ type: "err", msg: "Enter a password." });
    if (saltEnabled && !pepper) return setStatus({ type: "err", msg: "Enter a custom salt, or disable the salt feature." });
    setLoading(true); setStatus(null); setOutput(""); setSaltInfo(null);
    try {
      const result = await encryptMessage(plaintext, password, saltEnabled ? pepper : "");
      setOutput(result);
      const bytes = Uint8Array.from(atob(result), c => c.charCodeAt(0));
      const saltHex = Array.from(bytes.slice(0, 16)).map(b => b.toString(16).padStart(2, "0")).join(" ").toUpperCase();
      setSaltInfo(saltHex);
      setStatus({
        type: "ok",
        msg: saltEnabled
          ? "Encrypted with custom salt. Recipient needs the ciphertext, password, AND salt to decrypt."
          : "Encrypted. Without the password, this is unreadable.",
      });
    } catch (e) {
      setStatus({ type: "err", msg: "Encryption failed: " + e.message });
    }
    setLoading(false);
  }

  async function handleDecrypt() {
    if (!ciphertext.trim()) return setStatus({ type: "err", msg: "Paste ciphertext to decrypt." });
    if (!password)           return setStatus({ type: "err", msg: "Enter the password used to encrypt." });
    if (saltEnabled && !pepper) return setStatus({ type: "err", msg: "Enter the custom salt used during encryption." });
    setLoading(true); setStatus(null); setOutput(""); setSaltInfo(null);
    try {
      const result = await decryptMessage(ciphertext.trim(), password, saltEnabled ? pepper : "");
      setOutput(result);
      setStatus({ type: "ok", msg: "Decrypted successfully." });
    } catch {
      setStatus({
        type: "err",
        msg: saltEnabled
          ? "Decryption failed — wrong password, wrong salt, or corrupted ciphertext."
          : "Decryption failed — wrong password or corrupted ciphertext.",
      });
    }
    setLoading(false);
  }

  function switchMode(m) {
    setMode(m); setOutput(""); setStatus(null); setSaltInfo(null);
  }

  function handleCopy() {
    navigator.clipboard.writeText(output).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div style={{ minHeight: "100vh", background: "#06080f", color: "#a0b4ff", fontFamily: "'Courier Prime', monospace", position: "relative", overflow: "hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&family=VT323&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0a0c18; }
        ::-webkit-scrollbar-thumb { background: #a0b4ff22; border-radius: 3px; }

        .rc-input {
          background: #03040d;
          border: 1px solid #a0b4ff22;
          color: #c0ccff;
          padding: 10px 14px;
          font-family: 'Courier Prime', monospace;
          font-size: 14px;
          border-radius: 4px;
          outline: none;
          width: 100%;
          transition: border-color 0.2s, box-shadow 0.2s;
          resize: vertical;
        }
        .rc-input:focus { border-color: #a0b4ff66; box-shadow: 0 0 0 3px #a0b4ff0a; }
        .rc-input::placeholder { color: #1a2040; }

        .salt-input { background: #03050f; border-color: #e8a0ff33; color: #e0c0ff; }
        .salt-input:focus { border-color: #e8a0ff77; box-shadow: 0 0 0 3px #e8a0ff0a; }
        .salt-input::placeholder { color: #2a1a40; }

        .rc-btn {
          background: transparent;
          border: 1px solid #a0b4ff33;
          color: #a0b4ff;
          padding: 8px 18px;
          font-family: 'Courier Prime', monospace;
          font-size: 12px;
          border-radius: 3px;
          cursor: pointer;
          transition: all 0.2s;
          letter-spacing: 0.1em;
          text-transform: uppercase;
        }
        .rc-btn:hover { background: #a0b4ff11; border-color: #a0b4ff88; }
        .rc-btn:disabled { opacity: 0.3; cursor: not-allowed; }
        .rc-btn.active { background: #a0b4ff22; border-color: #a0b4ff; box-shadow: 0 0 10px #a0b4ff22; }
        .rc-btn.primary { background: #a0b4ff18; border-color: #a0b4ff88; font-size: 13px; padding: 12px 28px; letter-spacing: 0.15em; }
        .rc-btn.primary:hover:not(:disabled) { background: #a0b4ff28; border-color: #a0b4ffcc; box-shadow: 0 0 20px #a0b4ff22; }
        .rc-btn.primary.salted { background: #e8a0ff18; border-color: #e8a0ff88; }
        .rc-btn.primary.salted:hover:not(:disabled) { background: #e8a0ff28; border-color: #e8a0ffcc; box-shadow: 0 0 20px #e8a0ff22; }

        .salt-toggle {
          display: flex; align-items: center; gap: 10px; cursor: pointer;
          user-select: none; padding: 12px 14px; border-radius: 4px;
          border: 1px solid #a0b4ff18; background: #02030a;
          transition: all 0.2s; width: 100%; text-align: left;
        }
        .salt-toggle:hover { border-color: #e8a0ff33; background: #05030f; }
        .salt-toggle.on { border-color: #e8a0ff55; background: #08030f; }

        .toggle-pill { width: 36px; height: 20px; border-radius: 10px; border: 1px solid #a0b4ff33; background: #0a0c18; position: relative; transition: all 0.25s; flex-shrink: 0; }
        .toggle-pill.on { background: #e8a0ff33; border-color: #e8a0ff88; }
        .toggle-dot { position: absolute; width: 14px; height: 14px; border-radius: 50%; background: #4a5890; top: 2px; left: 2px; transition: all 0.25s; }
        .toggle-pill.on .toggle-dot { left: 18px; background: #e8a0ff; }

        .grid-bg {
          background-image: linear-gradient(rgba(160,180,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(160,180,255,0.025) 1px, transparent 1px);
          background-size: 28px 28px;
        }

        @keyframes pulse-blue { 0%,100% { text-shadow: 0 0 12px #a0b4ff44; } 50% { text-shadow: 0 0 24px #a0b4ff99, 0 0 48px #a0b4ff22; } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideDown { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 400px; } }
        .title-glow { animation: pulse-blue 4s ease-in-out infinite; }
        .spin { animation: spin 1s linear infinite; }
        .fade-in { animation: fadeIn 0.3s ease; }
        .slide-down { animation: slideDown 0.35s ease; overflow: hidden; }
      `}</style>

      {/* Scanline + scan beam */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 100, background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)" }} />
      <div style={{ position: "fixed", left: 0, right: 0, height: "2px", background: "linear-gradient(90deg, transparent, rgba(160,180,255,0.06), transparent)", top: `${scanLine}%`, pointerEvents: "none", zIndex: 99, transition: "top 0.025s linear" }} />

      {/* Corners */}
      {[
        { top:0,left:0,borderTop:"2px solid #a0b4ff33",borderLeft:"2px solid #a0b4ff33" },
        { top:0,right:0,borderTop:"2px solid #a0b4ff33",borderRight:"2px solid #a0b4ff33" },
        { bottom:0,left:0,borderBottom:"2px solid #a0b4ff33",borderLeft:"2px solid #a0b4ff33" },
        { bottom:0,right:0,borderBottom:"2px solid #a0b4ff33",borderRight:"2px solid #a0b4ff33" },
      ].map((s,i) => <div key={i} style={{ position:"fixed", width:"24px", height:"24px", ...s, pointerEvents:"none", zIndex:50 }} />)}

      <div className="grid-bg" style={{ minHeight: "100vh", padding: "40px 20px" }}>
        <div style={{ maxWidth: "680px", margin: "0 auto" }}>

          {/* Header */}
          <div style={{ textAlign: "center", marginBottom: "48px" }}>
            <div style={{ fontSize: "10px", color: "#2a3060", letterSpacing: "0.4em", marginBottom: "12px" }}>◈ AES-256-GCM · PBKDF2-SHA256 · CUSTOM SALT ◈</div>
            <h1 className="title-glow" style={{ fontFamily: "'VT323', monospace", fontSize: "clamp(40px,8vw,68px)", margin: 0, letterSpacing: "0.08em", color: "#a0b4ff", lineHeight: 1 }}>SECURE CIPHER</h1>
            <div style={{ fontSize: "11px", color: "#3a4880", marginTop: "10px", letterSpacing: "0.2em" }}>PRODUCTION-GRADE ENCRYPTION</div>
          </div>

          {/* Mode Toggle */}
          <div style={{ display: "flex", gap: "8px", justifyContent: "center", marginBottom: "32px" }}>
            <button className={`rc-btn ${mode==="encrypt"?"active":""}`} onClick={() => switchMode("encrypt")}>⬡ Encrypt</button>
            <button className={`rc-btn ${mode==="decrypt"?"active":""}`} onClick={() => switchMode("decrypt")}>⬡ Decrypt</button>
          </div>

          {/* Main Panel */}
          <div style={{ background: "#03040d", border: "1px solid #a0b4ff1a", borderRadius: "8px", padding: "28px", boxShadow: "0 0 60px #a0b4ff06, inset 0 0 40px #a0b4ff03", marginBottom: "20px" }}>

            {/* Message */}
            <div style={{ marginBottom: "22px" }}>
              <label style={{ display:"block", fontSize:"10px", color:"#4a5890", letterSpacing:"0.25em", marginBottom:"8px" }}>
                ◉ {mode==="encrypt" ? "PLAINTEXT MESSAGE" : "CIPHERTEXT (BASE64)"}
              </label>
              {mode==="encrypt"
                ? <textarea className="rc-input" rows={4} value={plaintext} onChange={e => setPlaintext(e.target.value)} placeholder="Type your secret message..." />
                : <textarea className="rc-input" rows={4} value={ciphertext} onChange={e => setCiphertext(e.target.value)} placeholder="Paste encrypted base64 here..." style={{ fontSize:"12px", wordBreak:"break-all" }} />
              }
            </div>

            {/* Password */}
            <div style={{ marginBottom: "8px" }}>
              <label style={{ display:"block", fontSize:"10px", color:"#4a5890", letterSpacing:"0.25em", marginBottom:"8px" }}>◉ PASSWORD</label>
              <div style={{ position:"relative" }}>
                <input type={showPass?"text":"password"} className="rc-input" style={{ paddingRight:"52px" }} value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter a strong password..." />
                <button onClick={() => setShowPass(!showPass)} style={{ position:"absolute", right:"12px", top:"50%", transform:"translateY(-50%)", background:"none", border:"none", color:"#4a5890", cursor:"pointer", fontSize:"11px", padding:"4px" }}>
                  {showPass?"HIDE":"SHOW"}
                </button>
              </div>
            </div>

            {/* Strength bar */}
            {mode==="encrypt" && password && (
              <div style={{ marginBottom:"22px" }}>
                <div style={{ display:"flex", alignItems:"center", gap:"10px", marginBottom:"6px" }}>
                  <div style={{ flex:1, height:"3px", background:"#0a0c18", borderRadius:"2px", overflow:"hidden" }}>
                    <div style={{ height:"100%", width:`${(strength.score/4)*100}%`, background:strength.color, borderRadius:"2px", transition:"all 0.3s" }} />
                  </div>
                  <span style={{ fontSize:"10px", color:strength.color, letterSpacing:"0.15em", minWidth:"50px" }}>{strength.label}</span>
                </div>
                {strength.score < 3 && <div style={{ fontSize:"10px", color:"#4a5890", lineHeight:"1.5" }}>Tip: use 12+ chars, mix uppercase, numbers & symbols.</div>}
              </div>
            )}
            {(mode==="decrypt" || !password) && <div style={{ marginBottom:"22px" }} />}

            {/* ─── Custom Salt Toggle ─────────────────────────────────── */}
            <div style={{ marginBottom: "22px" }}>
              <button className={`salt-toggle ${saltEnabled?"on":""}`} onClick={() => { setSaltEnabled(!saltEnabled); if (saltEnabled) setPepper(""); }}>
                <div className={`toggle-pill ${saltEnabled?"on":""}`}><div className="toggle-dot" /></div>
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:"11px", color:saltEnabled?"#e8a0ff":"#4a5890", letterSpacing:"0.15em", marginBottom:"2px" }}>
                    🧂 CUSTOM SALT {saltEnabled ? "— ENABLED" : "— DISABLED"}
                  </div>
                  <div style={{ fontSize:"10px", color:saltEnabled?"#8a5a99":"#2a3060", lineHeight:"1.4" }}>
                    {saltEnabled ? "Acts as a second secret factor — required to decrypt" : "Enable to add a secret pepper to key derivation"}
                  </div>
                </div>
                <div style={{ fontSize:"9px", color:saltEnabled?"#e8a0ff88":"#2a3060", letterSpacing:"0.1em", flexShrink:0, border:`1px solid ${saltEnabled?"#e8a0ff33":"#2a3060"}`, padding:"3px 7px", borderRadius:"2px" }}>
                  {saltEnabled ? "2FA" : "OFF"}
                </div>
              </button>

              {saltEnabled && (
                <div className="slide-down" style={{ marginTop:"12px" }}>
                  <div style={{ background:"#04020f", border:"1px solid #e8a0ff22", borderRadius:"6px", padding:"18px" }}>
                    <label style={{ display:"block", fontSize:"10px", color:"#8a5a99", letterSpacing:"0.25em", marginBottom:"8px" }}>◉ CUSTOM SALT / PEPPER</label>
                    <div style={{ position:"relative" }}>
                      <input
                        type={showPepper?"text":"password"}
                        className="rc-input salt-input"
                        style={{ paddingRight:"52px" }}
                        value={pepper}
                        onChange={e => setPepper(e.target.value)}
                        placeholder="e.g. a shared secret phrase..."
                      />
                      <button onClick={() => setShowPepper(!showPepper)} style={{ position:"absolute", right:"12px", top:"50%", transform:"translateY(-50%)", background:"none", border:"none", color:"#6a4a80", cursor:"pointer", fontSize:"11px", padding:"4px" }}>
                        {showPepper?"HIDE":"SHOW"}
                      </button>
                    </div>

                    {/* Diagram */}
                    <div style={{ marginTop:"16px", padding:"14px", background:"#02010a", borderRadius:"4px", border:"1px solid #e8a0ff12" }}>
                      <div style={{ fontSize:"9px", color:"#4a2a60", letterSpacing:"0.2em", marginBottom:"10px" }}>HOW IT WORKS</div>
                      <div style={{ display:"flex", flexDirection:"column", gap:"6px" }}>
                        {[
                          ["SHA-256(pepper)", "→", "16 bytes"],
                          ["XOR with random salt", "→", "effective salt"],
                          ["PBKDF2(password, effective salt)", "→", "256-bit key"],
                          ["Without pepper", "→", "wrong key → decrypt fails"],
                        ].map(([a, arrow, b], i) => (
                          <div key={i} style={{ display:"flex", gap:"8px", alignItems:"center", fontSize:"10px" }}>
                            <span style={{ color:"#6a4a80", fontFamily:"monospace", flexShrink:0 }}>{a}</span>
                            <span style={{ color:"#3a2050" }}>{arrow}</span>
                            <span style={{ color:"#4a3060" }}>{b}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div style={{ marginTop:"10px", padding:"10px 12px", background:"#0a0318", border:"1px solid #e8a0ff15", borderRadius:"4px" }}>
                      <span style={{ fontSize:"10px", color:"#e8a0ff55" }}>⚠ </span>
                      <span style={{ fontSize:"10px", color:"#5a3a70", lineHeight:"1.5" }}>
                        Share the salt via a <em style={{ color:"#7a5a90" }}>different channel</em> than the ciphertext. If an attacker intercepts both, they can still try brute-forcing without the salt.
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Action button */}
            <button className={`rc-btn primary ${saltEnabled?"salted":""}`} onClick={mode==="encrypt"?handleEncrypt:handleDecrypt} disabled={loading} style={{ width:"100%" }}>
              {loading
                ? <span style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:"10px" }}>
                    <span className="spin" style={{ display:"inline-block", width:"14px", height:"14px", border:`2px solid ${saltEnabled?"#e8a0ff44":"#a0b4ff44"}`, borderTop:`2px solid ${saltEnabled?"#e8a0ff":"#a0b4ff"}`, borderRadius:"50%" }} />
                    {mode==="encrypt" ? "ENCRYPTING..." : "DECRYPTING..."}
                  </span>
                : <>
                    {saltEnabled && <span style={{ color:"#e8a0ff88", marginRight:"8px" }}>⊕</span>}
                    {mode==="encrypt" ? "⬡ ENCRYPT MESSAGE" : "⬡ DECRYPT MESSAGE"}
                    {saltEnabled && <span style={{ fontSize:"10px", color:"#e8a0ff66", marginLeft:"8px" }}>+ SALT</span>}
                  </>
              }
            </button>

            {/* Status */}
            {status && (
              <div className="fade-in" style={{ marginTop:"16px", padding:"12px 14px", borderRadius:"4px", fontSize:"12px", lineHeight:"1.5", border:`1px solid ${status.type==="ok"?"#00ffaa33":"#ff444433"}`, color:status.type==="ok"?"#00cc88":"#ff7777", background:status.type==="ok"?"#00ffaa08":"#ff000008" }}>
                {status.type==="ok"?"✓ ":"✕ "}{status.msg}
              </div>
            )}

            {/* Output */}
            {output && (
              <div className="fade-in" style={{ marginTop:"20px" }}>
                <div style={{ fontSize:"10px", color:"#4a5890", letterSpacing:"0.25em", marginBottom:"8px" }}>
                  ◉ {mode==="encrypt" ? "CIPHERTEXT OUTPUT" : "DECRYPTED MESSAGE"}
                </div>
                <div style={{ background:"#010208", border:`1px solid ${saltEnabled?"#e8a0ff18":"#a0b4ff18"}`, borderRadius:"6px", padding:"16px", fontFamily:mode==="encrypt"?"'Courier Prime',monospace":"'VT323',monospace", fontSize:mode==="encrypt"?"11px":"24px", color:mode==="encrypt"?(saltEnabled?"#b080dd":"#6a80cc"):"#a0b4ff", wordBreak:"break-all", lineHeight:"1.6" }}>
                  {output}
                </div>

                {/* Salt transparency box */}
                {mode==="encrypt" && saltInfo && saltEnabled && (
                  <div style={{ marginTop:"10px", padding:"12px", background:"#04020f", border:"1px solid #e8a0ff12", borderRadius:"4px" }}>
                    <div style={{ fontSize:"9px", color:"#5a3a70", letterSpacing:"0.2em", marginBottom:"5px" }}>RANDOM SALT EMBEDDED IN CIPHERTEXT (not secret)</div>
                    <div style={{ fontFamily:"monospace", fontSize:"11px", color:"#7a5a90", letterSpacing:"0.04em", wordBreak:"break-all" }}>{saltInfo}</div>
                    <div style={{ fontSize:"9px", color:"#3a2050", marginTop:"5px" }}>Your pepper was XORed into this before key derivation — it is stored nowhere in the ciphertext.</div>
                  </div>
                )}

                <div style={{ marginTop:"10px", display:"flex", gap:"8px", flexWrap:"wrap" }}>
                  <button className="rc-btn" onClick={handleCopy} style={{ fontSize:"10px" }}>{copied?"✓ Copied!":"⎘ Copy"}</button>
                  {mode==="encrypt" && (
                    <button className="rc-btn" onClick={() => { switchMode("decrypt"); setCiphertext(output); }} style={{ fontSize:"10px" }}>↩ Test Decrypt</button>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Stats cards */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(120px,1fr))", gap:"10px", marginBottom:"20px" }}>
            {[
              { label:"KEY SIZE",    value:"256-bit",             sub:"2²⁵⁶ possible keys",       hi: false },
              { label:"ALGORITHM",  value:"AES-GCM",             sub:"Authenticated encryption",  hi: false },
              { label:"KEY DERIVE", value:"PBKDF2",              sub:"310,000 iterations",        hi: false },
              { label:"IV",         value:"96-bit",              sub:"Random per message",         hi: false },
              { label:"SALT",       value:saltEnabled?"ACTIVE":"RANDOM", sub:saltEnabled?"Pepper + random":"128-bit random", hi: saltEnabled },
            ].map(({ label, value, sub, hi }) => (
              <div key={label} style={{ background:"#03040d", border:`1px solid ${hi?"#e8a0ff18":"#a0b4ff12"}`, borderRadius:"6px", padding:"14px 12px", textAlign:"center", transition:"all 0.3s" }}>
                <div style={{ fontSize:"9px", color:"#3a4870", letterSpacing:"0.2em", marginBottom:"6px" }}>{label}</div>
                <div style={{ fontFamily:"'VT323',monospace", fontSize:"20px", color:hi?"#e8a0ff":"#a0b4ff", marginBottom:"4px" }}>{value}</div>
                <div style={{ fontSize:"9px", color:"#2a3860", lineHeight:"1.4" }}>{sub}</div>
              </div>
            ))}
          </div>

          {/* Why secure */}
          <div style={{ background:"#03040d", border:"1px solid #a0b4ff12", borderRadius:"8px", padding:"22px 24px" }}>
            <div style={{ fontSize:"10px", color:"#4a5890", letterSpacing:"0.25em", marginBottom:"16px" }}>◈ WHY THIS IS ACTUALLY SECURE</div>
            <div style={{ display:"flex", flexDirection:"column", gap:"12px" }}>
              {[
                { icon:"🔑", title:"256-bit key space",        desc:"Even with every computer on Earth, brute-forcing all 2²⁵⁶ keys would take longer than the age of the universe.", salt:false },
                { icon:"🔀", title:"Random IV per message",    desc:"A fresh 96-bit initialization vector is generated for every encryption. Same message + same password → different ciphertext every time.", salt:false },
                { icon:"🛡", title:"Authentication tag (GCM)", desc:"Any tampering with the ciphertext is detected before decryption. Forged or corrupted messages are rejected outright.", salt:false },
                { icon:"🏗", title:"PBKDF2 key stretching",   desc:"Your password is run through 310,000 hash iterations to derive the key, making offline dictionary attacks extremely slow.", salt:false },
                { icon:"🧂", title:"Custom salt (pepper)",     desc:"SHA-256 hashes your pepper and XORs it into the random PBKDF2 salt. Decryption is impossible without both the password and the correct salt — a true second factor.", salt:true },
                { icon:"🏛", title:"Battle-tested primitives", desc:"AES-256 and GCM are NIST-standardized, audited by the global cryptography community, and used by TLS, Signal, and governments worldwide.", salt:false },
              ].map(({ icon, title, desc, salt }) => (
                <div key={title} style={{ display:"flex", gap:"14px", alignItems:"flex-start", opacity: salt && !saltEnabled ? 0.4 : 1, transition:"opacity 0.3s" }}>
                  <span style={{ fontSize:"16px", flexShrink:0, marginTop:"1px" }}>{icon}</span>
                  <div>
                    <div style={{ fontSize:"11px", color:salt?"#c080ee":"#8090cc", letterSpacing:"0.08em", marginBottom:"3px" }}>
                      {title}{salt && !saltEnabled && <span style={{ color:"#3a2050", fontSize:"9px", marginLeft:"8px" }}>— DISABLED</span>}
                    </div>
                    <div style={{ fontSize:"11px", color:"#2a3860", lineHeight:"1.6" }}>{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ textAlign:"center", marginTop:"28px", fontSize:"10px", color:"#0f1430", letterSpacing:"0.2em" }}>
            SECURE CIPHER ◈ AES-256-GCM ◈ WEB CRYPTO API ◈ NO DATA LEAVES YOUR BROWSER
          </div>
        </div>
      </div>
    </div>
  );
}
