# 🔐 Secure Cipher

A production-grade, browser-based encryption tool built with React + Vite. Uses the **Web Crypto API** with **AES-256-GCM** the same standard used by Signal, TLS, and government systems.

![AES-256-GCM](https://img.shields.io/badge/cipher-AES--256--GCM-a0b4ff?style=flat-square&labelColor=06080f)
![PBKDF2](https://img.shields.io/badge/key%20derivation-PBKDF2--SHA256-a0b4ff?style=flat-square&labelColor=06080f)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-5-646cff?style=flat-square&logo=vite&logoColor=white)

> ✅ **No data ever leaves your browser.** All cryptographic operations run locally via the native `SubtleCrypto` API.

---

## 🔒 Cryptographic Design

| Property | Detail |
|---|---|
| Algorithm | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-SHA256, 310,000 iterations |
| Random salt | 128-bit, unique per message, embedded in ciphertext |
| Custom pepper | User-supplied, SHA-256 hashed, XORed into salt — **never stored** |
| IV | 96-bit random, unique per message |
| Authentication | GCM tag detects any tampering |
| Key size | 256-bit (2²⁵⁶ possible keys) |

### Why each piece matters

- **AES-256-GCM** — NIST-standardized, audited by the global cryptography community for decades. The "GCM" mode provides both encryption *and* an authentication tag, so any tampering with the ciphertext is detected and rejected.
- **PBKDF2 with 310,000 iterations** — Slows down offline brute-force and dictionary attacks by forcing an attacker to compute 310k hashes per password guess. (OWASP 2023 recommended minimum.)
- **Random 96-bit IV** — A fresh initialization vector per message means identical plaintexts always produce different ciphertexts. Prevents pattern analysis.
- **Random 128-bit salt** — Prevents precomputed rainbow-table attacks on the password.
- **Custom pepper (optional)** — A user-supplied secret that is SHA-256 hashed and XORed into the random PBKDF2 salt before key derivation. The pepper is **never stored anywhere** — not in the ciphertext, not in the app. Without the correct pepper, decryption fails. This acts as a true second factor: an attacker needs the ciphertext, the password, *and* the pepper to decrypt.

### Ciphertext format

Output is Base64-encoded with the following layout:

```
[ salt 16B ][ iv 12B ][ ciphertext + GCM tag ]
```

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or higher

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/secure-cipher.git
cd secure-cipher

# 2. Install dependencies
npm install

# 3. Start the dev server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

---

## 📦 Build for Production

```bash
npm run build
# Output is in /dist — serve it from any static host
npm run preview  # preview locally
```

---

## 🌐 Deploy

### Vercel / Netlify
Import the repo — zero config needed, deploys automatically.

### GitHub Pages

```bash
npm install --save-dev gh-pages
```

Add to `package.json`:
```json
"homepage": "https://YOUR_USERNAME.github.io/secure-cipher",
"scripts": {
  "predeploy": "npm run build",
  "deploy": "gh-pages -d dist"
}
```

Then:
```bash
npm run deploy
```

---

## 🗂 Project Structure

```
secure-cipher/
├── index.html
├── vite.config.js
├── package.json
├── .gitignore
└── src/
    ├── main.jsx          # React root
    ├── App.jsx           # App wrapper
    └── SecureCipher.jsx  # Main component + all crypto logic
```

---

## ⚠️ Limitations & Honest Notes

- **Password strength matters** — AES-256 is unbreakable, but a weak password (e.g. `password123`) can still be guessed. Use a strong, unique passphrase.
- **No key exchange** — This tool assumes you already share a password with the recipient via a separate secure channel.
- **No metadata protection** — Ciphertext length reveals approximate plaintext length.
- **Browser support** — `SubtleCrypto` requires a modern browser (Chrome 37+, Firefox 34+, Safari 11+) and a secure context (`https://` or `localhost`).

---

## 📄 License

MIT
