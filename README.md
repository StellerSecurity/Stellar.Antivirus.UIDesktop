# **Stellar Antivirus — Swiss-Grade Protection**

{Still in work}

Stellar Antivirus is a cross-platform security engine built for **Mac, Linux and Windows** (Windows version WIP).  
It combines a modern UI written in **React + Tailwind** with a high-performance **Tauri/Rust backend**, delivering fast, privacy-focused malware detection with Swiss-grade precision.

Stellar Antivirus is part of the **Stellar Security** ecosystem — a Swiss company dedicated to protecting everyone's privacy and security.

---

## ✨ Features

### 🔍 **Full System Scan**
Fast Rust-powered scanning through:
- Desktop  
- Documents  
- Downloads  
- User-defined paths (coming soon)

Matches files against:
- Local signature DB (SQLite)  
- SHA-256 threat hashes  
- Filename rules (test mode)  
- Cloud-updated DB (Azure Blob Storage)

---

### 🛡 **Real-Time Protection**
Monitors files using OS-native APIs:

| Platform | API |
|---------|------|
| macOS   | FSEvents |
| Linux   | inotify |
| Windows | USN Journal (coming) |

Real-time engine:
- Detects creation/modification  
- Hashes file instantly  
- Matches against signature DB  
- Blocks & quarantines threats  
- Sends native OS notifications  

---

### 🗃 **Quarantine**
All detected threats can be:
- Moved to isolated quarantine folder  
- Restored later  
- Permanently deleted  

Every detection is logged in SQLite.

---

### 🔔 **Native Notifications**
Powered by **Tauri Notification Plugin**  
Notifications on:
- Threat blocked (real-time)  
- Threats found (full scan)  
- Scan clean  
- DB sync status  

---

### 🔄 **Automatic Threat DB Updates**
Threat DB auto-syncs every hour from:

```
https://stellarantivirusthreatdb.blob.core.windows.net/threat-db/v1/threats.json
```

Configurable via `.env`:

```
VITE_THREAT_DB_URL="https://stellarantivirusthreatdb.blob.core.windows.net/threat-db/v1/threats.json"
```

---

### 🚀 **Autostart & Background Mode**
Starts with the system  
Runs silently with tray support  
Realtime engine always active unless disabled

---

### 🧬 **Cross-Platform**
- Linux  
- macOS  
- Windows (coming soon)

---

## 🧩 Tech Stack

### Frontend
- React 19  
- Vite  
- Tailwind CSS  
- TypeScript  

### Backend
- Tauri 2  
- Rust  
- notify (FS events)  
- rusqlite  
- sha2  
- hex  

---

## 📂 Project Structure

```
/
├── src/                       # React UI
│   ├── components/
│   ├── screens/
│   └── App.tsx
│
└── src-tauri/
    ├── src/lib.rs            # Rust backend (scan engine, realtime, DB)
    ├── tauri.conf.json
    └── Cargo.toml
```

---

## 🚀 Development

Install dependencies:

```bash
npm install
```

Run dev mode:

```bash
npm run tauri
```

Build production binaries:

```bash
npm run tauri build
```

---

## 🔐 Security Notes
- All scanning is local  
- No user data leaves the device  
- DB is read-only & cloud-delivered  
- Quarantine is isolated per-user  
- Future: signed DB + secure updater  

---

## 🌍 Roadmap
- [ ] Windows realtime engine (USN Journal)  
- [ ] Deep Scan mode  
- [ ] Folder exclusions  
- [ ] Tauri Updater (auto-updates)  
- [ ] Threat reputation cloud API  
- [ ] Signed threat DB  
- [ ] Behavioral sandbox  

---

## 🛡 About Stellar Security
Stellar Security is a Swiss cybersecurity company with a single mission:

> *“To protect everyone’s privacy and security.”*

Stellar Antivirus is part of the broader Stellar ecosystem:
- Stellar Phone  
- StellarOS  
- Stellar VPN  
- Stellar Protect  
- Stellar Secret  
- More to come…

---

## 📧 Contact

**Website:** https://stellarsecurity.com  
**Email:** info@stellarsecurity.com  
**Signal:** StellarSecurity.30  
