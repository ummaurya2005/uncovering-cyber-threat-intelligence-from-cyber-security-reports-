# 🛡 Cyber Threat Intelligence Analyzer
AI-Powered Automated Threat Intelligence from Cybersecurity PDF Reports  
Extract IoCs, TTPs, Threat Actors, Malware signatures, run VirusTotal analysis & generate summaries.

---

![Banner](https://vipre.com/wp-content/uploads/2022/08/8-9-2022-8-33-54-PM.jpg)

---

# 🛡 Cyber Threat Intelligence Analyzer
AI-Powered Automated Threat Intelligence from Cybersecurity PDF Reports  
Extract IoCs, TTPs, Threat Actors, Malware signatures, run VirusTotal analysis & generate summaries.

---

![Banner](https://via.placeholder.com/1200x300?text=Cyber+Threat+Intelligence+Analyzer+%7C+AI+Security+Tool)

---

## 🚀 System Architecture Diagram

```mermaid
graph TD;
    A[Upload PDF via UI] --> B[Extract Text From PDF / OCR]
    B --> C[Rule-Based Threat Discovery]
    B --> D[AI NER Model Extraction]
    C --> E[MITRE TTP Detection]
    C --> F[Indicators of Compromise Extraction]
    F --> G[Check IoCs with VirusTotal API]
    G --> H[Final Scoring Verdict]
    B --> I[Summarization Model]
    C --> J[Output JSON]
    D --> J
    H --> J
    I --> J
    J --> K[Display Results in UI]
```
### 🧪 Sample Output JSON
```json
{
  "Final Verdict": "Malicious",
  "IoCs": {
    "IP addresses": ["192.168.1.1"],
    "Domains": ["example.com"]
  },
  "TTPs": {
    "Tactics": [
      { "TA0001": "Initial Access" }
    ],
    "Techniques": [
      { "T1566.001": "Spear Phishing Attachment" }
    ]
  },
  "Threat Actor(s)": ["APT33"],
  "VirusTotal Results": {
    "Hashes": {
      "abc123": {
        "score": 31,
        "malware_name": "Hacktool.PDF.Phish.3!c"
      }
    }
  }
}
```

###📁 **cyber-threat-intelligence-analyzer**

```bash
│── `app.py`                    # Streamlit UI
│── `main.py`                   # Backend pipeline
│── `requirements.txt`
│── `README.md`
│
├── **src/**
│   ├── `extracter.py`          # Text → IoC, TTP, Threat Actor extraction
│   └── `vt_api.py`             # VirusTotal API integration
│
├── **data/**
│   ├── `reports/`              # Uploaded PDFs
│   └── `output/`               # Result JSON files
│
├── **config/**
│   └── `config.json`           # API Keys (ignored in Git)
│
├── `.gitignore`
└── `.env`
```


