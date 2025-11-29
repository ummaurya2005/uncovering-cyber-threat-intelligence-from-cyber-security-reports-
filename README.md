graph TD;
    A[Upload PDF via UI] --> B[Extract Text From PDF / OCR]
    B --> C[Rule-Based Threat Discovery]
    B --> D[AI NER Model Extraction]
    C --> E[MITRE TTP Detection]
    C --> F[Indicators of Compromise Extraction]
    F --> G[Check IoCs via VirusTotal]
    G --> H[Final Scoring Verdict]
    B --> I[Summarization Model]
    C --> J[Output JSON]
    D --> J
    H --> J
    I --> J
    J --> K[Display Results in UI]


git clone YOUR_REPO_URL
cd cyber-threat-intelligence-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # (Linux/Mac)
venv\Scripts\activate     # (Windows)

pip install -r requirements.txt



python main.py

streamlit run app.py


📁 cyber-threat-intelligence-analyzer
│── app.py                    # Streamlit UI
│── main.py                   # Backend processing pipeline
│── requirements.txt
│── README.md
│
├── src/
│   ├── extracter.py          # Text → IoC + TTP extraction
│   └── vt_api.py             # VirusTotal API handler
│
├── data/
│   ├── reports/              # Input PDFs
│   └── output/               # Output JSON
│
├── .gitignore
└── .env

{
  "Final Verdict": "Malicious",
  "IoCs": {
    "IP addresses": ["192.168.1.1"],
    "Domains": ["example.com"]
  },
  "TTPs": {
    "Tactics": [{"TA0001": "Initial Access"}],
    "Techniques": [{"T1566.001": "Spear Phishing Attachment"}]
  },
  "VirusTotal Results": {
    "Hashes": {
      "abc123": {
        "score": 31,
        "malware_name": "Hacktool.PDF.Phish.3!c"
      }
    }
  }
}

