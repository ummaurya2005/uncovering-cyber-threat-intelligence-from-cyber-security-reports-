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
