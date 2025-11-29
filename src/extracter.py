
import re
import spacy
import fitz  # PyMuPDF for PDF text & OCR
import pytesseract
from PIL import Image
from tld import get_tld
from typing import Dict, Any, List
from transformers import pipeline

# ======================
# Load spaCy Model
# ======================
nlp = spacy.load("en_core_web_sm")

# ======================
# Load AI NER Model (Safe)
# ======================
try:
    ai_ner = pipeline(
        task="token-classification",
        model="dslim/bert-base-NER",
        aggregation_strategy="simple"
    )
    print("🤖 AI NER Model Loaded Successfully (dslim/bert-base-NER)")
except Exception as e:
    print("⚠ Failed to load AI NER model:", e)
    ai_ner = None  # keep typing valid


# =========================================================
#               DOMAIN VALIDATION
# =========================================================
def is_valid_domain(domain: str) -> bool:
    try:
        get_tld("http://" + domain, fail_silently=False)
        return True
    except Exception:
        return False


# =========================================================
#                   IoC Extraction
# =========================================================
def extract_iocs(text: str) -> Dict[str, List[str]]:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    hash_pattern = r'\b[A-Fa-f0-9]{32,64}\b'

    ips = list(set(re.findall(ip_pattern, text)))

    domains = [
        d for d in set(re.findall(domain_pattern, text))
        if is_valid_domain(d) and not d.lower().endswith(("exe", "dll", "zip"))
    ]

    hashes = list(set(re.findall(hash_pattern, text)))

    return {"IPs": ips, "Domains": domains, "Hashes": hashes}


# =========================================================
#                   MITRE TTP Extraction
# =========================================================
def extract_ttps(text: str) -> Dict[str, List[str]]:
    MITRE_TTPs = {
        "TA0001 Initial Access": ["initial access", "exploit", "compromise"],
        "TA0002 Execution": ["execute", "run", "payload"],
        "TA0003 Persistence": ["backdoor", "persistence"],
        "TA0008 Lateral Movement": ["lateral movement", "pivot"],
        "TA0010 Exfiltration": ["exfiltrate", "steal", "leak"],
        "TA0040 Impact": ["destroy", "ransomware", "damage"]
    }

    MITRE_Techniques = {
        "T1566.001 Spear-phishing Attachment": ["spear phishing", "phishing"],
        "T1059 PowerShell": ["powershell", "cmd.exe"],
        "T1041 Exfiltration Over C2 Channel": ["c2", "command and control"]
    }

    lower = text.lower()

    detected_tactics = [
        tid for tid, keys in MITRE_TTPs.items() if any(k in lower for k in keys)
    ]

    detected_techniques = [
        tid for tid, keys in MITRE_Techniques.items() if any(k in lower for k in keys)
    ]

    return {"Tactics": detected_tactics, "Techniques": detected_techniques}


# =========================================================
#              Threat Actor / Target Entities
# =========================================================
def extract_threat_actors(text: str) -> List[str]:
    pattern = r"\b(APT[- ]?\d{1,3}|UNC\d{2,4}|FIN\d{1,3}|Lazarus|Sandworm|Gamaredon|Mustang Panda|Volt Typhoon|Cobalt Group)\b"
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_targeted_entities(text: str) -> List[str]:
    keywords = [
        "government", "bank", "military", "aerospace",
        "defense", "infrastructure", "healthcare",
        "education", "telecom", "financial"
    ]
    return list({kw.capitalize() for kw in keywords if kw in text.lower()})


# =========================================================
#                     AI NER Chunk Extraction
# =========================================================
def extract_with_ai_ner(text: str, chunk_size: int = 400) -> Dict[str, List[str]]:
    if ai_ner is None:
        return {}

    words = text.split()
    chunks = [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]
    results: Dict[str, List[str]] = {}

    for chunk in chunks:
        try:
            ner_results = ai_ner(chunk)
            for item in ner_results:
                label = item.get("entity_group", "")
                word = item.get("word", "").replace("▁", "")  # remove BPE markers
                if label and word:
                    results.setdefault(label, []).append(word)
        except Exception:
            continue

    return results


# =========================================================
#                     PDF Reader with OCR fallback
# =========================================================
def read_pdf(path: str) -> str:
    doc = fitz.open(path)
    text = ""

    for page in doc:
        extracted = page.get_text("text")
        if extracted and extracted.strip():
            text += extracted + "\n"
        else:
            try:
                pix = page.get_pixmap()
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                text += pytesseract.image_to_string(img) + "\n"
            except Exception:
                continue

    return text


# =========================================================
#                Final Threat Extractor Wrapper
# =========================================================
def extract_threat_intelligence(text: str) -> Dict[str, Any]:
    return {
        "IoCs": extract_iocs(text),
        "TTPs": extract_ttps(text),
        "Threat Actors": extract_threat_actors(text),
        "Targeted Entities": extract_targeted_entities(text)
    }
