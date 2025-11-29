
import json
import os
from transformers import pipeline
from src.extracter import extract_threat_intelligence, extract_with_ai_ner, read_pdf
from src.vt_api import check_iocs_with_virustotal

# ------------------- LOAD SUMMARIZATION MODEL -------------------
print("📦 Loading summarization model...")
try:
    summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
    print("🤖 Summarizer Loaded Successfully (BART-Large)")
except Exception as e:
    print("⚠ Failed to load summarization model:", e)
    summarizer = None


# ------------------- DOCUMENT SUMMARY FUNCTION -------------------
def summarize_report(text: str) -> str:
    if summarizer is None:
        return "Summarization unavailable (model not loaded)."

    try:
        words = text.split()
        if len(words) < 60:
            return "Not enough textual content to summarize."

        chunk_size = 300
        chunks = [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]

        summaries = []
        for idx, chunk in enumerate(chunks[:10]):  # Limit to first 10 chunks to avoid overload
            print(f"📄 Summarizing chunk {idx + 1}/{min(len(chunks),10)} ...")
            try:
                summary = summarizer(chunk, max_length=180, min_length=60, do_sample=False)[0]["summary_text"]
                summaries.append(summary)
            except Exception:
                continue

        return " ".join(summaries)

    except Exception as e:
        print("⚠ Summary error:", e)
        return "Summary unavailable due to processing limitation."


# ---------------------- FORMATTERS ----------------------
def format_ttps(ttp_data: dict):
    def convert(items):
        formatted = []
        for item in items:
            try:
                tid, meaning = item.split(" ", 1)
                formatted.append({tid: meaning})
            except:
                formatted.append({item: ""})
        return formatted

    return {
        "Tactics": convert(ttp_data.get("Tactics", [])),
        "Techniques": convert(ttp_data.get("Techniques", [])),
    }


# def format_malware(hashes):
#     return [
#         {
#             "Name": "Unknown Malware",
#             "md5": h if len(h) == 32 else "",
#             "sha1": h if len(h) == 40 else "",
#             "sha256": h if len(h) == 64 else "",
#             "ssdeep": "",
#             "TLSH": "",
#             "tags": ""
#         }
#         for h in hashes
#     ]

#def format_malware(hash_results):
    # malware_list = []
    # for hash_value, info in hash_results.items():
    #     malware_list.append({
    #         "Name": info.get("malware_name", "Unknown"),
    #         "md5": hash_value if len(hash_value) == 32 else "",
    #         "sha1": hash_value if len(hash_value) == 40 else "",
    #         "sha256": hash_value if len(hash_value) == 64 else "",
    #         "ssdeep": "",
    #         "TLSH": "",
    #         "tags": ""
    #     })
    # return malware_list

def format_malware(hashes, vt_hash_info=None):
    malware_list = []

    # If VirusTotal returned detailed hash info (dict format)
    if isinstance(vt_hash_info, dict):
        for h, info in vt_hash_info.items():
            malware_list.append({
                "Name": info.get("malware_name", "Unknown Malware"),
                "md5": h if len(h) == 32 else "",
                "sha1": h if len(h) == 40 else "",
                "sha256": h if len(h) == 64 else "",
                "score": info.get("score", 0),
                "ssdeep": "",
                "TLSH": "",
                "tags": ""
            })
        return malware_list

    # Fallback: No VirusTotal names available, basic formatting
    for h in hashes:
        malware_list.append({
            "Name": "Unknown Malware",
            "md5": h if len(h) == 32 else "",
            "sha1": h if len(h) == 40 else "",
            "sha256": h if len(h) == 64 else "",
            "score": "",
            "ssdeep": "",
            "TLSH": "",
            "tags": ""
        })
    return malware_list

# ------------------- PATHS -------------------
PDF_PATH = r"C3i_HACKATHON_FINAL_ROUND_Q1_DATA/Checkpoint_BlindEagle-Targeting-Ecuador-Sharpened-Tools(01-05-2023).pdf"
OUTPUT_FILE = r"data/output/output.json"
os.makedirs("data/output", exist_ok=True)

# ------------------- EXECUTION PIPELINE -------------------
print("🔍 Extracting text from PDF...")
text = read_pdf(PDF_PATH)

if not text.strip():
    print("❌ ERROR: No text extracted. Stopping process.")
    exit()

print("🧠 Extracting rule-based indicators...")
rule_output = extract_threat_intelligence(text)

print("🤖 Running AI NER extraction...")
ai_entities = extract_with_ai_ner(text)

print("🛡 Running VirusTotal lookups...")
vt_results, verdict = check_iocs_with_virustotal(rule_output.get("IoCs", {}))

print("📝 Summarizing the document...")
summary_text = summarize_report(text)

# ------------------- BUILD FINAL JSON -------------------
final_output = {
    "file_processed": os.path.basename(PDF_PATH),
    "summary": summary_text,
    "Threat Intelligence": {
        "IoCs": {
            "IP addresses": rule_output["IoCs"].get("IPs", []),
            "Domains": rule_output["IoCs"].get("Domains", [])
        },
        "TTPs": format_ttps(rule_output.get("TTPs", {})),
        "Threat Actor(s)": rule_output.get("Threat Actors", []),
        "Malware": format_malware(rule_output["IoCs"].get("Hashes", [])),
        "Targeted Entities": rule_output.get("Targeted Entities", [])
    },
    "AI Extracted Entities": ai_entities,
    "VirusTotal Results": vt_results,
    "Final Verdict": verdict
}

# ------------------- SAVE OUTPUT -------------------
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(final_output, f, indent=4, ensure_ascii=False)

print("\n📁 Output saved successfully →", OUTPUT_FILE)
print("🏁 Final Verdict:", verdict)
