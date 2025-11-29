
import streamlit as st
import subprocess
import json
import time
import os
import sys

OUTPUT_JSON = "data/output/output.json"
PDF_SAVE_PATH = "data/reports/input.pdf"

# ---------- Custom Tailwind-style UI CSS ----------
# st.markdown("""
# <style>
#     .title {
#         font-size: 32px;
#         font-weight: 700;
#         color: #00FFD1;
#         text-align: center;
#         padding: 10px;
#     }
#     .section-card {
#         background: #0e1117;
#         padding: 18px;
#         border-radius: 12px;
#         margin-top: 10px;
#         border: 1px solid #1f2937;
#         box-shadow: 0 4px 10px rgba(0,0,0,0.4);
#     }
#     .verdict-box {
#         background: linear-gradient(90deg, #06D6A0, #1B9C85);
#         padding: 12px;
#         border-radius: 10px;
#         color: blue;
#         font-weight: bold;
#         text-align: center;
#         font-size: 18px;
#     }
# </style>
# """, unsafe_allow_html=True)

st.markdown("""
<style>
    body, .stApp {
        background-color: #d4f8e8 !important;  /* Full background light green */
    }

    .title {
        font-size: 32px;
        font-weight: 700;
        color: #003B73;   /* Deep blue heading */
        text-align: center;
        padding: 10px;
    }

    .section-card {
        background: #002855;  /* Dark navy blue */
        padding: 18px;
        border-radius: 12px;
        margin-top: 10px;
        border: 1px solid #001c3d;
        box-shadow: 0 4px 10px rgba(0,0,0,0.4);
        color: white;   /* White text for readability */
    }

    .verdict-box {
        background: linear-gradient(90deg, #FFD700, #FFA500);
        padding: 12px;
        border-radius: 10px;
        color: black;
        font-weight: bold;
        text-align: center;
        font-size: 18px;
    }

</style>
""", unsafe_allow_html=True)


# ---------------- UI ----------------
st.markdown("<div class='title'>🔐 Cyber Threat Intelligence Analyzer</div>", unsafe_allow_html=True)
st.write("Upload a cyber threat PDF report and run full pipeline using **main.py backend**.")

uploaded_pdf = st.file_uploader("📄 Upload PDF Report", type=["pdf"])

if uploaded_pdf is not None:
    with open(PDF_SAVE_PATH, "wb") as f:
        f.write(uploaded_pdf.read())

    st.success("📁 PDF uploaded successfully!")

    if st.button("🚀 Run Analysis"):
        st.info("⚙ Running backend processing. Please wait...")

        if os.path.exists(OUTPUT_JSON):
            os.remove(OUTPUT_JSON)

        process = subprocess.Popen([sys.executable, "main.py"])

        with st.spinner("Processing PDF... this may take time depending on file size"):
            process.wait()

        if os.path.exists(OUTPUT_JSON):
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                results = json.load(f)

            st.success("🎉 Analysis Completed!")

            # --- Final Verdict ---
            st.markdown(
                f"<div class='verdict-box'>🏁 FINAL VERDICT: {results.get('Final Verdict', 'Unknown')}</div>",
                unsafe_allow_html=True
            )

            # --- Summary ---
            st.markdown("<div class='section-card'><h3>📝 Summary</h3></div>", unsafe_allow_html=True)
            st.write(results.get("summary", ""))

            # 2 Column layout for Info
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("<div class='section-card'><h4>🕵 IoCs</h4></div>", unsafe_allow_html=True)
                st.json(results.get("Threat Intelligence", {}).get("IoCs", {}))

                st.markdown("<div class='section-card'><h4>⚔ TTPs</h4></div>", unsafe_allow_html=True)
                st.json(results.get("Threat Intelligence", {}).get("TTPs", {}))

            with col2:
                st.markdown("<div class='section-card'><h4>🎭 Threat Actor(s)</h4></div>", unsafe_allow_html=True)
                st.json(results.get("Threat Intelligence", {}).get("Threat Actor(s)", []))

                st.markdown("<div class='section-card'><h4>🤖 AI Extracted Entities</h4></div>", unsafe_allow_html=True)
                st.json(results.get("AI Extracted Entities", {}))

            st.markdown("<div class='section-card'><h3>🛡 VirusTotal Results</h3></div>", unsafe_allow_html=True)
            st.json(results.get("VirusTotal Results", {}))

            st.markdown("<div class='section-card'><h3>📦 Download Full Report</h3></div>", unsafe_allow_html=True)

            json_str = json.dumps(results, indent=4, ensure_ascii=False)

            st.download_button(
                label="⬇ Download JSON Report",
                data=json_str,
                file_name="CyberThreatAnalysisReport.json",
                mime="application/json",
                help="Download the full analysis in JSON format"
            )

        else:
            st.error("❌ Something went wrong. No output JSON generated.")

else:
    st.warning("📌 Upload a PDF to begin analysis")
