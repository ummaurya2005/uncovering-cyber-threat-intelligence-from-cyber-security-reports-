
from PyPDF2 import PdfReader

def generate_report(pdf_path):
    """
    Extracts and returns all cleaned text from PDF
    """
    try:
        reader = PdfReader(pdf_path)
        text = ""

        for page in reader.pages:
            page_text = page.extract_text() or ""
            text += page_text.replace("\n", " ").strip() + " "

        return text

    except Exception as e:
        print(f"[ERROR] Unable to read PDF: {e}")
        return ""
