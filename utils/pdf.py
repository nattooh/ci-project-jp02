import PyPDF2

def extract_pdf_text(path: str) -> str:
    text = ""
    with open(path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for i in range(len(reader.pages)):
            page = reader.pages[i]
            text += page.extract_text() or ""
            text += "\n"
    return text
