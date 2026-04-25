import markdown
from xhtml2pdf import pisa
import os

class PDFGenerator:
    def __init__(self, output_dir="."):
        self.output_dir = output_dir

    def convert(self, source_html, output_filename="report.pdf"):
        output_path = os.path.join(self.output_dir, output_filename)
        
        # Define Standard Paged Media CSS (compatible with xhtml2pdf)
        css = """
        <style>
            @page {
                size: A4;
                margin: 2cm;
            }
            body { font-family: Helvetica, sans-serif; font-size: 11pt; line-height: 1.6; color: #333; }
            h1 { font-size: 24pt; color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 10px; margin-top: 0; }
            h2 { font-size: 18pt; color: #7f8c8d; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 5px; }
            h3 { font-size: 14pt; color: #27ae60; margin-top: 20px; }
            pre { background-color: #f8f9fa; padding: 15px; border: 1px solid #e9ecef; font-family: 'Courier New', Courier, monospace; font-size: 9pt; }
            code { background-color: #f8f9fa; font-family: 'Courier New', Courier, monospace; padding: 2px 4px; }
            .vulnerability { border: 1px solid #e1e4e8; background: #fff; padding: 20px; margin-bottom: 20px; }
            .high { border-left: 5px solid #e74c3c; }
            .medium { border-left: 5px solid #f39c12; }
            .low { border-left: 5px solid #3498db; }
            .info { border-left: 5px solid #95a5a6; }
            strong { color: #000; }
        </style>
        """

        # Prepare HTML structure
        final_html = f"""
        <html>
        <head>{css}</head>
        <body>
            {source_html}
        </body>
        </html>
        """

        try:
            with open(output_path, "wb") as f:
                pisa_status = pisa.CreatePDF(final_html, dest=f)
            return not pisa_status.err
        except Exception as e:
            print(f"PDF Generation Error: {e}")
            return False

    def generate_from_markdown(self, markdown_content, filename="scan_report.pdf"):
        # Convert MD to HTML with extensions
        html_content = markdown.markdown(markdown_content, extensions=['fenced_code', 'tables', 'nl2br'])
        return self.convert(html_content, filename)
