from flask import Flask, render_template, request, jsonify, stream_with_context, Response
from discovery.bruteforce import BruteForcer
import subprocess
import os
import time

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    # Extract scope from target (simple split)
    try:
        from urllib.parse import urlparse
        scope = urlparse(target).netloc
    except:
        scope = target

    # Command to run the agent
    command = ["python", "main.py", "--target", target, "--scope", scope, "--scan-all"]
    
    def generate():
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            bufsize=1,
            cwd=os.getcwd()
        )
        
        # Stream the output line by line
        for line in iter(process.stdout.readline, ''):
            yield f"data: {line}\n\n"
            
        process.stdout.close()
        process.wait()
        
        # After scan, read the report
        if os.path.exists("scan_report.md"):
            with open("scan_report.md", "r") as f:
                report_content = f.read()
                # Send a special event for the report
                # We base64 encode or just safe send it. 
                # For simplicity, we just send a DONE event with the report content if feasible
                # But SSE relies on data: lines. 
                # Let's just signal done and have the frontend fetch the report.
                
        yield "data: [DONE]\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/brute', methods=['POST'])
def brute_force():
    target = request.form.get('target')
    username = request.form.get('username')
    wordlist = request.form.get('wordlist', 'top1000')
    
    if not target or not username:
        return jsonify({"error": "Target and Username required"}), 400

    bf = BruteForcer()
    
    def generate():
        yield f"data: [*] Starting Brute Force on {target}\n\n"
        yield f"data: [*] User: {username} | Wordlist: {wordlist}\n\n"
        
        # Download first if separate step, or just run
        # The run method prints only start/end/success usually.
        # We might want to subclass or modify run to yield. 
        # For simplicity, we wrap the threaded execution or modify BruteForcer to callback?
        # Quick hack: We just run it synchronously-ish (it blocks) but we can yield "Initializing..."
        
        # Actually, since BruteForcer.run returns the password, we can just run it.
        # Capturing the stdout of the class method is hard without redirection.
        # simpler: We modify BruteForcer to match our needs OR we just print result.
        
        # Let's assume we just await the result.
        yield f"data: [*] Downloading/Loading wordlist (this may take a moment)...\n\n"
        
        password = bf.run(target, username, wordlist_name=wordlist)
        
        if password:
            yield f"data: [!!!] SUCCESS! Password Found: {password}\n\n"
        else:
             yield f"data: [-] Failed. Password not in list.\n\n"
             
        yield "data: [DONE]\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/report')
def get_report():
    if os.path.exists("scan_report.md"):
        with open("scan_report.md", "r") as f:
            content = f.read()
        return jsonify({"content": content})
    return jsonify({"content": "No report found."})

@app.route('/download-pdf')
def download_pdf():
    if os.path.exists("scan_report.pdf"):
        from flask import send_file
        return send_file("scan_report.pdf", as_attachment=True)
    return "PDF Not Found", 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
