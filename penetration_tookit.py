import socket
from concurrent.futures import ThreadPoolExecutor
import time
import requests
from flask import Flask, render_template_string, request, jsonify, send_file
from fpdf import FPDF
import io
import threading

app = Flask(__name__)

# ---------------------------
# Module: Port Scanner
# ---------------------------
def scan_port(ip, port, timeout=1):
    """ Try to connect to a port on the target IP. Return True if open. """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def scan_ports(ip, ports, max_workers=100):
    """ Concurrently scan a list of ports on the target IP. Return list of open ports. """
    open_ports = []

    def worker(port):
        if scan_port(ip, port):
            open_ports.append(port)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(worker, ports)

    return sorted(open_ports)

# ---------------------------
# Module: Brute Forcer (HTTP form example)
# ---------------------------
def brute_force_http_login(url, username_field, password_field, username, password_list):
    """
    Attempt to brute force login by POSTing username and password
    to the target URL (assuming simple login form).
    Returns the successful password or None.
    """
    session = requests.Session()
    for password in password_list:
        try:
            data = {username_field: username, password_field: password}
            resp = session.post(url, data=data, timeout=5)
            # This condition needs to be adapted per target (example: check redirect or content)
            if resp.status_code == 200 and "login failed" not in resp.text.lower():
                # Assume login success if "login failed" not detected
                return password
        except requests.RequestException:
            continue
    return None

# ---------------------------
# PDF Report Generation
# ---------------------------
def generate_pdf_report(scan_results, brute_results):
    """
    Generates a PDF report in memory and returns a BytesIO object.
    scan_results: dict {ip: [open ports]}
    brute_results: dict {url: {username: password or None}}
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Penetration Testing Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Port Scan Results:", ln=True)
    pdf.set_font("Arial", '', 12)
    if not scan_results:
        pdf.cell(0, 10, "No port scan performed.", ln=True)
    else:
        for ip, ports in scan_results.items():
            pdf.cell(0, 10, f"Target: {ip}", ln=True)
            if ports:
                pdf.cell(0, 10, f"Open Ports: {', '.join(str(p) for p in ports)}", ln=True)
            else:
                pdf.cell(0, 10, "No open ports found.", ln=True)
            pdf.ln(2)
    pdf.ln(8)

    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Brute Force Results:", ln=True)
    pdf.set_font("Arial", '', 12)
    if not brute_results:
        pdf.cell(0, 10, "No brute force performed.", ln=True)
    else:
        for url, user_results in brute_results.items():
            pdf.cell(0, 10, f"Target URL: {url}", ln=True)
            for user, passwd in user_results.items():
                if passwd:
                    pdf.cell(0, 10, f"User '{user}' login successful! Password: {passwd}", ln=True)
                else:
                    pdf.cell(0, 10, f"User '{user}' password not found.", ln=True)
            pdf.ln(4)
    pdf.ln(8)

    pdf.cell(0, 10, f"Report generated at {time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='R')

    pdf_output = pdf.output(dest='S').encode('latin1')
    output = io.BytesIO(pdf_output)
    output.seek(0)
    return output

# ---------------------------
# Global variables to hold last results
last_scan_results = {}
last_brute_results = {}

# ---------------------------
# Flask routes and web UI
# ---------------------------
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Penetration Testing Toolkit</title>
<link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet" />
<style>
  /* Modern glass-morphism style */
  * {
    box-sizing: border-box;
  }
  body {
    margin: 0; min-height: 100vh;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    color: #fff;
    display: flex; flex-direction: column; align-items: center; padding: 24px;
  }
  h1 {
    margin-bottom: 24px;
    text-align: center;
    text-shadow: 0 0 8px rgba(0,0,0,0.3);
  }
  .container {
    background: rgba(255 255 255 / 0.15);
    backdrop-filter: blur(12px);
    border-radius: 16px;
    box-shadow: 0 8px 32px 0 rgba(0 0 0 / 0.37);
    max-width: 900px;
    width: 100%;
    padding: 24px 32px;
  }
  label {
    display: block;
    margin-top: 16px;
    font-weight: 600;
    font-size: 14px;
    user-select: none;
  }
  input[type=text], input[type=number], textarea {
    margin-top: 8px;
    width: 100%;
    padding: 10px 12px;
    border-radius: 8px;
    border: none;
    font-size: 16px;
    outline: none;
    resize: vertical;
  }
  .button-row {
    margin-top: 24px;
    display: flex; gap: 16px; flex-wrap: wrap;
    justify-content: center;
  }
  button {
    background: linear-gradient(135deg, #8b5cf6, #6366f1);
    color: white;
    border: none;
    padding: 12px 28px;
    border-radius: 12px;
    cursor: pointer;
    font-weight: 700;
    font-size: 16px;
    transition: transform 0.2s ease, box-shadow 0.25s ease;
    display: flex;
    gap: 6px;
    align-items: center;
  }
  button:hover {
    transform: scale(1.05);
    box-shadow: 0 12px 20px rgba(139, 92, 246, 0.6);
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .material-icons {
    font-size: 20px;
  }
  #results {
    margin-top: 32px;
    background: rgba(255 255 255 / 0.1);
    padding: 16px;
    border-radius: 12px;
    max-height: 300px;
    overflow-y: auto;
    font-family: monospace;
    white-space: pre-wrap;
  }
  .footer {
    margin-top: 40px;
    font-size: 13px;
    color: #d1d5db;
    text-align: center;
  }
  @media (max-width: 480px) {
    .button-row {
      flex-direction: column;
    }
    button {
      width: 100%;
      justify-content: center;
    }
  }
</style>
</head>
<body>
<h1>Penetration Testing Toolkit</h1>

<div class="container" role="main">

  <section aria-labelledby="portscan-title">
    <h2 id="portscan-title">Port Scanner</h2>
    <form id="port-scan-form" aria-describedby="portscan-desc">
      <label for="target-ip">Target IP or Hostname</label>
      <input type="text" id="target-ip" name="target" placeholder="e.g. 192.168.1.1 or example.com" required />

      <label for="port-range">Port Range (e.g. 20-80)</label>
      <input type="text" id="port-range" name="ports" placeholder="e.g. 20-80 or 22,80,443" required />

      <div class="button-row">
        <button type="submit" id="start-portscan">
          <span class="material-icons">play_arrow</span> Start Port Scan
        </button>
      </div>
    </form>
  </section>

  <hr style="margin: 32px 0; border-color: rgba(255,255,255,0.25);" />

  <section aria-labelledby="bruteforce-title">
    <h2 id="bruteforce-title">Brute Forcer (HTTP POST Login)</h2>
    <form id="brute-force-form" aria-describedby="bruteforce-desc">
      <label for="login-url">Login URL</label>
      <input type="text" id="login-url" name="url" placeholder="e.g. http://example.com/login" required />

      <label for="username-field">Username Field Name</label>
      <input type="text" id="username-field" name="username_field" placeholder="e.g. username or user" required />

      <label for="password-field">Password Field Name</label>
      <input type="text" id="password-field" name="password_field" placeholder="e.g. password or pass" required />

      <label for="username-input">Username to Test</label>
      <input type="text" id="username-input" name="username" placeholder="e.g. admin" required />

      <label for="password-list">Password List (one per line)</label>
      <textarea id="password-list" name="password_list" placeholder="Enter passwords separated by newlines" rows="5" required></textarea>

      <div class="button-row">
        <button type="submit" id="start-bruteforce">
          <span class="material-icons">play_arrow</span> Start Brute Force
        </button>
      </div>
    </form>
  </section>

  <hr style="margin: 32px 0; border-color: rgba(255,255,255,0.25);" />

  <section>
    <h2>Scan Results</h2>
    <pre id="results" role="region" aria-live="polite" aria-atomic="true" tabindex="0">No scans performed yet.</pre>
  </section>

  <div class="button-row" style="justify-content: center;">
    <button id="generate-pdf" disabled>
      <span class="material-icons">picture_as_pdf</span> Generate PDF Report
    </button>
  </div>
</div>

<div class="footer">
  Developed with Python-Flask | Modular Penetration Testing Toolkit
</div>

<script>
  const portScanForm = document.getElementById('port-scan-form');
  const bruteForceForm = document.getElementById('brute-force-form');
  const resultsPre = document.getElementById('results');
  const pdfButton = document.getElementById('generate-pdf');

  let scanResults = null;
  let bruteResults = null;

  function appendResult(text) {
    resultsPre.textContent += "\\n" + text;
    resultsPre.scrollTop = resultsPre.scrollHeight;
  }

  portScanForm.addEventListener('submit', async e => {
    e.preventDefault();
    resultsPre.textContent = 'Starting port scan...';
    pdfButton.disabled = true;

    const target = e.target.target.value.trim();
    const portsInput = e.target.ports.value.trim();

    const ports = parsePorts(portsInput);
    if (!ports.length) {
      alert('Invalid ports input!');
      return;
    }

    const payload = {
      target,
      ports
    };

    try {
      const res = await fetch('/scan_ports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.error) {
        resultsPre.textContent = 'Error: ' + data.error;
        return;
      }
      resultsPre.textContent = `Port scan complete for ${target}.\nOpen ports:\n${data.open_ports.join(', ') || 'None'}`;
      scanResults = { [target]: data.open_ports };
      enablePdfIfReady();
    } catch (err) {
      resultsPre.textContent = 'Fetch error: ' + err.message;
    }
  });

  bruteForceForm.addEventListener('submit', async e => {
    e.preventDefault();
    resultsPre.textContent = 'Starting brute force...';
    pdfButton.disabled = true;

    const url = e.target.url.value.trim();
    const username_field = e.target.username_field.value.trim();
    const password_field = e.target.password_field.value.trim();
    const username = e.target.username.value.trim();
    const password_list_raw = e.target.password_list.value.trim();

    const password_list = password_list_raw.split('\\n').map(s => s.trim()).filter(Boolean);
    if (!password_list.length) {
      alert('Password list cannot be empty!');
      return;
    }

    const payload = {
      url,
      username_field,
      password_field,
      username,
      password_list
    };

    try {
      const res = await fetch('/brute_force', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.error) {
        resultsPre.textContent = 'Error: ' + data.error;
        return;
      }
      if (data.password) {
        resultsPre.textContent = `Brute force success! Username: ${username} Password: ${data.password}`;
        bruteResults = { [url]: { [username]: data.password } };
      } else {
        resultsPre.textContent = `Brute force failed: Password not found for username '${username}'.`;
        bruteResults = { [url]: { [username]: null } };
      }
      enablePdfIfReady();
    } catch (err) {
      resultsPre.textContent = 'Fetch error: ' + err.message;
    }
  });

  pdfButton.addEventListener('click', () => {
    window.open('/generate_pdf', '_blank');
  });

  function parsePorts(input) {
    const ports = new Set();
    const parts = input.split(',');
    for (let p of parts) {
      p = p.trim();
      if (p.includes('-')) {
        const [start, end] = p.split('-').map(Number);
        if (start > 0 && end >= start && end <= 65535) {
          for (let i = start; i <= end; i++) ports.add(i);
        }
      } else {
        const n = Number(p);
        if (n > 0 && n <= 65535) ports.add(n);
      }
    }
    return Array.from(ports).sort((a,b) => a-b);
  }

  function enablePdfIfReady() {
    if ((scanResults && Object.keys(scanResults).length > 0) || (bruteResults && Object.keys(bruteResults).length > 0)) {
      pdfButton.disabled = false;
    }
  }
</script>

</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/scan_ports', methods=['POST'])
def scan_ports_route():
    try:
        data = request.get_json()
        target = data.get('target')
        ports = data.get('ports')

        if not target or not ports or not isinstance(ports, list):
            return jsonify(error='Invalid input.'), 400

        # Validate ports numeric range and limit to max 1000 ports for performance
        valid_ports = [p for p in ports if isinstance(p, int) and 1 <= p <= 65535]
        if len(valid_ports) > 1000:
            return jsonify(error='Too many ports requested. Max 1000 allowed.'), 400

        open_ports = scan_ports(target, valid_ports)

        global last_scan_results
        last_scan_results = {target: open_ports}

        return jsonify(open_ports=open_ports)
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/brute_force', methods=['POST'])
def brute_force_route():
    try:
        data = request.get_json()
        url = data.get('url')
        username_field = data.get('username_field')
        password_field = data.get('password_field')
        username = data.get('username')
        password_list = data.get('password_list')

        if not all([url, username_field, password_field, username, password_list]):
            return jsonify(error='Missing required parameters.'), 400
        if not isinstance(password_list, list) or len(password_list) > 1000:
            return jsonify(error='Password list must be a list with max length 1000.'), 400

        pwd = brute_force_http_login(url, username_field, password_field, username, password_list)

        global last_brute_results
        last_brute_results = {url: {username: pwd}}

        return jsonify(password=pwd)
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/generate_pdf')
def generate_pdf_route():
    # Generate PDF from last results and send as downloadable file
    pdf_io = generate_pdf_report(last_scan_results, last_brute_results)
    return send_file(pdf_io, mimetype='application/pdf', as_attachment=True, download_name='penetration_report.pdf')

if __name__ == '__main__':
    print("Starting Penetration Testing Toolkit...")
    print("Open http://127.0.0.1:5000/ in your browser to use the toolkit.")
    app.run(debug=True)

