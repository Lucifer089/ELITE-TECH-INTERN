from flask import Flask, request, render_template_string, redirect, url_for
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re

app = Flask(__name__)

SQLI_TESTS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    '" OR "1"="1',
    "' OR SLEEP(5)--"
]

XSS_TEST = '<script>alert("XSS")</script>'

def is_internal_url(url, base_netloc):
    try:
        return urlparse(url).netloc == base_netloc
    except Exception:
        return False

def calculate_sqli_vulnerabilities(session, url, params, method='get'):
    vulnerabilities = []
    for param in params:
        for payload in SQLI_TESTS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                if method == 'post':
                    res = session.post(url, data=test_params, timeout=10)
                else:
                    res = session.get(url, params=test_params, timeout=10)
            except:
                continue
            text = res.text.lower()
            errors = [
                "you have an error in your sql syntax;",
                "warning: mysql",
                "unclosed quotation mark after the character string",
                "quoted string not properly terminated",
                "sql syntax error",
                "mysql_fetch_array()",
                "syntax error",
                "mysql_num_rows()",
                "odbc sql server driver"
            ]
            if any(error in text for error in errors):
                vulnerabilities.append((param, payload))
                break
    return vulnerabilities

def calculate_xss_vulnerabilities(session, url, params, method='get'):
    vulnerabilities = []
    for param in params:
        test_params = params.copy()
        test_params[param] = XSS_TEST
        try:
            if method == 'post':
                res = session.post(url, data=test_params, timeout=10)
            else:
                res = session.get(url, params=test_params, timeout=10)
        except:
            continue
        # Basic reflection check, not secure but enough for demo
        if XSS_TEST.lower() in res.text.lower():
            vulnerabilities.append(param)
    return vulnerabilities

@app.route("/", methods=["GET", "POST"])
def index():
    vulnerabilities = []
    error = None
    scanned_url = None

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()
        if not target_url:
            error = "Please enter a valid URL."
            return render_template_string(TEMPLATE, vulnerabilities=vulnerabilities, error=error)
        try:
            session = requests.Session()
            res = session.get(target_url, timeout=10)
            scanned_url = target_url
            soup = BeautifulSoup(res.text, "html.parser")
            base_netloc = urlparse(target_url).netloc
            checked_urls = set()
            pages_to_check = [(target_url, res.text)]
            links_queue = []

            # Extract links within domain to crawl (limit to 10 pages)
            for a_tag in soup.find_all("a", href=True):
                href = urljoin(target_url, a_tag["href"])
                if is_internal_url(href, base_netloc):
                    links_queue.append(href)
            # Limit pages to scan to 10 for demo
            links_queue = links_queue[:10]

            # Prepare results list for displaying vulnerabilities
            vulnerabilities = []

            # Scan main page forms
            vulnerabilities.extend(scan_forms(session, target_url, soup))

            # Scan GET parameters in URL if any
            vulnerabilities.extend(scan_get_params(session, target_url))

            # Scan linked pages
            for page_url in links_queue:
                if page_url in checked_urls:
                    continue
                try:
                    page_res = session.get(page_url, timeout=10)
                    page_soup = BeautifulSoup(page_res.text, "html.parser")
                except:
                    continue
                checked_urls.add(page_url)
                vulnerabilities.extend(scan_forms(session, page_url, page_soup))
                vulnerabilities.extend(scan_get_params(session, page_url))

            if not vulnerabilities:
                vulnerabilities.append({"type": "Info", "url": "N/A", "details": "No vulnerabilities detected."})

        except Exception as e:
            error = f"Error scanning the site: {e}"

    return render_template_string(TEMPLATE, vulnerabilities=vulnerabilities, error=error, scanned_url=scanned_url)

def scan_forms(session, url, soup):
    vulns = []
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, action) if action else url
        inputs = form.find_all(['input', 'textarea'])
        data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                data[name] = "test"
        # Test SQLi
        sqli_vulns = calculate_sqli_vulnerabilities(session, form_url, data, method)
        for param, payload in sqli_vulns:
            vulns.append({"type": "SQL Injection", "url": url, "details": f"Form param '{param}' vulnerable, payload: {payload}"})
        # Test XSS
        xss_vulns = calculate_xss_vulnerabilities(session, form_url, data, method)
        for param in xss_vulns:
            vulns.append({"type": "Reflected XSS", "url": url, "details": f"Form param '{param}' vulnerable to reflected XSS"})
    return vulns

def scan_get_params(session, url):
    vulns = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return vulns
    params_dict = {k: v[0] for k, v in params.items()}
    # SQLi test
    sqli_vulns = calculate_sqli_vulnerabilities(session, url, params_dict, 'get')
    for param, payload in sqli_vulns:
        vulns.append({"type": "SQL Injection", "url": url, "details": f"GET param '{param}' vulnerable, payload: {payload}"})
    # XSS test
    xss_vulns = calculate_xss_vulnerabilities(session, url, params_dict, 'get')
    for param in xss_vulns:
        vulns.append({"type": "Reflected XSS", "url": url, "details": f"GET param '{param}' vulnerable to reflected XSS"})
    return vulns

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Web Vulnerability Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet"/>
<style>
    :root {
        --primary: #4f46e5;
        --primary-dark: #4338ca;
        --bg-light: #f3f4f6;
        --text-dark: #1f2937;
        --text-muted: #6b7280;
        --error-color: #b91c1c;
        --info-color: #2563eb;
    }
    * {
        box-sizing: border-box;
        scroll-behavior: smooth;
    }
    body {
        margin: 0;
        font-family: 'Poppins', sans-serif;
        background: var(--bg-light);
        color: var(--text-dark);
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }
    header {
        background-color: var(--primary);
        color: white;
        padding: 1.2rem 1rem;
        font-size: 1.75rem;
        font-weight: 600;
        text-align: center;
        box-shadow: 0 4px 8px rgba(79, 70, 229, 0.3);
    }
    main {
        flex-grow: 1;
        max-width: 900px;
        width: 100%;
        margin: 2rem auto;
        padding: 0 1rem 3rem;
    }
    form {
        display: flex;
        gap: 0.75rem;
        margin-bottom: 1.5rem;
        flex-wrap: wrap;
        justify-content: center;
    }
    input[type="url"] {
        flex-grow: 1;
        min-width: 280px;
        padding: 0.65rem 1rem;
        font-size: 1.1rem;
        border: 2px solid #ddd;
        border-radius: 8px;
        transition: border-color 0.3s ease;
    }
    input[type="url"]:focus {
        outline: none;
        border-color: var(--primary-dark);
        box-shadow: 0 0 6px var(--primary-dark);
    }
    button {
        background: var(--primary);
        color: #fff;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        font-size: 1.1rem;
        cursor: pointer;
        padding: 0 1.5rem;
        min-height: 44px;
        box-shadow: 0 4px 8px rgba(79, 70, 229, 0.45);
        transition: background-color 0.3s ease, transform 0.15s ease;
    }
    button:hover, button:focus {
        background: var(--primary-dark);
        transform: translateY(-2px);
        outline: none;
        box-shadow: 0 6px 12px rgba(67, 56, 202, 0.8);
    }
    button:active {
        transform: translateY(0);
    }
    .error {
        color: var(--error-color);
        font-weight: 600;
        margin-bottom: 1rem;
        text-align: center;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        box-shadow: 0 0 14px rgb(0 0 0 / 0.1);
        border-radius: 12px;
        overflow: hidden;
        background: white;
    }
    th, td {
        padding: 0.9rem 1rem;
        text-align: left;
        font-size: 0.95rem;
        border-bottom: 1px solid #e5e7eb;
    }
    th {
        background: #ede9fe;
        font-weight: 600;
        color: var(--primary-dark);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    tr:nth-child(even) {
        background: #fafafa;
    }
    a {
        color: var(--primary);
        text-decoration: none;
        transition: color 0.3s ease;
    }
    a:hover, a:focus {
        color: var(--primary-dark);
        text-decoration: underline;
    }
    h2 {
        color: var(--primary-dark);
        margin-top: 2rem;
        margin-bottom: 0.8rem;
        font-weight: 700;
    }
    @media (max-width: 600px) {
      form {
        flex-direction: column;
        gap: 1rem;
      }
      input[type="url"] {
        width: 100%;
      }
      button {
        width: 100%;
      }
      table, thead, tbody, th, td, tr {
        display: block;
      }
      thead tr {
        position: absolute;
        top: -9999px;
        left: -9999px;
      }
      tr {
        margin-bottom: 1rem;
        border-bottom: 2px solid var(--bg-light);
      }
      td {
        border-bottom: 1px solid var(--bg-light);
        position: relative;
        padding-left: 50%;
        white-space: pre-wrap;
        text-align: right;
      }
      td::before {
        position: absolute;
        top: 0;
        left: 0;
        width: 48%;
        padding-left: 1rem;
        font-weight: 700;
        white-space: nowrap;
        text-align: left;
        content: attr(data-label);
        color: var(--text-muted);
      }
    }
</style>
</head>
<body>
<header>Web Vulnerability Scanner</header>
<main>
    <form method="post" action="/">
        <input type="url" id="url" name="url" placeholder="Enter website URL (e.g. https://example.com)" required autofocus value="{{ scanned_url or '' }}" />
        <button type="submit" aria-label="Start vulnerability scan">Scan</button>
    </form>
    {% if error %}
        <div class="error" role="alert">{{ error }}</div>
    {% endif %}
    {% if vulnerabilities %}
        <h2>Scan Results</h2>
        <table role="table" aria-live="polite" aria-relevant="all" aria-label="Vulnerability scan results">
            <thead>
                <tr>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">URL</th>
                    <th scope="col">Details</th>
                </tr>
            </thead>
            <tbody>
                {% for v in vulnerabilities %}
                    <tr>
                        <td data-label="Vulnerability">{{ v.type }}</td>
                        <td data-label="URL"><a href="{{ v.url }}" target="_blank" rel="noopener noreferrer">{{ v.url }}</a></td>
                        <td data-label="Details">{{ v.details }}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% endif %}
</main>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)

