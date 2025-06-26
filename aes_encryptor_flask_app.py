from flask import Flask, render_template_string, request, send_file, flash, redirect, url_for
from io import BytesIO
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Needed for flash messages

# HTML template with inline CSS and JS for modern, engaging UI
template = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AES-256 File Encryptor/Decryptor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;700&display=swap');

  /* Reset */
  * {
    margin: 0; padding: 0; box-sizing: border-box;
  }

  body {
    font-family: 'Poppins', sans-serif;
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    min-height: 100vh;
    color: #f0f4f8;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 20px;
  }

  main {
    background: rgba(32, 58, 67, 0.85);
    border-radius: 16px;
    padding: 32px 40px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.6);
    max-width: 520px;
    width: 100%;
    backdrop-filter: blur(8px);
  }

  h1 {
    font-size: 2rem;
    font-weight: 700;
    text-align: center;
    margin-bottom: 24px;
    background: linear-gradient(90deg, #7f59ff, #00d0ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  label {
    font-weight: 600;
    font-size: 1rem;
    margin-bottom: 6px;
  }

  input[type="file"] {
    padding: 6px;
    border-radius: 8px;
    border: none;
    background: #1c2e3c;
    color: #a9b8c9;
    cursor: pointer;
  }
  input[type="file"]::-webkit-file-upload-button {
    cursor: pointer;
    background: #7f59ff;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 8px;
    transition: background 0.3s ease;
  }
  input[type="file"]::-webkit-file-upload-button:hover {
    background: #914fff;
  }
  input[type="file"]:focus-visible {
    outline: 2px solid #00d0ff;
  }

  input[type="password"], input[type="text"] {
    padding: 12px 14px;
    font-size: 1rem;
    border-radius: 12px;
    border: none;
    background: #1c2e3c;
    color: #f0f4f8;
    transition: box-shadow 0.3s ease;
  }
  input[type="password"]:focus, input[type="text"]:focus {
    outline: none;
    box-shadow: 0 0 8px 2px #00d0ff;
  }

  .toggle-password {
    margin-top: -12px;
    margin-bottom: 16px;
    cursor: pointer;
    align-self: flex-end;
    font-size: 0.9rem;
    color: #7f59ff;
    user-select: none;
  }
  .toggle-password:hover {
    color: #914fff;
  }

  .mode-selector {
    display: flex;
    justify-content: center;
    gap: 30px;
    margin-bottom: 20px;
  }
  .mode-selector input[type="radio"] {
    display: none;
  }
  .mode-selector label {
    background: #1c2e3c;
    padding: 10px 26px;
    border-radius: 20px;
    cursor: pointer;
    font-weight: 600;
    color: #a9b8c9;
    user-select: none;
    transition: background 0.3s ease, color 0.3s ease;
  }
  .mode-selector input[type="radio"]:checked + label {
    background: linear-gradient(90deg, #7f59ff, #00d0ff);
    color: white;
    box-shadow: 0 0 10px #7f59ff;
  }

  button {
    margin-top: 10px;
    padding: 14px;
    font-weight: 700;
    font-size: 1.1rem;
    border-radius: 14px;
    border: none;
    background: linear-gradient(90deg, #7f59ff, #00d0ff);
    color: white;
    cursor: pointer;
    transition: background 0.3s ease, box-shadow 0.3s ease;
    user-select: none;
  }
  button:hover:not(:disabled) {
    background: linear-gradient(90deg, #914fff, #00e0ff);
    box-shadow: 0 0 12px 2px #7f59ff;
  }
  button:disabled {
    background: #555d6e;
    cursor: not-allowed;
  }

  .flash {
    margin-top: 14px;
    padding: 12px;
    border-radius: 12px;
    font-weight: 600;
    text-align: center;
  }
  .flash.error {
    background: #f44336;
    color: white;
  }
  .flash.success {
    background: #4caf50;
    color: white;
  }

  /* Responsive */
  @media(max-width: 600px){
    main {
      padding: 24px;
    }
  }
</style>
</head>
<body>
<main>
  <h1>AES-256 Encryptor & Decryptor</h1>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="flash {{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  
  <form method="POST" enctype="multipart/form-data" id="encdecForm">
    <div class="mode-selector" role="radiogroup" aria-label="Select operation mode">
      <input type="radio" id="modeEncrypt" name="mode" value="encrypt" checked>
      <label for="modeEncrypt">Encrypt</label>

      <input type="radio" id="modeDecrypt" name="mode" value="decrypt">
      <label for="modeDecrypt">Decrypt</label>
    </div>

    <label for="fileInput">Choose File to <span id="fileAction">Encrypt</span></label>
    <input type="file" id="fileInput" name="file" required accept="*/*">

    <label for="passwordInput">Enter Password</label>
    <input type="password" id="passwordInput" name="password" minlength="6" autocomplete="new-password" required aria-describedby="passwordHelp">

    <div class="toggle-password" tabindex="0" role="button" aria-pressed="false" aria-label="Toggle password visibility" id="togglePwd">Show Password</div>
    
    <div id="passwordHelp" style="font-size:0.85rem; color:#8a8abd; margin-bottom:16px;">
      Password should be at least 6 characters.
    </div>

    <button type="submit" id="submitBtn">Encrypt File</button>
  </form>
</main>

<script>
  const modeRadios = document.querySelectorAll('input[name="mode"]');
  const fileInput = document.getElementById('fileInput');
  const submitBtn = document.getElementById('submitBtn');
  const fileActionSpan = document.getElementById('fileAction');
  const togglePwd = document.getElementById('togglePwd');
  const passwordInput = document.getElementById('passwordInput');

  function updateFormForMode() {
    let mode = document.querySelector('input[name="mode"]:checked').value;
    fileActionSpan.textContent = mode === 'encrypt' ? 'Encrypt' : 'Decrypt';
    submitBtn.textContent = mode === 'encrypt' ? 'Encrypt File' : 'Decrypt File';

    // Change file input accept attribute for decrypt mode to .enc files ideally
    if (mode === 'decrypt') {
      fileInput.accept = ".enc";
    } else {
      fileInput.accept = "*/*";
    }
  }

  modeRadios.forEach(radio => {
    radio.addEventListener('change', updateFormForMode);
  });

  updateFormForMode();

  togglePwd.addEventListener('click', () => {
    if (passwordInput.type === "password") {
      passwordInput.type = "text";
      togglePwd.textContent = "Hide Password";
      togglePwd.setAttribute("aria-pressed", "true");
    } else {
      passwordInput.type = "password";
      togglePwd.textContent = "Show Password";
      togglePwd.setAttribute("aria-pressed", "false");
    }
  });
  
  togglePwd.addEventListener('keydown', (e) => {
    if(e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      togglePwd.click();
    }
  });
</script>

</body>
</html>
"""

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        mode = request.form.get("mode", "encrypt")
        password = request.form.get("password", "")
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(request.url)

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(request.url)

        filename = file.filename
        file_data = file.read()

        if mode == "encrypt":
            # Encrypt
            salt = os.urandom(16)
            key = derive_key(password, salt)
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(file_data) + encryptor.finalize()
            # Output file will contain salt + nonce + ciphertext + tag
            out_data = salt + nonce + ciphertext + encryptor.tag
            out_filename = filename + ".enc"
        else:
            # Decrypt
            if not filename.endswith(".enc"):
                flash("For decryption, please upload a file with .enc extension.", "error")
                return redirect(request.url)
            # Parse salt, nonce, ciphertext, tag from uploaded data
            if len(file_data) < 16 + 12 + 16:
                flash("Uploaded file is too small or corrupted.", "error")
                return redirect(request.url)
            salt = file_data[:16]
            nonce = file_data[16:28]
            tag = file_data[-16:]
            ciphertext = file_data[28:-16]

            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            except Exception:
                flash("Decryption failed. Incorrect password or corrupted file.", "error")
                return redirect(request.url)

            out_data = plaintext
            out_filename = filename[:-4]  # remove '.enc' extension

        # Serve the file for download via memory buffer
        return send_file(
            BytesIO(out_data),
            as_attachment=True,
            download_name=out_filename,
            mimetype="application/octet-stream"
        )

    return render_template_string(template)

if __name__ == "__main__":
    app.run(debug=True)

