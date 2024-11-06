from flask import Flask, render_template_string, request, jsonify
import secrets
import os
import json
import logging
from datetime import datetime, timedelta
import base64
from hashlib import sha256
from secrets import token_bytes

MAX_SECRET_LENGTH = 5000

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create secrets directory
SECRETS_DIR = "secrets"
if not os.path.exists(SECRETS_DIR):
    os.makedirs(SECRETS_DIR)


def get_encryption_key():
    key_file = os.path.join(SECRETS_DIR, '.encryption_key')
    if not os.path.exists(key_file):
        with open(key_file, 'wb') as f:
            f.write(token_bytes(32))
    with open(key_file, 'rb') as f:
        return f.read()


def secure_encrypt(text):
    key = get_encryption_key()
    text_bytes = text.encode()
    key_bytes = sha256(key).digest()
    # Extend key if needed
    key_bytes = (key_bytes * (len(text_bytes) // len(key_bytes) + 1))[:len(text_bytes)]
    # XOR with random prefix for added security
    prefix = token_bytes(16)
    encrypted = bytes(a ^ b for a, b in zip(text_bytes, key_bytes))
    return base64.b64encode(prefix + encrypted).decode()

def secure_decrypt(encrypted_text):
    key = get_encryption_key()
    key_bytes = sha256(key).digest()
    encrypted_bytes = base64.b64decode(encrypted_text.encode())
    # Remove prefix
    prefix = encrypted_bytes[:16]
    encrypted_bytes = encrypted_bytes[16:]
    # Extend key if needed
    key_bytes = (key_bytes * (len(encrypted_bytes) // len(key_bytes) + 1))[:len(encrypted_bytes)]
    decrypted = bytes(a ^ b for a, b in zip(encrypted_bytes, key_bytes))
    return decrypted.decode()
    
# Generate encryption key
# ENCRYPTION_KEY_FILE = os.path.join(SECRETS_DIR, '.encryption_key')
# if not os.path.exists(ENCRYPTION_KEY_FILE):
    # with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
        # key_file.write(Fernet.generate_key())

# Load the encryption key
# with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
    # encryption_key = key_file.read()
# fernet = Fernet(encryption_key)

# Encryption functions
# def secure_encrypt(text):
    # return fernet.encrypt(text.encode()).decode()

# def secure_decrypt(encrypted_text):
    # return fernet.decrypt(encrypted_text.encode()).decode()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Secret Sharing</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --primary-hover: #1d4ed8;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.5;
            padding: 1rem;
        }

        .container {
            max-width: 600px;
            margin: 2rem auto;
        }

        .card {
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            padding: 2rem;
        }

        h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--text-color);
        }

        .input-group {
            margin-bottom: 1.5rem;
        }

        textarea {
            width: 100%;
            min-height: 120px;
            padding: 0.75rem;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-family: inherit;
            font-size: 1rem;
            transition: border-color 0.15s ease;
            resize: vertical;
        }

        textarea:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .controls {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        select {
            padding: 0.5rem;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            font-size: 0.875rem;
            min-width: 120px;
            cursor: pointer;
        }

        button {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.15s ease;
        }

        button:hover {
            background-color: var(--primary-hover);
        }

        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .result {
            display: none;
            background-color: var(--bg-color);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1.5rem;
        }

        .result.show {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        .link {
            margin-top: 0.5rem;
            padding: 0.75rem;
            background: white;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            word-break: break-all;
            font-family: monospace;
        }

        .copy-btn {
            margin-top: 1rem;
            background-color: white;
            color: var(--primary-color);
            border: 2px solid var(--primary-color);
        }

        .copy-btn:hover {
            background-color: var(--bg-color);
        }

        .loading {
            display: none;
            align-items: center;
            gap: 0.5rem;
            margin-top: 1rem;
        }

        .loading.show {
            display: flex;
        }

        .spinner {
            width: 20px;
            height: 20px;
            border: 3px solid var(--bg-color);
            border-top: 3px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .error {
            color: #dc2626;
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }

        @media (max-width: 640px) {
            .container {
                margin: 1rem auto;
            }
            
            .card {
                padding: 1.5rem;
            }

            .controls {
                flex-direction: column;
            }

            select, button {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Share a Secret Securely</h1>
            <div class="input-group">
                <textarea 
                    id="secret" 
                    placeholder="Enter your secret message here..."
                    maxlength="5000"
                    aria-label="Secret message"
                    onkeyup="updateCharCount()"
                ></textarea>
                <div id="charCount">0/5000 characters</div>
                <div id="error" class="error"></div>
            </div>
            <div class="controls">
                <select id="expireTime" aria-label="Expiration time">
                    <option value="300">5 minutes</option>
                    <option value="3600">1 hour</option>
                    <option value="86400">24 hours</option>
                </select>
                <button onclick="createSecret()" id="createBtn">Create Secret Link</button>
            </div>
            <div id="loading" class="loading">
                <div class="spinner"></div>
                <span>Creating secure link...</span>
            </div>
            <div id="result" class="result">
                <strong>Share this link (works only once):</strong>
                <div id="secretLink" class="link"></div>
                <button onclick="copyToClipboard()" class="copy-btn">
                    Copy Link
                </button>
            </div>
        </div>
    </div>

    <script>
    
        function updateCharCount() {
        const textarea = document.getElementById('secret');
        const charCount = document.getElementById('charCount');
        const maxLength = 5000;
        const remaining = maxLength - textarea.value.length;
        charCount.textContent = `${textarea.value.length}/${maxLength} characters`;
        
            // Change color when nearing limit
            if (textarea.value.length > maxLength * 0.9) {
                charCount.style.color = '#dc2626'; // Red
            } else {
                charCount.style.color = '#1e293b'; // Normal color
            }
        }
        const createBtn = document.getElementById('createBtn');
        const loading = document.getElementById('loading');
        const result = document.getElementById('result');
        const error = document.getElementById('error');

        async function createSecret() {
            const secret = document.getElementById('secret').value.trim();
            error.textContent = '';
            
            if (!secret) {
                error.textContent = 'Please enter a secret message';
                return;
            }

            if (secret.length > 5000) {
                error.textContent = 'Secret must be less than 5000 characters';
                return;
            }

            try {
                createBtn.disabled = true;
                loading.classList.add('show');
                result.classList.remove('show');
                
                const expireTime = document.getElementById('expireTime').value;
                
                const response = await fetch('/create', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        secret: secret,
                        expire_seconds: parseInt(expireTime)
                    }),
                });
                
                if (!response.ok) {
                    throw new Error('Failed to create secret');
                }

                const data = await response.json();
                const link = window.location.origin + '/view/' + data.token;
                
                document.getElementById('secretLink').textContent = link;
                result.classList.add('show');
            } catch (err) {
                error.textContent = 'Failed to create secret. Please try again.';
                console.error(err);
            } finally {
                createBtn.disabled = false;
                loading.classList.remove('show');
            }
        }

        async function copyToClipboard() {
            const link = document.getElementById('secretLink').textContent;
            try {
                await navigator.clipboard.writeText(link);
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        }

        // Enable create button when user starts typing
        document.getElementById('secret').addEventListener('input', function() {
            createBtn.disabled = false;
            error.textContent = '';
        });
        
    </script>
</body>
</html>
'''

VIEW_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Secret</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --primary-hover: #1d4ed8;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.5;
            padding: 1rem;
        }

        .container {
            max-width: 600px;
            margin: 2rem auto;
        }

        .card {
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            padding: 2rem;
        }

        h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--text-color);
        }

        .secret-content {
            background-color: var(--bg-color);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            white-space: pre-wrap;
            word-break: break-word;
        }

        button {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.15s ease;
        }

        button:hover {
            background-color: var(--primary-hover);
        }

        .warning {
            font-size: 0.875rem;
            color: #dc2626;
            margin-top: 1rem;
        }

        @media (max-width: 640px) {
            .container {
                margin: 1rem auto;
            }
            
            .card {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Secret Message</h1>
            <div class="secret-content">{{ secret }}</div>
            <button onclick="copyToClipboard()">Copy Message</button>
            <div class="warning">
                Note: This message will be destroyed after you leave this page.
            </div>
        </div>
    </div>

    <script>
        async function copyToClipboard() {
            const text = document.querySelector('.secret-content').textContent;
            try {
                await navigator.clipboard.writeText(text);
                const btn = event.target;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = 'Copy Message';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/create', methods=['POST'])
def create_secret():
    try:
        data = request.get_json()
        secret = data.get('secret', '').strip()
        
        # Check length
        if len(secret) > MAX_SECRET_LENGTH:
            return jsonify({
                'error': f'Secret must be less than {MAX_SECRET_LENGTH} characters'
            }), 400
            
        if not secret:
            return jsonify({'error': 'No secret provided'}), 400
            
        expire_seconds = data.get('expire_seconds', 3600)        

        token = secrets.token_urlsafe(16)
        encrypted_secret = secure_encrypt(secret)
        
        secret_data = {
            'secret': encrypted_secret,
            'expires_at': (datetime.now() + timedelta(seconds=expire_seconds)).timestamp()
        }
        
        with open(os.path.join(SECRETS_DIR, f"{token}.json"), 'w') as f:
            json.dump(secret_data, f)
        
        logging.info(f'Secret created with token: {token}')
        return jsonify({'token': token})

    except Exception as e:
        logging.error(f'Error creating secret: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/view/<token>')
def view_secret(token):
    file_path = os.path.join(SECRETS_DIR, f"{token}.json")
    
    try:
        # Read and delete the secret file
        with open(file_path, 'r') as f:
            data = json.load(f)
        os.remove(file_path)
        
        # Check if expired
        if datetime.now().timestamp() > data['expires_at']:
            logging.info(f'Expired secret accessed: {token}')
            return render_template_string('''
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Secret Expired</title>
                    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
                    <style>
                        body {
                            font-family: 'Inter', sans-serif;
                            background-color: #f8fafc;
                            color: #1e293b;
                            line-height: 1.5;
                            padding: 1rem;
                        }
                        .container {
                            max-width: 600px;
                            margin: 2rem auto;
                        }
                        .card {
                            background: white;
                            border-radius: 12px;
                            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
                            padding: 2rem;
                            text-align: center;
                        }
                        .error-message {
                            color: #dc2626;
                            font-size: 1.1rem;
                            margin-bottom: 1rem;
                        }
                        .home-link {
                            color: #2563eb;
                            text-decoration: none;
                        }
                        .home-link:hover {
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="card">
                            <div class="error-message">This secret has expired</div>
                            <a href="/" class="home-link">Create a new secret</a>
                        </div>
                    </div>
                </body>
                </html>
            '''), 404
        
        # Decrypt secret
        decrypted_secret = secure_decrypt(data['secret'])
        logging.info(f'Secret viewed successfully: {token}')
        return render_template_string(VIEW_TEMPLATE, secret=decrypted_secret)
        
    except FileNotFoundError:
        logging.info(f'Attempted to view non-existent secret: {token}')
        return render_template_string('''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Secret Not Found</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
                <style>
                    body {
                        font-family: 'Inter', sans-serif;
                        background-color: #f8fafc;
                        color: #1e293b;
                        line-height: 1.5;
                        padding: 1rem;
                    }
                    .container {
                        max-width: 600px;
                        margin: 2rem auto;
                    }
                    .card {
                        background: white;
                        border-radius: 12px;
                        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
                        padding: 2rem;
                        text-align: center;
                    }
                    .error-message {
                        color: #dc2626;
                        font-size: 1.1rem;
                        margin-bottom: 1rem;
                    }
                    .home-link {
                        color: #2563eb;
                        text-decoration: none;
                    }
                    .home-link:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="card">
                        <div class="error-message">Secret not found or already viewed</div>
                        <a href="/" class="home-link">Create a new secret</a>
                    </div>
                </div>
            </body>
            </html>
        '''), 404
        
    except Exception as e:
        logging.error(f'Error viewing secret: {str(e)}')
        return render_template_string('''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
                <style>
                    body {
                        font-family: 'Inter', sans-serif;
                        background-color: #f8fafc;
                        color: #1e293b;
                        line-height: 1.5;
                        padding: 1rem;
                    }
                    .container {
                        max-width: 600px;
                        margin: 2rem auto;
                    }
                    .card {
                        background: white;
                        border-radius: 12px;
                        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
                        padding: 2rem;
                        text-align: center;
                    }
                    .error-message {
                        color: #dc2626;
                        font-size: 1.1rem;
                        margin-bottom: 1rem;
                    }
                    .home-link {
                        color: #2563eb;
                        text-decoration: none;
                    }
                    .home-link:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="card">
                        <div class="error-message">An error occurred</div>
                        <a href="/" class="home-link">Try creating a new secret</a>
                    </div>
                </div>
            </body>
            </html>
        '''), 500
        
# Error handling for production
@app.errorhandler(404)
def not_found_error(error):
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Page Not Found</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Inter', sans-serif;
                    background-color: #f8fafc;
                    color: #1e293b;
                    line-height: 1.5;
                    padding: 1rem;
                }
                .container {
                    max-width: 600px;
                    margin: 2rem auto;
                }
                .card {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
                    padding: 2rem;
                    text-align: center;
                }
                .error-message {
                    color: #dc2626;
                    font-size: 1.1rem;
                    margin-bottom: 1rem;
                }
                .home-link {
                    color: #2563eb;
                    text-decoration: none;
                }
                .home-link:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="error-message">Page not found</div>
                    <a href="/" class="home-link">Go to homepage</a>
                </div>
            </div>
        </body>
        </html>
    '''), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Server Error</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Inter', sans-serif;
                    background-color: #f8fafc;
                    color: #1e293b;
                    line-height: 1.5;
                    padding: 1rem;
                }
                .container {
                    max-width: 600px;
                    margin: 2rem auto;
                }
                .card {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
                    padding: 2rem;
                    text-align: center;
                }
                .error-message {
                    color: #dc2626;
                    font-size: 1.1rem;
                    margin-bottom: 1rem;
                }
                .home-link {
                    color: #2563eb;
                    text-decoration: none;
                }
                .home-link:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="error-message">An unexpected error occurred</div>
                    <a href="/" class="home-link">Go to homepage</a>
                </div>
            </div>
        </body>
        </html>
    '''), 500

# Production configuration
if __name__ == '__main__':
    # For development
    app.run(debug=True)
else:
    # For production
    app.debug = False     