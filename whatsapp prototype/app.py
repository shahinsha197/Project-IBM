# app.py
from flask import Flask, render_template, request, jsonify
import json
from crypto_utils import encrypt_message_for_web, decrypt_message_from_web

app = Flask(__name__)

# --- In-Memory Storage (for prototype) ---
# In a real app, use a database.
messages = []  # List of message dictionaries

# --- Routes ---
@app.route('/')
def index():
    # Serve the main chat page
    return render_template('index.html')

@app.route('/send_message', methods=['POST'])
def send_message():
    """Endpoint to send and store an encrypted message."""
    data = request.json
    sender = data.get('sender', 'Anonymous')
    recipient = data.get('recipient', 'User2')  # Default recipient for prototype
    plaintext = data.get('plaintext', '')
    recipient_key = data.get('recipient_key', '')  # Pre-shared key for recipient

    if not plaintext or not recipient_key:
        return jsonify({"error": "Missing plaintext or recipient key"}), 400

    try:
        # Encrypt the message for the recipient
        encrypted_components = encrypt_message_for_web(plaintext, recipient_key)
        
        # Store the encrypted message
        message_record = {
            "sender": sender,
            "recipient": recipient,
            "salt": encrypted_components["salt"],
            "nonce": encrypted_components["nonce"],
            "ciphertext": encrypted_components["ciphertext"]
        }
        messages.append(message_record)
        
        return jsonify({"status": "Message sent and stored (encrypted)"}), 200
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {e}"}), 500

@app.route('/get_messages', methods=['GET'])
def get_messages():
    """Endpoint to fetch all stored messages."""
    # In a real app, filter by recipient.
    return jsonify(messages), 200

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    """Endpoint to decrypt a single message."""
    data = request.json
    salt_b64 = data.get('salt', '')
    nonce_b64 = data.get('nonce', '')
    ciphertext_b64 = data.get('ciphertext', '')
    user_key = data.get('user_key', '')  # User's secret key

    if not all([salt_b64, nonce_b64, ciphertext_b64, user_key]):
        return jsonify({"error": "Missing decryption components or user key"}), 400

    try:
        decrypted_text = decrypt_message_from_web(salt_b64, nonce_b64, ciphertext_b64, user_key)
        return jsonify({"plaintext": decrypted_text}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')  # Allow external access