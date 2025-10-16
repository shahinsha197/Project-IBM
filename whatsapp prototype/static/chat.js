// static/chat.js

// --- Configuration ---
let SENDER_NAME = "User1"; // Default sender
let RECIPIENT_NAME = "User2"; // Default recipient
let RECIPIENT_KEY = "TheirSecretKey67890"; // Default recipient key

// --- Helper Functions ---
function detectUser() {
    const userKey = document.getElementById('user-key').value;
    if (userKey === "MySecretKey12345") {
        SENDER_NAME = "User1";
        RECIPIENT_NAME = "User2";
        RECIPIENT_KEY = "TheirSecretKey67890";
        document.getElementById('current-user').textContent = "User1";
    } else if (userKey === "TheirSecretKey67890") {
        SENDER_NAME = "User2";
        RECIPIENT_NAME = "User1";
        RECIPIENT_KEY = "MySecretKey12345";
        document.getElementById('current-user').textContent = "User2";
    } else {
        document.getElementById('current-user').textContent = "Unknown";
    }
}

function displayMessage(text, isSent) {
    const chatBox = document.getElementById('chat-box');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message ' + (isSent ? 'sent' : 'received');
    messageDiv.innerText = text;
    chatBox.appendChild(messageDiv);
    chatBox.scrollTop = chatBox.scrollHeight; // Auto-scroll
}

function sendMessage() {
    const inputField = document.getElementById('message-input');
    const userKeyField = document.getElementById('user-key');
    const plaintext = inputField.value.trim();
    
    if (!plaintext) {
        alert("Please enter a message.");
        return;
    }
    
    // Detect current user based on key
    detectUser();
    
    const userKey = userKeyField.value;

    // Display the message as "sending" (encrypted)
    displayMessage(`(Encrypted) ${plaintext}`, true);
    inputField.value = ''; // Clear input

    // Send the message to the server for storage
    $.ajax({
        url: '/send_message',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            sender: SENDER_NAME,
            recipient: RECIPIENT_NAME,
            plaintext: plaintext,
            recipient_key: RECIPIENT_KEY // Key to encrypt for recipient
        }),
        success: function(response) {
            console.log("Server response:", response);
        },
        error: function(xhr, status, error) {
            console.error("Send error:", error);
            displayMessage("[Failed to send]", true);
        }
    });
}

let lastMessageCount = 0;

function fetchAndDecryptMessages() {
    const userKey = document.getElementById('user-key').value;
    
    // Detect current user based on key
    detectUser();

    $.get('/get_messages', function(data) {
        // Filter messages for the current user
        const userMessages = data.filter(msg => msg.recipient === SENDER_NAME);
        
        // Only process new messages
        if (userMessages.length > lastMessageCount) {
            const newMessages = userMessages.slice(lastMessageCount);
            
            newMessages.forEach(function(msg) {
                // Decrypt each message
                $.ajax({
                    url: '/decrypt_message',
                    type: 'POST',
                    async: false, // For simplicity in prototype
                    contentType: 'application/json',
                    data: JSON.stringify({
                        salt: msg.salt,
                        nonce: msg.nonce,
                        ciphertext: msg.ciphertext,
                        user_key: userKey
                    }),
                    success: function(decryptResponse) {
                        displayMessage(`${msg.sender}: ${decryptResponse.plaintext}`, false);
                    },
                    error: function(xhr, status, error) {
                        console.error("Decrypt error for message:", error);
                        displayMessage(`${msg.sender}: [Decryption Failed]`, false);
                    }
                });
            });
            
            lastMessageCount = userMessages.length;
        }
    }).fail(function() {
        console.error("Failed to fetch messages.");
    });
}

// --- Initialization ---
$(document).ready(function() {
    // Update user info on key change
    document.getElementById('user-key').addEventListener('input', function() {
        detectUser();
    });
    
    // Set initial user info
    detectUser();
    
    // Fetch and display messages every 2 seconds
    setInterval(fetchAndDecryptMessages, 2000);
    fetchAndDecryptMessages(); // Initial fetch
});

// Allow sending with Enter key
document.getElementById('message-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});