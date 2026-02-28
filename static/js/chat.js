// Global variables
let socket;
let currentFriend = null;
let privateKey = null;
let friends = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    // Check if user is logged in
    const userId = sessionStorage.getItem('user_id');
    if (!userId) {
        window.location.href = '/login';
        return;
    }

    // Decrypt private key using password
    const password = prompt("Enter your password to decrypt messages:"); // In production, use a proper password input
    if (!password) {
        alert('Password required');
        window.location.href = '/login';
        return;
    }

    try {
        await decryptPrivateKey(password);
        console.log('Private key decrypted successfully');
    } catch (e) {
        console.error('Failed to decrypt private key:', e);
        alert('Failed to decrypt private key. Wrong password?');
        window.location.href = '/login';
        return;
    }

    // Connect to Socket.IO
    socket = io();

    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('new_message', async (data) => {
        if (data.friend_id === currentFriend?.id || data.friend_id == sessionStorage.getItem('user_id')) {
            try {
                if (data.type === 'text') {
                    const decrypted = await decryptMessage(data.encrypted_message, data.encrypted_key, data.iv);
                    displayMessage({
                        text: decrypted,
                        isSent: data.is_sent,
                        timestamp: new Date().toLocaleTimeString()
                    });
                }
            } catch (e) {
                console.error('Decryption failed', e);
            }
        }
    });

    socket.on('new_photo', async (data) => {
        if (data.friend_id === currentFriend?.id || data.friend_id == sessionStorage.getItem('user_id')) {
            await processPhotoMessage(data);
        }
    });

    socket.on('typing_indicator', (data) => {
        if (data.user_id === currentFriend?.id) {
            document.getElementById('typingIndicator').innerText = data.is_typing ? `${currentFriend.username} is typing...` : '';
        }
    });

    // Load friends
    await loadFriends();

    // Setup event listeners
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('searchInput').addEventListener('input', searchUsers);
    document.getElementById('sendBtn').addEventListener('click', sendMessage);
    document.getElementById('messageText').addEventListener('input', handleTyping);
    document.getElementById('photoBtn').addEventListener('click', () => {
        document.getElementById('photoInput').click();
    });
    document.getElementById('photoInput').addEventListener('change', handlePhotoSelected);
});

async function decryptPrivateKey(password) {
    const encryptedPrivateKeyBase64 = sessionStorage.getItem('encrypted_private_key');
    const encryptedPrivateKeyData = Uint8Array.from(atob(encryptedPrivateKeyBase64), c => c.charCodeAt(0));

    const salt = encryptedPrivateKeyData.slice(0, 16);
    const iv = encryptedPrivateKeyData.slice(16, 28);
    const ciphertext = encryptedPrivateKeyData.slice(28);

    const passwordKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt"]
    );

    const decryptedPrivateKeyBase64 = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        derivedKey,
        ciphertext
    );

    const privateKeyPem = new TextDecoder().decode(decryptedPrivateKeyBase64);
    const privateKeyBuffer = Uint8Array.from(atob(privateKeyPem), c => c.charCodeAt(0)).buffer;
    privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBuffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["decrypt"]
    );
}

async function loadFriends() {
    const response = await fetch('/friends');
    friends = await response.json();
    const friendsList = document.getElementById('friendsList');
    friendsList.innerHTML = '';
    friends.forEach(friend => {
        const div = document.createElement('div');
        div.className = 'friend-item';
        div.dataset.id = friend.id;
        div.innerHTML = `
            <span>
                <span class="online-status ${friend.online ? '' : 'offline'}"></span>
                ${friend.username}
            </span>
        `;
        div.addEventListener('click', () => selectFriend(friend));
        friendsList.appendChild(div);
    });
}

async function selectFriend(friend) {
    currentFriend = friend;
    document.getElementById('chatHeader').innerText = `Chat with ${friend.username}`;
    document.getElementById('messageInputContainer').style.display = 'flex';
    document.getElementById('messages').innerHTML = '';

    document.querySelectorAll('.friend-item').forEach(el => el.classList.remove('selected'));
    document.querySelector(`.friend-item[data-id="${friend.id}"]`).classList.add('selected');

    const response = await fetch(`/messages/${friend.id}`);
    const messages = await response.json();
    for (const msg of messages) {
        try {
            if (msg.type === 'text') {
                const decrypted = await decryptMessage(msg.encrypted_message, msg.encrypted_key, msg.iv);
                displayMessage({
                    text: decrypted,
                    isSent: msg.is_sent,
                    timestamp: new Date(msg.timestamp).toLocaleTimeString()
                });
            } else if (msg.type === 'photo') {
                await processPhotoMessage(msg);
            }
        } catch (e) {
            console.error('Failed to decrypt message', e);
        }
    }
}

async function decryptMessage(encryptedMessageBase64, encryptedKeyBase64, ivBase64) {
    const encryptedKey = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));
    const aesKeyBuffer = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKey
    );

    const aesKey = await crypto.subtle.importKey(
        "raw",
        aesKeyBuffer,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );

    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const encryptedMessage = Uint8Array.from(atob(encryptedMessageBase64), c => c.charCodeAt(0));
    const decryptedMessage = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        aesKey,
        encryptedMessage
    );

    return new TextDecoder().decode(decryptedMessage);
}

async function processPhotoMessage(data) {
    try {
        const encryptedKey = Uint8Array.from(atob(data.encrypted_key), c => c.charCodeAt(0));
        const aesKeyBuffer = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedKey
        );
        const aesKey = await crypto.subtle.importKey(
            "raw",
            aesKeyBuffer,
            { name: "AES-CBC" },
            false,
            ["decrypt"]
        );

        const downloadResponse = await fetch(`/download_photo/${data.file_id}`);
        if (!downloadResponse.ok) throw new Error('Download failed');
        const encryptedFileData = await downloadResponse.arrayBuffer();

        const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
        const decryptedFileData = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            aesKey,
            encryptedFileData
        );

        const blob = new Blob([decryptedFileData], { type: 'image/jpeg' });
        const url = URL.createObjectURL(blob);

        displayPhoto({
            url: url,
            fileName: data.file_name,
            isSent: data.is_sent,
            timestamp: new Date().toLocaleTimeString()
        });
    } catch (e) {
        console.error('Failed to process photo:', e);
    }
}

function displayMessage(msg) {
    const messagesDiv = document.getElementById('messages');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${msg.isSent ? 'sent' : 'received'}`;
    msgDiv.innerHTML = `
        <div>${msg.text}</div>
        <div class="message-time">${msg.timestamp}</div>
    `;
    messagesDiv.appendChild(msgDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function displayPhoto(photo) {
    const messagesDiv = document.getElementById('messages');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${photo.isSent ? 'sent' : 'received'}`;
    msgDiv.innerHTML = `
        <img src="${photo.url}" alt="Photo" style="max-width: 200px; max-height: 200px; border-radius: 8px;" onclick="window.open(this.src)">
        <div class="message-time">${photo.timestamp}</div>
    `;
    messagesDiv.appendChild(msgDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

async function sendMessage() {
    if (!currentFriend) return;
    const text = document.getElementById('messageText').value.trim();
    if (!text) return;

    try {
        const aesKey = await crypto.subtle.generateKey(
            { name: "AES-CBC", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(16));

        const encodedMessage = new TextEncoder().encode(text);
        const encryptedMessage = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            aesKey,
            encodedMessage
        );

        const aesKeyRaw = await crypto.subtle.exportKey("raw", aesKey);

        const publicKeyPem = sessionStorage.getItem('public_key');
        const recipientPublicKeyPem = await getPublicKeyForUser(currentFriend.id);

        const encryptedKeySelf = await encryptAesKeyWithRsa(aesKeyRaw, publicKeyPem);
        const encryptedKeyRecipient = await encryptAesKeyWithRsa(aesKeyRaw, recipientPublicKeyPem);

        socket.emit('send_message', {
            recipient_id: currentFriend.id,
            encrypted_message: btoa(String.fromCharCode(...new Uint8Array(encryptedMessage))),
            iv: btoa(String.fromCharCode(...iv)),
            encrypted_key_self: btoa(String.fromCharCode(...new Uint8Array(encryptedKeySelf))),
            encrypted_key_recipient: btoa(String.fromCharCode(...new Uint8Array(encryptedKeyRecipient)))
        });

        document.getElementById('messageText').value = '';
    } catch (e) {
        console.error('Error sending message:', e);
        alert('Failed to send message. Check console for details.');
    }
}

async function handlePhotoSelected(event) {
    const file = event.target.files[0];
    if (!file || !currentFriend) return;

    try {
        const fileData = await file.arrayBuffer();

        const aesKey = await crypto.subtle.generateKey(
            { name: "AES-CBC", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(16));

        const encryptedFile = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            aesKey,
            fileData
        );

        const aesKeyRaw = await crypto.subtle.exportKey("raw", aesKey);

        const publicKeyPem = sessionStorage.getItem('public_key');
        const recipientPublicKeyPem = await getPublicKeyForUser(currentFriend.id);

        const encryptedKeySelf = await encryptAesKeyWithRsa(aesKeyRaw, publicKeyPem);
        const encryptedKeyRecipient = await encryptAesKeyWithRsa(aesKeyRaw, recipientPublicKeyPem);

        const formData = new FormData();
        formData.append('recipient_id', currentFriend.id);
        formData.append('encrypted_key_self', btoa(String.fromCharCode(...new Uint8Array(encryptedKeySelf))));
        formData.append('encrypted_key_recipient', btoa(String.fromCharCode(...new Uint8Array(encryptedKeyRecipient))));
        formData.append('iv', btoa(String.fromCharCode(...iv)));
        formData.append('filename', file.name);
        formData.append('file', new Blob([encryptedFile]));

        const uploadResponse = await fetch('/upload_photo', { method: 'POST', body: formData });
        if (!uploadResponse.ok) throw new Error('Upload failed');
        const uploadResult = await uploadResponse.json();

        socket.emit('send_photo', {
            recipient_id: currentFriend.id,
            file_id: uploadResult.file_id,
            iv: btoa(String.fromCharCode(...iv)),
            encrypted_key_self: btoa(String.fromCharCode(...new Uint8Array(encryptedKeySelf))),
            encrypted_key_recipient: btoa(String.fromCharCode(...new Uint8Array(encryptedKeyRecipient))),
            file_name: file.name
        });

        document.getElementById('photoInput').value = '';
    } catch (e) {
        console.error('Error sending photo:', e);
        alert('Failed to send photo');
    }
}

async function encryptAesKeyWithRsa(aesKeyRaw, publicKeyPem) {
    function pemToArrayBuffer(pem) {
        const header = "-----BEGIN PUBLIC KEY-----";
        const footer = "-----END PUBLIC KEY-----";
        const start = pem.indexOf(header) + header.length;
        const end = pem.indexOf(footer, start);
        let pemContents = pem.substring(start, end);
        pemContents = pemContents.replace(/\s/g, '');
        const binaryString = atob(pemContents);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    try {
        const publicKeyBuffer = pemToArrayBuffer(publicKeyPem);
        const publicKey = await crypto.subtle.importKey(
            "spki",
            publicKeyBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            false,
            ["encrypt"]
        );

        return await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            aesKeyRaw
        );
    } catch (e) {
        console.error('RSA encryption failed:', e);
        throw e;
    }
}

async function getPublicKeyForUser(userId) {
    const response = await fetch(`/public_key/${userId}`);
    if (!response.ok) {
        throw new Error(`Failed to fetch public key: ${response.status}`);
    }
    const data = await response.json();
    return data.public_key;
}

function handleTyping() {
    if (!currentFriend) return;
    const isTyping = document.getElementById('messageText').value.length > 0;
    socket.emit('typing', {
        friend_id: currentFriend.id,
        is_typing: isTyping
    });
}

async function searchUsers() {
    const query = document.getElementById('searchInput').value;
    if (query.length < 1) {
        document.getElementById('searchResults').innerHTML = '';
        return;
    }
    const response = await fetch(`/search?q=${encodeURIComponent(query)}`);
    const users = await response.json();
    const resultsDiv = document.getElementById('searchResults');
    resultsDiv.innerHTML = '';
    users.forEach(user => {
        const div = document.createElement('div');
        div.className = 'search-result-item';
        div.innerText = user.username;
        div.addEventListener('click', () => sendFriendRequest(user.id));
        resultsDiv.appendChild(div);
    });
}

async function sendFriendRequest(recipientId) {
    await fetch('/send_request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: recipientId })
    });
    alert('Friend request sent');
    document.getElementById('searchResults').innerHTML = '';
    document.getElementById('searchInput').value = '';
}

function logout() {
    fetch('/logout', { method: 'POST' }).then(() => {
        sessionStorage.clear();
        window.location.href = '/login';
    });
}