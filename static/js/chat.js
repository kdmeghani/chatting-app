// Ultra-minimal version with guaranteed input box visibility
let socket;
let currentFriend = null;
let privateKey = null;

// Force input visible on every possible event
function forceInputVisible() {
    const inputContainer = document.getElementById('messageInputContainer');
    if (inputContainer) {
        inputContainer.style.cssText = 'display: flex !important; background: #202c33 !important; padding: 10px !important; border-top: 2px solid red !important; position: sticky !important; bottom: 0 !important; width: 100% !important; z-index: 9999 !important;';
        console.log('Input container forced visible with red border');
    } else {
        console.error('Input container missing!');
        // Try to recreate it
        const chatArea = document.querySelector('.app-container');
        if (chatArea) {
            const newInput = document.createElement('div');
            newInput.id = 'messageInputContainer';
            newInput.style.cssText = 'display: flex; background: #202c33; padding: 10px; border-top: 2px solid red;';
            newInput.innerHTML = `
                <textarea id="messageText" placeholder="Type a message" style="flex:1; background:#2a3942; border:none; border-radius:8px; padding:10px; color:white; margin-right:10px;"></textarea>
                <input type="file" id="photoInput" accept="image/*" style="display:none;">
                <button id="photoBtn" style="background:#28a745; border:none; border-radius:8px; padding:8px 12px; color:white; margin-right:5px;">📷</button>
                <button id="sendBtn" style="background:#007bff; border:none; border-radius:8px; padding:8px 12px; color:white;">Send</button>
            `;
            chatArea.appendChild(newInput);
            console.log('Recreated input container');
        }
    }
}

// Call forceInputVisible on every possible event
window.addEventListener('load', forceInputVisible);
window.addEventListener('resize', forceInputVisible);
document.addEventListener('DOMContentLoaded', forceInputVisible);
setInterval(forceInputVisible, 1000); // Keep checking every second

document.addEventListener('DOMContentLoaded', async () => {
    // Check login
    if (!sessionStorage.getItem('user_id')) {
        window.location.href = '/login';
        return;
    }

    // Decrypt key
    const password = prompt("Password:");
    if (!password) {
        alert('Password required');
        window.location.href = '/login';
        return;
    }

    try {
        await decryptPrivateKey(password);
    } catch (e) {
        alert('Wrong password');
        window.location.href = '/login';
        return;
    }

    // Socket connection
    socket = io();

    socket.on('new_message', async (data) => {
        if (data.friend_id == currentFriend?.id || data.friend_id == sessionStorage.getItem('user_id')) {
            const decrypted = await decryptMessage(data.encrypted_message, data.encrypted_key, data.iv);
            addMessage(decrypted, data.is_sent);
        }
    });

    socket.on('new_photo', async (data) => {
        if (data.friend_id == currentFriend?.id || data.friend_id == sessionStorage.getItem('user_id')) {
            const encryptedKey = Uint8Array.from(atob(data.encrypted_key), c => c.charCodeAt(0));
            const aesKeyBuffer = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedKey);
            const aesKey = await crypto.subtle.importKey("raw", aesKeyBuffer, { name: "AES-CBC" }, false, ["decrypt"]);
            
            const download = await fetch(`/download_photo/${data.encrypted_message}`);
            const encrypted = await download.arrayBuffer();
            const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv: iv }, aesKey, encrypted);
            
            const blob = new Blob([decrypted], { type: 'image/jpeg' });
            const url = URL.createObjectURL(blob);
            
            const msgDiv = document.createElement('div');
            msgDiv.className = `message ${data.is_sent ? 'sent' : 'received'}`;
            msgDiv.innerHTML = `<img src="${url}" style="max-width:200px; border-radius:8px;">`;
            document.getElementById('messages').appendChild(msgDiv);
        }
    });

    // Load friends
    await loadFriends();

    // Setup buttons
    document.getElementById('logoutBtn').onclick = () => {
        fetch('/logout', { method: 'POST' }).then(() => {
            sessionStorage.clear();
            window.location.href = '/login';
        });
    };

    document.getElementById('sendBtn').onclick = sendMessage;
    document.getElementById('photoBtn').onclick = () => document.getElementById('photoInput').click();
    document.getElementById('photoInput').onchange = handlePhotoSelected;
    document.getElementById('menuToggle').onclick = () => {
        document.getElementById('sidebar').style.left = '0';
        document.getElementById('sidebarOverlay').style.display = 'block';
    };
    document.getElementById('sidebarOverlay').onclick = () => {
        document.getElementById('sidebar').style.left = '-300px';
        document.getElementById('sidebarOverlay').style.display = 'none';
    };
});

// Add a message to the chat
function addMessage(text, isSent) {
    const msgDiv = document.createElement('div');
    msgDiv.style.cssText = `max-width: 70%; margin-bottom: 10px; padding: 8px 12px; border-radius: 8px; word-wrap: break-word; ${isSent ? 'align-self: flex-end; background: #005c4b;' : 'align-self: flex-start; background: #202c33;'}`;
    msgDiv.innerHTML = `${text}<div style="font-size: 11px; color: #8696a0; margin-top: 4px;">${new Date().toLocaleTimeString()}</div>`;
    document.getElementById('messages').appendChild(msgDiv);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

// Crypto functions
async function decryptPrivateKey(password) {
    const data = Uint8Array.from(atob(sessionStorage.getItem('encrypted_private_key')), c => c.charCodeAt(0));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const cipher = data.slice(28);
    
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
    const derived = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, derived, cipher);
    
    const pem = new TextDecoder().decode(decrypted);
    const buffer = Uint8Array.from(atob(pem), c => c.charCodeAt(0)).buffer;
    privateKey = await crypto.subtle.importKey("pkcs8", buffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

async function decryptMessage(encMsg, encKey, iv64) {
    const key = Uint8Array.from(atob(encKey), c => c.charCodeAt(0));
    const aesBuf = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, key);
    const aesKey = await crypto.subtle.importKey("raw", aesBuf, { name: "AES-CBC" }, false, ["decrypt"]);
    const iv = Uint8Array.from(atob(iv64), c => c.charCodeAt(0));
    const msg = Uint8Array.from(atob(encMsg), c => c.charCodeAt(0));
    const dec = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, msg);
    return new TextDecoder().decode(dec);
}

async function loadFriends() {
    const response = await fetch('/friends');
    const friends = await response.json();
    const list = document.getElementById('friendsList');
    list.innerHTML = '';
    friends.forEach(f => {
        const div = document.createElement('div');
        div.style.cssText = 'padding: 10px; border-bottom: 1px solid #2a3942; cursor: pointer; color: white;';
        div.innerText = f.username;
        div.onclick = () => selectFriend(f);
        list.appendChild(div);
    });
}

async function selectFriend(friend) {
    currentFriend = friend;
    document.getElementById('chatHeader').innerText = friend.username;
    document.getElementById('messageText').disabled = false;
    document.getElementById('photoBtn').disabled = false;
    document.getElementById('sendBtn').disabled = false;
    
    document.getElementById('sidebar').style.left = '-300px';
    document.getElementById('sidebarOverlay').style.display = 'none';
    
    document.getElementById('messages').innerHTML = '';
    
    const response = await fetch(`/messages/${friend.id}`);
    const messages = await response.json();
    for (const msg of messages) {
        if (msg.type === 'text') {
            const text = await decryptMessage(msg.encrypted_message, msg.encrypted_key, msg.iv);
            addMessage(text, msg.is_sent);
        }
    }
}

async function sendMessage() {
    if (!currentFriend) return;
    const text = document.getElementById('messageText').value.trim();
    if (!text) return;
    
    const aesKey = await crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, new TextEncoder().encode(text));
    const rawKey = await crypto.subtle.exportKey("raw", aesKey);
    
    const myPub = sessionStorage.getItem('public_key');
    const theirPub = await (await fetch(`/public_key/${currentFriend.id}`)).json().then(d => d.public_key);
    
    const myEncKey = await encryptRSA(rawKey, myPub);
    const theirEncKey = await encryptRSA(rawKey, theirPub);
    
    socket.emit('send_message', {
        recipient_id: currentFriend.id,
        encrypted_message: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        iv: btoa(String.fromCharCode(...iv)),
        encrypted_key_self: btoa(String.fromCharCode(...new Uint8Array(myEncKey))),
        encrypted_key_recipient: btoa(String.fromCharCode(...new Uint8Array(theirEncKey)))
    });
    
    addMessage(text, true);
    document.getElementById('messageText').value = '';
}

async function handlePhotoSelected(e) {
    const file = e.target.files[0];
    if (!file || !currentFriend) return;
    
    const data = await file.arrayBuffer();
    const aesKey = await crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, data);
    const rawKey = await crypto.subtle.exportKey("raw", aesKey);
    
    const myPub = sessionStorage.getItem('public_key');
    const theirPub = await (await fetch(`/public_key/${currentFriend.id}`)).json().then(d => d.public_key);
    
    const myEncKey = await encryptRSA(rawKey, myPub);
    const theirEncKey = await encryptRSA(rawKey, theirPub);
    
    const formData = new FormData();
    formData.append('recipient_id', currentFriend.id);
    formData.append('encrypted_key_self', btoa(String.fromCharCode(...new Uint8Array(myEncKey))));
    formData.append('encrypted_key_recipient', btoa(String.fromCharCode(...new Uint8Array(theirEncKey))));
    formData.append('iv', btoa(String.fromCharCode(...iv)));
    formData.append('filename', file.name);
    formData.append('file', new Blob([encrypted]));
    
    const upload = await fetch('/upload_photo', { method: 'POST', body: formData });
    const result = await upload.json();
    
    socket.emit('send_photo', {
        recipient_id: currentFriend.id,
        encrypted_message: result.file_id,
        iv: btoa(String.fromCharCode(...iv)),
        encrypted_key_self: btoa(String.fromCharCode(...new Uint8Array(myEncKey))),
        encrypted_key_recipient: btoa(String.fromCharCode(...new Uint8Array(theirEncKey))),
        file_name: file.name
    });
}

async function encryptRSA(key, pubPem) {
    const pem = pubPem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\s/g, '');
    const buf = Uint8Array.from(atob(pem), c => c.charCodeAt(0)).buffer;
    const pub = await crypto.subtle.importKey("spki", buf, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    return await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, key);
}
