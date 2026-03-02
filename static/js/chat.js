// Ultra-simple chat.js
let socket;
let currentFriend = null;
let privateKey = null;

document.addEventListener('DOMContentLoaded', async () => {
    if (!sessionStorage.getItem('user_id')) {
        window.location.href = '/login';
        return;
    }

    const password = prompt("Enter your password:");
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

    socket = io();

    socket.on('new_message', async (data) => {
        if (data.friend_id == currentFriend?.id || data.friend_id == sessionStorage.getItem('user_id')) {
            const text = await decryptMessage(data.encrypted_message, data.encrypted_key, data.iv);
            addMessage(text, data.is_sent);
        }
    });

    socket.on('new_photo', async (data) => {
        if (data.friend_id == currentFriend?.id || data.friend_id == sessionStorage.getItem('user_id')) {
            const key = Uint8Array.from(atob(data.encrypted_key), c => c.charCodeAt(0));
            const aesBuf = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, key);
            const aesKey = await crypto.subtle.importKey("raw", aesBuf, { name: "AES-CBC" }, false, ["decrypt"]);
            
            const resp = await fetch(`/download_photo/${data.encrypted_message}`);
            const enc = await resp.arrayBuffer();
            const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
            const dec = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, enc);
            
            const blob = new Blob([dec], { type: 'image/jpeg' });
            const url = URL.createObjectURL(blob);
            
            const msgDiv = document.createElement('div');
            msgDiv.className = `message ${data.is_sent ? 'sent' : 'received'}`;
            msgDiv.innerHTML = `<img src="${url}" style="max-width:200px; border-radius:8px;">`;
            document.getElementById('messages').appendChild(msgDiv);
            document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
        }
    });

    await loadFriends();

    // Enable/disable input based on friend selection
    document.getElementById('messageText').disabled = true;
    document.getElementById('photoBtn').disabled = true;
    document.getElementById('sendBtn').disabled = true;

    // Event listeners
    document.getElementById('sendBtn').onclick = sendMessage;
    document.getElementById('photoBtn').onclick = () => document.getElementById('photoInput').click();
    document.getElementById('photoInput').onchange = handlePhotoSelected;
    document.getElementById('logoutBtn').onclick = logout;
    document.getElementById('menuToggle').onclick = () => {
        document.getElementById('sidebar').classList.add('open');
        document.getElementById('sidebarOverlay').classList.add('active');
    };
    document.getElementById('sidebarOverlay').onclick = () => {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebarOverlay').classList.remove('active');
    };
    document.getElementById('searchInput').addEventListener('input', searchUsers);
});

// Core functions
async function decryptPrivateKey(password) {
    const data = Uint8Array.from(atob(sessionStorage.getItem('encrypted_private_key')), c => c.charCodeAt(0));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const cipher = data.slice(28);
    
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
    const derived = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
    const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, derived, cipher);
    
    const pem = new TextDecoder().decode(dec);
    const buf = Uint8Array.from(atob(pem), c => c.charCodeAt(0)).buffer;
    privateKey = await crypto.subtle.importKey("pkcs8", buf, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
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

async function encryptRSA(key, pubPem) {
    const pem = pubPem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\s/g, '');
    const buf = Uint8Array.from(atob(pem), c => c.charCodeAt(0)).buffer;
    const pub = await crypto.subtle.importKey("spki", buf, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    return await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, key);
}

async function loadFriends() {
    const resp = await fetch('/friends');
    const friends = await resp.json();
    const list = document.getElementById('friendsList');
    list.innerHTML = '';
    friends.forEach(f => {
        const div = document.createElement('div');
        div.style.cssText = 'padding:10px; border-bottom:1px solid #2a3942; cursor:pointer; color:white;';
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
    
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('active');
    
    document.getElementById('messages').innerHTML = '';
    
    const resp = await fetch(`/messages/${friend.id}`);
    const msgs = await resp.json();
    for (const msg of msgs) {
        if (msg.type === 'text') {
            const text = await decryptMessage(msg.encrypted_message, msg.encrypted_key, msg.iv);
            addMessage(text, msg.is_sent);
        } else {
            // handle photo – simplified, can add later
        }
    }
}

function addMessage(text, isSent) {
    const div = document.createElement('div');
    div.className = `message ${isSent ? 'sent' : 'received'}`;
    div.innerHTML = `${text}<div style="font-size:11px; color:#8696a0; margin-top:4px;">${new Date().toLocaleTimeString()}</div>`;
    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

async function sendMessage() {
    if (!currentFriend) return;
    const text = document.getElementById('messageText').value.trim();
    if (!text) return;
    
    const aesKey = await crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const enc = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, new TextEncoder().encode(text));
    const raw = await crypto.subtle.exportKey("raw", aesKey);
    
    const myPub = sessionStorage.getItem('public_key');
    const theirPub = await (await fetch(`/public_key/${currentFriend.id}`)).json().then(d => d.public_key);
    
    const myKey = await encryptRSA(raw, myPub);
    const theirKey = await encryptRSA(raw, theirPub);
    
    socket.emit('send_message', {
        recipient_id: currentFriend.id,
        encrypted_message: btoa(String.fromCharCode(...new Uint8Array(enc))),
        iv: btoa(String.fromCharCode(...iv)),
        encrypted_key_self: btoa(String.fromCharCode(...new Uint8Array(myKey))),
        encrypted_key_recipient: btoa(String.fromCharCode(...new Uint8Array(theirKey)))
    });
    
    addMessage(text, true);
    document.getElementById('messageText').value = '';
}

async function handlePhotoSelected(e) {
    // Simplified photo sending – omitted for brevity but can be added
    alert('Photo sending not implemented in this minimal version');
}

async function searchUsers() {
    const q = document.getElementById('searchInput').value;
    if (q.length < 1) return;
    const resp = await fetch(`/search?q=${encodeURIComponent(q)}`);
    const users = await resp.json();
    const results = document.getElementById('searchResults');
    results.innerHTML = '';
    users.forEach(u => {
        const div = document.createElement('div');
        div.style.cssText = 'padding:8px; background:#202c33; margin:2px 0; cursor:pointer;';
        div.innerText = u.username;
        div.onclick = async () => {
            await fetch('/send_request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipient_id: u.id }) });
            alert('Request sent');
            document.getElementById('searchInput').value = '';
            results.innerHTML = '';
        };
        results.appendChild(div);
    });
}

function logout() {
    fetch('/logout', { method: 'POST' }).then(() => {
        sessionStorage.clear();
        window.location.href = '/login';
    });
}
