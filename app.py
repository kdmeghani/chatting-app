import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
import models
import crypto_utils
from socket_events import register_socket_handlers

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins="*")

register_socket_handlers(socketio)

# Initialize database tables (only once)
with app.app_context():
    models.init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        public_key = request.form['public_key']
        encrypted_private_key = request.form['encrypted_private_key']
        if session.get('csrf_token') != request.form.get('csrf_token'):
            abort(400)
        if not username or not email or not password:
            return "All fields required", 400
        if models.get_user_by_username(username):
            return "Username already exists", 400
        user_id = models.create_user(username, email, password, public_key, encrypted_private_key)
        session['user_id'] = user_id
        session['username'] = username
        return redirect(url_for('chat'))
    csrf_token = os.urandom(16).hex()
    session['csrf_token'] = csrf_token
    return render_template('register.html', csrf_token=csrf_token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if session.get('csrf_token') != request.form.get('csrf_token'):
            abort(400)
        user = models.get_user_by_username(username)
        if user and crypto_utils.check_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({
                'success': True,
                'user_id': user['id'],
                'username': user['username'],
                'public_key': user['public_key'],
                'encrypted_private_key': user['encrypted_private_key']
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    csrf_token = os.urandom(16).hex()
    session['csrf_token'] = csrf_token
    return render_template('login.html', csrf_token=csrf_token)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

@app.route('/search')
def search():
    if 'user_id' not in session:
        return jsonify([])
    query = request.args.get('q', '')
    if len(query) < 1:
        return jsonify([])
    with models.get_db() as conn:
        users = conn.execute(
            'SELECT id, username FROM users WHERE username LIKE ? AND id != ?',
            (f'%{query}%', session['user_id'])
        ).fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/send_request', methods=['POST'])
def send_request():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    data = request.get_json()
    recipient_id = data.get('recipient_id')
    if not recipient_id:
        return jsonify({'success': False, 'error': 'Missing recipient'}), 400
    success = models.send_friend_request(session['user_id'], recipient_id)
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Request already sent or user not found'}), 400

@app.route('/requests')
def list_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    requests = models.get_pending_requests(session['user_id'])
    return render_template('requests.html', requests=requests)

@app.route('/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    success = models.accept_friend_request(request_id)
    return jsonify({'success': success})

@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    success = models.reject_friend_request(request_id)
    return jsonify({'success': success})

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return jsonify([])
    friends_list = models.get_friends(session['user_id'])
    return jsonify([dict(f) for f in friends_list])

@app.route('/public_key/<int:user_id>')
def get_public_key(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = models.get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'public_key': user['public_key']})

@app.route('/messages/<int:friend_id>')
def get_messages(friend_id):
    if 'user_id' not in session:
        return jsonify([])
    messages = models.get_messages_for_user(session['user_id'], friend_id)
    return jsonify([{
        'id': m['id'],
        'type': m['type'],
        'encrypted_message': m['encrypted_message'],
        'encrypted_key': m['encrypted_key'],
        'iv': m['iv'],
        'file_name': m['file_name'],
        'timestamp': m['timestamp'],
        'is_sent': bool(m['is_sent'])
    } for m in messages])

@app.route('/upload_photo', methods=['POST'])
def upload_photo():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    recipient_id = request.form.get('recipient_id')
    encrypted_key_self = request.form.get('encrypted_key_self')
    encrypted_key_recipient = request.form.get('encrypted_key_recipient')
    iv = request.form.get('iv')
    original_filename = request.form.get('filename', 'photo')
    file = request.files.get('file')
    
    if not all([recipient_id, encrypted_key_self, encrypted_key_recipient, iv, file]):
        return jsonify({'error': 'Missing fields'}), 400
    
    file_id = str(uuid.uuid4())
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    file.save(file_path)
    
    models.save_photo_message(
        owner_id=session['user_id'],
        other_id=recipient_id,
        file_id=file_id,
        encrypted_key=encrypted_key_self,
        iv=iv,
        file_name=original_filename,
        is_sent=True
    )
    models.save_photo_message(
        owner_id=int(recipient_id),
        other_id=session['user_id'],
        file_id=file_id,
        encrypted_key=encrypted_key_recipient,
        iv=iv,
        file_name=original_filename,
        is_sent=False
    )
    
    return jsonify({'success': True, 'file_id': file_id})

@app.route('/download_photo/<file_id>')
def download_photo(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    with models.get_db() as conn:
        msg = conn.execute(
            'SELECT * FROM messages WHERE encrypted_message = ? AND (owner_id = ? OR other_id = ?)',
            (file_id, session['user_id'], session['user_id'])
        ).fetchone()
    
    if not msg:
        return jsonify({'error': 'File not found or access denied'}), 404
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found on server'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=msg['file_name'] or 'photo')

if __name__ == '__main__':
    socketio.run(app, debug=True)