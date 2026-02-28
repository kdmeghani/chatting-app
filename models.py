import os
import sqlite3
import bcrypt
from datetime import datetime

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///database.db')

# ---------- PostgreSQL Branch ----------
if DATABASE_URL.startswith('postgresql://'):
    import psycopg2
    from psycopg2.extras import RealDictCursor
    from psycopg2 import pool

    connection_pool = psycopg2.pool.SimpleConnectionPool(1, 10, DATABASE_URL)

    class PGConnection:
        """Wrapper that mimics sqlite3.Connection for PostgreSQL."""
        def __init__(self, conn, cur):
            self.conn = conn
            self.cur = cur

        def execute(self, sql, parameters=None):
            # Convert ? placeholders to %s for PostgreSQL
            sql_pg = sql.replace('?', '%s')
            if parameters is None:
                self.cur.execute(sql_pg)
            else:
                self.cur.execute(sql_pg, parameters)
            return self

        def fetchall(self):
            return self.cur.fetchall()

        def fetchone(self):
            return self.cur.fetchone()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            from models import put_db  # avoid circular import
            put_db(self.conn, self.cur)

    def get_db():
        conn = connection_pool.getconn()
        conn.autocommit = True
        cur = conn.cursor(cursor_factory=RealDictCursor)
        return PGConnection(conn, cur)

    def put_db(conn, cur):
        cur.close()
        connection_pool.putconn(conn)

    def init_db():
        with get_db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    encrypted_private_key TEXT NOT NULL,
                    online BOOLEAN DEFAULT FALSE,
                    last_seen TIMESTAMP
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS friend_requests (
                    id SERIAL PRIMARY KEY,
                    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(sender_id, recipient_id)
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS friendships (
                    id SERIAL PRIMARY KEY,
                    user1_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    user2_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CHECK (user1_id < user2_id),
                    UNIQUE(user1_id, user2_id)
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    other_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    type TEXT DEFAULT 'text',
                    encrypted_message TEXT NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    file_name TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_sent BOOLEAN NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS typing_status (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    is_typing BOOLEAN DEFAULT FALSE,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, friend_id)
                )
            """)

    # All helper functions (create_user, get_user_by_username, etc.) must use `with get_db() as db:`
    # and call db.execute(...). They should NOT use direct psycopg2 calls.
    # I'll rewrite one as an example; you need to rewrite all others similarly.

    def create_user(username, email, password, public_key, encrypted_private_key):
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        with get_db() as db:
            db.execute(
                'INSERT INTO users (username, email, password_hash, public_key, encrypted_private_key) VALUES (?, ?, ?, ?, ?) RETURNING id',
                (username, email, password_hash, public_key, encrypted_private_key)
            )
            row = db.fetchone()
            return row['id'] if row else None

    def get_user_by_username(username):
        with get_db() as db:
            db.execute('SELECT * FROM users WHERE username = ?', (username,))
            return db.fetchone()

    def get_user_by_id(user_id):
        with get_db() as db:
            db.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            return db.fetchone()

    def update_user_online(user_id, online):
        with get_db() as db:
            db.execute(
                'UPDATE users SET online = ?, last_seen = ? WHERE id = ?',
                (online, datetime.utcnow() if online else None, user_id)
            )

    def send_friend_request(sender_id, recipient_id):
        with get_db() as db:
            try:
                db.execute(
                    'INSERT INTO friend_requests (sender_id, recipient_id) VALUES (?, ?)',
                    (sender_id, recipient_id)
                )
                return True
            except psycopg2.IntegrityError:
                return False

    def get_pending_requests(user_id):
        with get_db() as db:
            db.execute('''
                SELECT fr.*, u.username as sender_username
                FROM friend_requests fr
                JOIN users u ON fr.sender_id = u.id
                WHERE fr.recipient_id = ? AND fr.status = 'pending'
            ''', (user_id,))
            return db.fetchall()

    def accept_friend_request(request_id):
        with get_db() as db:
            db.execute('SELECT * FROM friend_requests WHERE id = ?', (request_id,))
            req = db.fetchone()
            if not req or req['status'] != 'pending':
                return False
            db.execute('UPDATE friend_requests SET status = ? WHERE id = ?', ('accepted', request_id))
            user1, user2 = sorted([req['sender_id'], req['recipient_id']])
            db.execute(
                'INSERT INTO friendships (user1_id, user2_id) VALUES (?, ?) ON CONFLICT DO NOTHING',
                (user1, user2)
            )
            return True

    def reject_friend_request(request_id):
        with get_db() as db:
            db.execute('UPDATE friend_requests SET status = ? WHERE id = ?', ('rejected', request_id))
            return True

    def get_friends(user_id):
        with get_db() as db:
            db.execute('''
                SELECT u.id, u.username, u.online
                FROM friendships f
                JOIN users u ON (u.id = f.user1_id OR u.id = f.user2_id)
                WHERE (f.user1_id = ? OR f.user2_id = ?) AND u.id != ?
            ''', (user_id, user_id, user_id))
            return db.fetchall()

    def get_messages_for_user(user_id, friend_id):
        with get_db() as db:
            db.execute('''
                SELECT * FROM messages
                WHERE owner_id = ? AND other_id = ?
                ORDER BY timestamp ASC
            ''', (user_id, friend_id))
            return db.fetchall()

    def save_message(owner_id, other_id, encrypted_message, encrypted_key, iv, is_sent):
        with get_db() as db:
            db.execute(
                'INSERT INTO messages (owner_id, other_id, type, encrypted_message, encrypted_key, iv, is_sent) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (owner_id, other_id, 'text', encrypted_message, encrypted_key, iv, is_sent)
            )

    def save_photo_message(owner_id, other_id, file_id, encrypted_key, iv, file_name, is_sent):
        with get_db() as db:
            db.execute(
                'INSERT INTO messages (owner_id, other_id, type, encrypted_message, encrypted_key, iv, file_name, is_sent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (owner_id, other_id, 'photo', file_id, encrypted_key, iv, file_name, is_sent)
            )

    def set_typing(user_id, friend_id, is_typing):
        with get_db() as db:
            db.execute('''
                INSERT INTO typing_status (user_id, friend_id, is_typing, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT (user_id, friend_id)
                DO UPDATE SET is_typing = EXCLUDED.is_typing, updated_at = EXCLUDED.updated_at
            ''', (user_id, friend_id, is_typing))

# ---------- SQLite Branch (unchanged, but uses the same function names) ----------
else:
    DATABASE = DATABASE_URL.replace('sqlite:///', '')

    def get_db():
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db():
        with get_db() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    encrypted_private_key TEXT NOT NULL,
                    online BOOLEAN DEFAULT 0,
                    last_seen DATETIME
                );

                CREATE TABLE IF NOT EXISTS friend_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users(id),
                    FOREIGN KEY (recipient_id) REFERENCES users(id),
                    UNIQUE(sender_id, recipient_id)
                );

                CREATE TABLE IF NOT EXISTS friendships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user1_id INTEGER NOT NULL,
                    user2_id INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user1_id) REFERENCES users(id),
                    FOREIGN KEY (user2_id) REFERENCES users(id),
                    CHECK(user1_id < user2_id),
                    UNIQUE(user1_id, user2_id)
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    other_id INTEGER NOT NULL,
                    type TEXT DEFAULT 'text',
                    encrypted_message TEXT NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    file_name TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_sent BOOLEAN NOT NULL,
                    FOREIGN KEY (owner_id) REFERENCES users(id),
                    FOREIGN KEY (other_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS typing_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    friend_id INTEGER NOT NULL,
                    is_typing BOOLEAN DEFAULT 0,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (friend_id) REFERENCES users(id),
                    UNIQUE(user_id, friend_id)
                );
            ''')

    # SQLite helper functions (same as before, but keep them)
    def create_user(username, email, password, public_key, encrypted_private_key):
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        with get_db() as conn:
            cursor = conn.execute(
                'INSERT INTO users (username, email, password_hash, public_key, encrypted_private_key) VALUES (?, ?, ?, ?, ?)',
                (username, email, password_hash, public_key, encrypted_private_key)
            )
            return cursor.lastrowid

    def get_user_by_username(username):
        with get_db() as conn:
            return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    def get_user_by_id(user_id):
        with get_db() as conn:
            return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    def update_user_online(user_id, online):
        with get_db() as conn:
            conn.execute('UPDATE users SET online = ?, last_seen = ? WHERE id = ?',
                         (1 if online else 0, datetime.utcnow() if online else None, user_id))

    def send_friend_request(sender_id, recipient_id):
        with get_db() as conn:
            try:
                conn.execute('INSERT INTO friend_requests (sender_id, recipient_id) VALUES (?, ?)',
                             (sender_id, recipient_id))
                return True
            except sqlite3.IntegrityError:
                return False

    def get_pending_requests(user_id):
        with get_db() as conn:
            return conn.execute('''
                SELECT fr.*, u.username as sender_username
                FROM friend_requests fr
                JOIN users u ON fr.sender_id = u.id
                WHERE fr.recipient_id = ? AND fr.status = 'pending'
            ''', (user_id,)).fetchall()

    def accept_friend_request(request_id):
        with get_db() as conn:
            req = conn.execute('SELECT * FROM friend_requests WHERE id = ?', (request_id,)).fetchone()
            if not req or req['status'] != 'pending':
                return False
            conn.execute('UPDATE friend_requests SET status = "accepted" WHERE id = ?', (request_id,))
            user1, user2 = sorted([req['sender_id'], req['recipient_id']])
            conn.execute('INSERT OR IGNORE INTO friendships (user1_id, user2_id) VALUES (?, ?)', (user1, user2))
            return True

    def reject_friend_request(request_id):
        with get_db() as conn:
            conn.execute('UPDATE friend_requests SET status = "rejected" WHERE id = ?', (request_id,))
            return True

    def get_friends(user_id):
        with get_db() as conn:
            rows = conn.execute('''
                SELECT u.id, u.username, u.online
                FROM friendships f
                JOIN users u ON (u.id = f.user1_id OR u.id = f.user2_id)
                WHERE (f.user1_id = ? OR f.user2_id = ?) AND u.id != ?
            ''', (user_id, user_id, user_id)).fetchall()
            return rows

    def get_messages_for_user(user_id, friend_id):
        with get_db() as conn:
            return conn.execute('''
                SELECT * FROM messages
                WHERE owner_id = ? AND other_id = ?
                ORDER BY timestamp ASC
            ''', (user_id, friend_id)).fetchall()

    def save_message(owner_id, other_id, encrypted_message, encrypted_key, iv, is_sent):
        with get_db() as conn:
            conn.execute(
                'INSERT INTO messages (owner_id, other_id, type, encrypted_message, encrypted_key, iv, is_sent) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (owner_id, other_id, 'text', encrypted_message, encrypted_key, iv, 1 if is_sent else 0)
            )

    def save_photo_message(owner_id, other_id, file_id, encrypted_key, iv, file_name, is_sent):
        with get_db() as conn:
            conn.execute(
                'INSERT INTO messages (owner_id, other_id, type, encrypted_message, encrypted_key, iv, file_name, is_sent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (owner_id, other_id, 'photo', file_id, encrypted_key, iv, file_name, 1 if is_sent else 0)
            )

    def set_typing(user_id, friend_id, is_typing):
        with get_db() as conn:
            conn.execute('''
                INSERT INTO typing_status (user_id, friend_id, is_typing, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id, friend_id) DO UPDATE SET is_typing = excluded.is_typing, updated_at = excluded.updated_at
            ''', (user_id, friend_id, 1 if is_typing else 0))
