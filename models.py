import os
import bcrypt
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool

# Get database URL from environment
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://localhost/chat_app')

# Create a connection pool (min 1, max 10 connections)
connection_pool = psycopg2.pool.SimpleConnectionPool(1, 10, DATABASE_URL)

def get_db():
    """Get a connection from the pool and return a cursor as RealDict."""
    conn = connection_pool.getconn()
    conn.autocommit = True
    return conn, conn.cursor(cursor_factory=RealDictCursor)

def put_db(conn, cursor):
    """Return connection to pool."""
    cursor.close()
    connection_pool.putconn(conn)

def init_db():
    conn, cur = get_db()
    try:
        # Create tables if they don't exist
        cur.execute("""
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS friend_requests (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(sender_id, recipient_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS friendships (
                id SERIAL PRIMARY KEY,
                user1_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                user2_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK (user1_id < user2_id),
                UNIQUE(user1_id, user2_id)
            )
        """)
        cur.execute("""
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS typing_status (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                is_typing BOOLEAN DEFAULT FALSE,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, friend_id)
            )
        """)
    finally:
        put_db(conn, cur)

def create_user(username, email, password, public_key, encrypted_private_key):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn, cur = get_db()
    try:
        cur.execute(
            'INSERT INTO users (username, email, password_hash, public_key, encrypted_private_key) VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (username, email, password_hash, public_key, encrypted_private_key)
        )
        user_id = cur.fetchone()['id']
        return user_id
    finally:
        put_db(conn, cur)

def get_user_by_username(username):
    conn, cur = get_db()
    try:
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        return cur.fetchone()
    finally:
        put_db(conn, cur)

def get_user_by_id(user_id):
    conn, cur = get_db()
    try:
        cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        return cur.fetchone()
    finally:
        put_db(conn, cur)

def update_user_online(user_id, online):
    conn, cur = get_db()
    try:
        cur.execute(
            'UPDATE users SET online = %s, last_seen = %s WHERE id = %s',
            (online, datetime.utcnow() if online else None, user_id)
        )
    finally:
        put_db(conn, cur)

def send_friend_request(sender_id, recipient_id):
    conn, cur = get_db()
    try:
        cur.execute(
            'INSERT INTO friend_requests (sender_id, recipient_id) VALUES (%s, %s)',
            (sender_id, recipient_id)
        )
        return True
    except psycopg2.IntegrityError:
        conn.rollback()
        return False
    finally:
        put_db(conn, cur)

def get_pending_requests(user_id):
    conn, cur = get_db()
    try:
        cur.execute('''
            SELECT fr.*, u.username as sender_username
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.recipient_id = %s AND fr.status = 'pending'
        ''', (user_id,))
        return cur.fetchall()
    finally:
        put_db(conn, cur)

def accept_friend_request(request_id):
    conn, cur = get_db()
    try:
        cur.execute('SELECT * FROM friend_requests WHERE id = %s', (request_id,))
        req = cur.fetchone()
        if not req or req['status'] != 'pending':
            return False
        cur.execute('UPDATE friend_requests SET status = %s WHERE id = %s', ('accepted', request_id))
        user1, user2 = sorted([req['sender_id'], req['recipient_id']])
        cur.execute(
            'INSERT INTO friendships (user1_id, user2_id) VALUES (%s, %s) ON CONFLICT DO NOTHING',
            (user1, user2)
        )
        return True
    finally:
        put_db(conn, cur)

def reject_friend_request(request_id):
    conn, cur = get_db()
    try:
        cur.execute('UPDATE friend_requests SET status = %s WHERE id = %s', ('rejected', request_id))
        return True
    finally:
        put_db(conn, cur)

def get_friends(user_id):
    conn, cur = get_db()
    try:
        cur.execute('''
            SELECT u.id, u.username, u.online
            FROM friendships f
            JOIN users u ON (u.id = f.user1_id OR u.id = f.user2_id)
            WHERE (f.user1_id = %s OR f.user2_id = %s) AND u.id != %s
        ''', (user_id, user_id, user_id))
        return cur.fetchall()
    finally:
        put_db(conn, cur)

def get_messages_for_user(user_id, friend_id):
    conn, cur = get_db()
    try:
        cur.execute('''
            SELECT * FROM messages
            WHERE owner_id = %s AND other_id = %s
            ORDER BY timestamp ASC
        ''', (user_id, friend_id))
        return cur.fetchall()
    finally:
        put_db(conn, cur)

def save_message(owner_id, other_id, encrypted_message, encrypted_key, iv, is_sent):
    conn, cur = get_db()
    try:
        cur.execute(
            'INSERT INTO messages (owner_id, other_id, type, encrypted_message, encrypted_key, iv, is_sent) VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (owner_id, other_id, 'text', encrypted_message, encrypted_key, iv, is_sent)
        )
    finally:
        put_db(conn, cur)

def save_photo_message(owner_id, other_id, file_id, encrypted_key, iv, file_name, is_sent):
    conn, cur = get_db()
    try:
        cur.execute(
            'INSERT INTO messages (owner_id, other_id, type, encrypted_message, encrypted_key, iv, file_name, is_sent) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
            (owner_id, other_id, 'photo', file_id, encrypted_key, iv, file_name, is_sent)
        )
    finally:
        put_db(conn, cur)

def set_typing(user_id, friend_id, is_typing):
    conn, cur = get_db()
    try:
        cur.execute('''
            INSERT INTO typing_status (user_id, friend_id, is_typing, updated_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id, friend_id)
            DO UPDATE SET is_typing = EXCLUDED.is_typing, updated_at = EXCLUDED.updated_at
        ''', (user_id, friend_id, is_typing))
    finally:
        put_db(conn, cur)