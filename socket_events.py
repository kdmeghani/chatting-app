from flask import request, session
from flask_socketio import emit, join_room, leave_room
import models

def register_socket_handlers(socketio):
    @socketio.on('connect')
    def handle_connect():
        user_id = session.get('user_id')
        if user_id:
            models.update_user_online(user_id, True)
            join_room(f'user_{user_id}')
            emit('status', {'msg': 'Connected'})

    @socketio.on('disconnect')
    def handle_disconnect():
        user_id = session.get('user_id')
        if user_id:
            models.update_user_online(user_id, False)
            leave_room(f'user_{user_id}')

    @socketio.on('send_message')
    def handle_send_message(data):
        sender_id = session.get('user_id')
        if not sender_id:
            return
        recipient_id = data['recipient_id']
        encrypted_message = data['encrypted_message']
        iv = data['iv']
        encrypted_key_self = data['encrypted_key_self']
        encrypted_key_recipient = data['encrypted_key_recipient']

        models.save_message(sender_id, recipient_id, encrypted_message, encrypted_key_self, iv, True)
        models.save_message(recipient_id, sender_id, encrypted_message, encrypted_key_recipient, iv, False)

        sender_msg = {
            'id': 'temp',
            'type': 'text',
            'encrypted_message': encrypted_message,
            'encrypted_key': encrypted_key_self,
            'iv': iv,
            'timestamp': None,
            'is_sent': True,
            'friend_id': recipient_id
        }
        recipient_msg = {
            'id': 'temp',
            'type': 'text',
            'encrypted_message': encrypted_message,
            'encrypted_key': encrypted_key_recipient,
            'iv': iv,
            'timestamp': None,
            'is_sent': False,
            'friend_id': sender_id
        }

        emit('new_message', sender_msg, room=f'user_{sender_id}')
        emit('new_message', recipient_msg, room=f'user_{recipient_id}')

    @socketio.on('send_photo')
    def handle_send_photo(data):
        sender_id = session.get('user_id')
        if not sender_id:
            return
        recipient_id = data['recipient_id']
        file_id = data['file_id']
        iv = data['iv']
        encrypted_key_self = data['encrypted_key_self']
        encrypted_key_recipient = data['encrypted_key_recipient']
        file_name = data.get('file_name', 'photo')

        sender_msg = {
            'type': 'photo',
            'file_id': file_id,
            'encrypted_key': encrypted_key_self,
            'iv': iv,
            'file_name': file_name,
            'timestamp': None,
            'is_sent': True,
            'friend_id': recipient_id
        }
        recipient_msg = {
            'type': 'photo',
            'file_id': file_id,
            'encrypted_key': encrypted_key_recipient,
            'iv': iv,
            'file_name': file_name,
            'timestamp': None,
            'is_sent': False,
            'friend_id': sender_id
        }

        emit('new_photo', sender_msg, room=f'user_{sender_id}')
        emit('new_photo', recipient_msg, room=f'user_{recipient_id}')

    @socketio.on('typing')
    def handle_typing(data):
        user_id = session.get('user_id')
        if not user_id:
            return
        friend_id = data['friend_id']
        is_typing = data['is_typing']
        models.set_typing(user_id, friend_id, is_typing)
        emit('typing_indicator', {
            'user_id': user_id,
            'is_typing': is_typing
        }, room=f'user_{friend_id}')