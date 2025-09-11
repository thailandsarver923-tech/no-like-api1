from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
import secrets
import string
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb+srv://s09084711_db_user:gUuX0HPEcOhUW1oA@cluster0.udzsilh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["Cluster0"]
keys_collection = db.api_keys

# Master key for admin operations
MASTER_KEY = "Nilay-Rishika"

# Initialize scheduler for daily reset
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def reset_remaining_requests():
    """Reset remaining requests for all active keys to their total_requests"""
    try:
        now = datetime.now()
        active_keys = keys_collection.find({
            "is_active": True,
            "expires_at": {"$gt": now}
        })
        
        for key in active_keys:
            keys_collection.update_one(
                {"_id": key["_id"]},
                {"$set": {"remaining_requests": key["total_requests"]}}
            )
        
        app.logger.info("Daily reset of remaining requests completed")
    except Exception as e:
        app.logger.error(f"Error in reset_remaining_requests: {e}")

# Schedule daily reset at midnight
scheduler.add_job(
    reset_remaining_requests,
    'cron',
    hour=0,
    minute=0,
    second=0,
    timezone='UTC'
)

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
            return decode
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

def authenticate_key(api_key):
    """Check if API key exists and is valid"""
    try:
        key_data = keys_collection.find_one({"key": api_key})
        if not key_data:
            return None
        
        now = datetime.now()
        if (not key_data.get("is_active", True) or 
            key_data.get("expires_at") < now or 
            key_data.get("remaining_requests", 0) <= 0):
            return None
        
        return key_data
    except Exception as e:
        app.logger.error(f"Error authenticating key: {e}")
        return None

def update_key_usage(api_key, decrement=1):
    """Decrement remaining requests count for a key only when likes are given"""
    try:
        keys_collection.update_one(
            {"key": api_key},
            {
                "$inc": {"remaining_requests": -decrement},
                "$set": {"last_used": datetime.now()}
            }
        )
    except Exception as e:
        app.logger.error(f"Error updating key usage: {e}")

@app.route('/api/key/create', methods=['POST'])
def create_key():
    try:
        # Require master key for creating new keys
        master_key = request.headers.get('X-MASTER-KEY') or request.args.get('master_key')
        if not master_key or master_key != MASTER_KEY:
            return jsonify({"error": "Valid master key is required"}), 401
        
        data = request.get_json()
        custom_key = data.get('custom_key')
        total_requests = int(data.get('total_requests', 1000))
        expiry_days = int(data.get('expiry_days', 30))
        notes = data.get('notes', '')
        
        # Generate a random key if no custom key provided
        if not custom_key:
            alphabet = string.ascii_letters + string.digits
            custom_key = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        # Check if key already exists
        if keys_collection.find_one({"key": custom_key}):
            return jsonify({"error": "API key already exists"}), 400
        
        # Create key document
        key_data = {
            "key": custom_key,
            "total_requests": total_requests,
            "remaining_requests": total_requests,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(days=expiry_days),
            "is_active": True,
            "notes": notes,
            "last_used": None
        }
        
        # Insert into database
        result = keys_collection.insert_one(key_data)
        
        return jsonify({
            "message": "API key created successfully",
            "key": custom_key,
            "expires_at": key_data["expires_at"].isoformat(),
            "total_requests": total_requests
        }), 201
    except Exception as e:
        app.logger.error(f"Error creating API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/key/check', methods=['GET'])
def check_key():
    """Check the status and details of an API key"""
    try:
        api_key = request.headers.get('X-API-KEY') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        key_data = authenticate_key(api_key)
        if not key_data:
            return jsonify({"error": "Invalid or expired API key"}), 401
        
        # Return key information
        return jsonify({
            "key": key_data["key"],
            "total_requests": key_data["total_requests"],
            "remaining_requests": key_data["remaining_requests"],
            "created_at": key_data["created_at"].isoformat(),
            "expires_at": key_data["expires_at"].isoformat(),
            "is_active": key_data["is_active"],
            "notes": key_data.get("notes", ""),
            "last_used": key_data.get("last_used", "").isoformat() if key_data.get("last_used") else None
        }), 200
    except Exception as e:
        app.logger.error(f"Error checking API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/key/remove', methods=['DELETE'])
def remove_key():
    """Remove an API key (mark as inactive)"""
    try:
        # Require master key for removing keys
        master_key = request.headers.get('X-MASTER-KEY') or request.args.get('master_key')
        if not master_key or master_key != MASTER_KEY:
            return jsonify({"error": "Valid master key is required"}), 401
        
        api_key = request.headers.get('X-API-KEY') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        # Mark key as inactive
        result = keys_collection.update_one(
            {"key": api_key},
            {"$set": {"is_active": False}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "API key not found"}), 404
        
        return jsonify({"message": "API key deactivated successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error removing API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/key/update', methods=['PUT'])
def update_key():
    """Update an API key's properties"""
    try:
        # Require master key for updating keys
        master_key = request.headers.get('X-MASTER-KEY') or request.args.get('master_key')
        if not master_key or master_key != MASTER_KEY:
            return jsonify({"error": "Valid master key is required"}), 401
        
        api_key = request.headers.get('X-API-KEY') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        data = request.get_json()
        update_fields = {}
        
        if 'total_requests' in data:
            update_fields['total_requests'] = int(data['total_requests'])
            update_fields['remaining_requests'] = int(data['total_requests'])
        
        if 'expiry_days' in data:
            update_fields['expires_at'] = datetime.now() + timedelta(days=int(data['expiry_days']))
        
        if 'is_active' in data:
            update_fields['is_active'] = bool(data['is_active'])
        
        if 'notes' in data:
            update_fields['notes'] = data['notes']
        
        if not update_fields:
            return jsonify({"error": "No valid fields to update"}), 400
        
        # Update key
        result = keys_collection.update_one(
            {"key": api_key},
            {"$set": update_fields}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "API key not found or no changes made"}), 404
        
        return jsonify({"message": "API key updated successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error updating API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/like', methods=['GET'])
def handle_requests():
    api_key = request.headers.get('X-API-KEY') or request.args.get('key')
    if not api_key:
        return jsonify({"error": "API key is required"}), 401
    
    # Authenticate the API key
    key_data = authenticate_key(api_key)
    if not key_data:
        return jsonify({"error": "Invalid or expired API key"}), 401
    
    # Get parameters from request
    uid = request.args.get('uid')
    server_name = request.args.get('server_name', '').upper()
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400
    
    # Validate server name
    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD"]
    if server_name not in valid_servers:
        return jsonify({"error": "Invalid server name. Valid options: IND, BR, US, SAC, NA, BD"}), 400
    
    try:
        # Encrypt UID
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Failed to encrypt UID"}), 500
        
        # Load tokens for the server
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": "Failed to load tokens for the server"}), 500
        
        # Use the first token for the request
        token = tokens[0]["token"]
        
        # Make the request
        result = make_request(encrypted_uid, server_name, token)
        
        if result is None:
            return jsonify({"error": "Failed to process request"}), 500
        
        # Convert protobuf to JSON
        result_json = MessageToJson(result)
        result_data = json.loads(result_json)
        
        # Update key usage (only if likes were successfully given)
        if "likes" in result_data:
            update_key_usage(api_key)
        
        return jsonify(result_data), 200
    except Exception as e:
        app.logger.error(f"Error in handle_requests: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
