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
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# MongoDB connection
try:
    client = MongoClient(
        "mongodb+srv://s09084711_db_user:gUuX0HPEcOhUW1oA@cluster0.udzsilh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
        serverSelectionTimeoutMS=5000
    )
    db = client["Cluster0"]
    keys_collection = db.api_keys
    logger.info("MongoDB connection established")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    exit(1)

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
                {
                    "$set": {
                        "remaining_requests": key["total_requests"],
                        "last_reset": now
                    }
                }
            )
        logger.info(f"Successfully reset requests at {now}")
    except Exception as e:
        logger.error(f"Error in reset_remaining_requests: {e}")

# Schedule daily reset at midnight UTC
scheduler.add_job(
    reset_remaining_requests,
    'cron',
    hour=0,
    minute=0,
    second=0,
    timezone='UTC'
)

def load_tokens(server_name):
    """Load tokens from JSON file based on server name"""
    try:
        file_map = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "US": "token_br.json",
            "SAC": "token_br.json",
            "NA": "token_br.json"
        }
        file_name = file_map.get(server_name, "token_bd.json")
        with open(file_name, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    """Encrypt a message using AES-CBC"""
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    """Create a Protobuf message for liking a profile"""
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    """Send a single HTTP POST request with encrypted data"""
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
                    logger.error(f"Request failed with status code: {response.status}")
                    return {"status": response.status, "data": None}
                return {"status": response.status, "data": await response.text()}
    except Exception as e:
        logger.error(f"Exception in send_request: {e}")
        return {"status": 500, "data": None}

async def send_multiple_requests(uid, server_name, url):
    """Send multiple like requests concurrently"""
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            logger.error("Failed to create protobuf message")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            logger.error("Encryption failed")
            return None
        tokens = load_tokens(server_name)
        if tokens is None:
            logger.error("Failed to load tokens")
            return None
        tasks = [send_request(encrypted_uid, tokens[i % len(tokens)]["token"], url) for i in range(100)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    """Create a Protobuf message for UID generation"""
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    """Encrypt a UID using Protobuf and AES"""
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

def make_request(encrypt, server_name, token):
    """Make a single request to fetch player info"""
    try:
        url_map = {
            "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        }
        url = url_map.get(server_name, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
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
        if response.status_code != 200:
            logger.error(f"Request failed with status code: {response.status_code}")
            return None
        binary = response.content
        return decode_protobuf(binary)
    except Exception as e:
        logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    """Decode Protobuf data into a Python object"""
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

def authenticate_key(api_key):
    """Authenticate an API key and check its validity"""
    try:
        key_data = keys_collection.find_one({"key": api_key})
        if not key_data:
            return None
        
        now = datetime.now()
        if 'expires_at' in key_data and now > key_data['expires_at']:
            keys_collection.update_one(
                {"key": api_key},
                {"$set": {"is_active": False}}
            )
            return None
        
        if 'is_active' in key_data and not key_data['is_active']:
            return None
        
        if 'last_reset' in key_data:
            last_reset = key_data['last_reset']
            if isinstance(last_reset, str):
                last_reset = datetime.fromisoformat(last_reset)
            if last_reset.date() < now.date():
                keys_collection.update_one(
                    {"key": api_key},
                    {"$set": {
                        "remaining_requests": key_data['total_requests'],
                        "last_reset": now
                    }}
                )
                key_data['remaining_requests'] = key_data['total_requests']
        
        return key_data
    except Exception as e:
        logger.error(f"Error in authenticate_key: {e}")
        return None

def update_key_usage(api_key, decrement=1):
    """Decrement remaining requests count for a key"""
    try:
        keys_collection.update_one(
            {"key": api_key},
            {
                "$inc": {"remaining_requests": -decrement},
                "$set": {"last_used": datetime.now()}
            }
        )
    except Exception as e:
        logger.error(f"Error updating key usage: {e}")

@app.route('/api/key/create', methods=['POST'])
def create_key():
    """Create a new API key with default expiration on 2025-09-12"""
    try:
        data = request.get_json() or {}
        custom_key = data.get('custom_key')
        total_requests = int(data.get('total_requests', 1000))
        expiry_date = datetime(2025, 9, 12)  # Default expiration date
        notes = data.get('notes', '')
        
        if custom_key:
            if keys_collection.find_one({"key": custom_key}):
                return jsonify({"error": "Custom key already exists"}), 400
            api_key = custom_key
        else:
            alphabet = string.ascii_letters + string.digits
            api_key = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        key_doc = {
            "key": api_key,
            "created_at": datetime.now(),
            "expires_at": expiry_date,
            "total_requests": total_requests,
            "remaining_requests": total_requests,
            "notes": notes,
            "is_active": True,
            "last_reset": datetime.now()
        }
        
        keys_collection.insert_one(key_doc)
        
        return jsonify({
            "message": "API key created successfully",
            "key": api_key,
            "expires_at": expiry_date.isoformat(),
            "total_requests": total_requests,
            "notes": notes
        }), 201
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/key/check', methods=['GET'])
def check_key():
    """Check the status and details of an API key"""
    try:
        api_key = request.headers.get('X-API-KEY') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        key_data = authenticate_key(api_key)
        if not key_data:
            return jsonify({"error": "Invalid or expired API key"}), 403
        
        key_data.pop('_id', None)
        for field in ['created_at', 'expires_at', 'last_reset', 'last_used']:
            if field in key_data and isinstance(key_data[field], datetime):
                key_data[field] = key_data[field].isoformat()
        
        return jsonify(key_data), 200
    except Exception as e:
        logger.error(f"Error checking API key: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/key/remove', methods=['DELETE'])
def remove_key():
    """Deactivate an API key"""
    try:
        api_key = request.headers.get('X-API-KEY') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        key_data = authenticate_key(api_key)
        if not key_data:
            return jsonify({"error": "Invalid or expired API key"}), 403
        
        result = keys_collection.update_one(
            {"key": api_key},
            {"$set": {"is_active": False}}
        )
        
        if result.modified_count == 1:
            return jsonify({"message": "API key deactivated successfully"}), 200
        return jsonify({"error": "Failed to deactivate API key"}), 400
    except Exception as e:
        logger.error(f"Error removing API key: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/key/update', methods=['PUT'])
def update_key():
    """Update an API key's properties"""
    try:
        api_key = request.headers.get('X-API-KEY') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        key_data = authenticate_key(api_key)
        if not key_data:
            return jsonify({"error": "Invalid or expired API key"}), 403
        
        data = request.get_json() or {}
        update_fields = {}
        
        if 'total_requests' in data:
            try:
                total_requests = int(data['total_requests'])
                update_fields['total_requests'] = total_requests
                if total_requests > key_data.get('total_requests', 0):
                    update_fields['remaining_requests'] = total_requests - (key_data.get('total_requests', 0) - key_data.get('remaining_requests', 0))
            except ValueError:
                return jsonify({"error": "total_requests must be an integer"}), 400
        
        if 'expiry_days' in data:
            try:
                expiry_days = int(data['expiry_days'])
                update_fields['expires_at'] = datetime.now() + timedelta(days=expiry_days)
            except ValueError:
                return jsonify({"error": "expiry_days must be an integer"}), 400
        
        if 'is_active' in data:
            update_fields['is_active'] = bool(data['is_active'])
        
        if 'notes' in data:
            update_fields['notes'] = str(data['notes'])
        
        if not update_fields:
            return jsonify({"error": "No valid fields to update"}), 400
        
        result = keys_collection.update_one(
            {"key": api_key},
            {"$set": update_fields}
        )
        
        if result.modified_count == 1:
            return jsonify({"message": "API key updated successfully"}), 200
        return jsonify({"error": "No changes made to API key"}), 400
    except Exception as e:
        logger.error(f"Error updating API key: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/like', methods=['GET'])
def handle_like_requests():
    """Handle like requests with URL format /like?uid=64548484&server_name=ind&key=Nilay-seller"""
    try:
        api_key = request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        key_data = authenticate_key(api_key)
        if not key_data:
            return jsonify({"error": "Invalid or expired API key"}), 403
        
        if key_data.get('remaining_requests', 0) <= 0:
            next_reset = (datetime.now() + timedelta(days=1)).replace(hour=0, minute=0, second=0)
            return jsonify({
                "error": "No remaining requests",
                "status": 0,
                "next_reset": next_reset.isoformat()
            }), 429
        
        uid = request.args.get("uid")
        server_name = request.args.get("server_name", "").upper()
        if not uid or not server_name:
            return jsonify({"error": "UID and server_name are required"}), 400
        
        if server_name not in {"IND", "BR", "US", "SAC", "NA", "BD"}:
            return jsonify({"error": "Invalid server_name"}), 400
        
        tokens = load_tokens(server_name)
        if tokens is None:
            return jsonify({"error": "Failed to load tokens", "status": 0}), 500
        
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption of UID failed", "status": 0}), 500

        # Fetch initial player data
        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            return jsonify({"error": "Failed to retrieve initial player info", "status": 0}), 500
        
        try:
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            account_info = data_before.get('AccountInfo', {})
            before_like = int(account_info.get('Likes', 0))
        except Exception as e:
            return jsonify({"error": f"Error processing initial data: {str(e)}", "status": 0}), 500

        # Send like requests
        url_map = {
            "IND": "https://client.ind.freefiremobile.com/LikeProfile",
            "BR": "https://client.us.freefiremobile.com/LikeProfile",
            "US": "https://client.us.freefiremobile.com/LikeProfile",
            "SAC": "https://client.us.freefiremobile.com/LikeProfile",
            "NA": "https://client.us.freefiremobile.com/LikeProfile"
        }
        url = url_map.get(server_name, "https://clientbp.ggblueshark.com/LikeProfile")
        results = asyncio.run(send_multiple_requests(uid, server_name, url))
        if results is None:
            return jsonify({"error": "Failed to send like requests", "status": 0}), 500

        # Fetch updated player data
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            return jsonify({"error": "Failed to retrieve updated player info", "status": 0}), 500
        
        try:
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            account_info_after = data_after.get('AccountInfo', {})
            after_like = int(account_info_after.get('Likes', 0))
            player_uid = int(account_info_after.get('UID', 0))
            player_name = str(account_info_after.get('PlayerNickname', ''))
            like_given = after_like - before_like
        except Exception as e:
            return jsonify({"error": f"Error processing updated data: {str(e)}", "status": 0}), 500
        
        # Update key usage if likes were given
        status = 2 if like_given == 0 else 1
        if status == 1:
            update_key_usage(api_key, 1)
        
        # Get updated key info
        updated_key_data = authenticate_key(api_key)
        if not updated_key_data:
            return jsonify({"error": "Failed to retrieve updated key info", "status": 0}), 500
        
        response = {
            "response": {
                "KeyExpiresAt": updated_key_data['expires_at'].isoformat(),
                "KeyRemainingRequests": f"{updated_key_data['remaining_requests']}/{updated_key_data['total_requests']}",
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid
            },
            "status": status
        }
        
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error processing like request: {e}")
        return jsonify({"error": str(e), "status": 0}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
