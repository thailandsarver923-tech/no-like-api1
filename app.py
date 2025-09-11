import asyncio
import binascii
import json
import logging
import secrets
import string
import aiohttp
import requests
import atexit
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
from apscheduler.schedulers.background import BackgroundScheduler

# --- Protobuf Imports ---
# Make sure you have like_pb2.py, like_count_pb2.py, uid_generator_pb2.py
# generated from their respective .proto files using:
# python -m grpc_tools.protoc -I. --python_out=. --pyi_out=. like.proto
import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
app.logger.setLevel(logging.INFO)

# ✅ Corrected MongoDB connection details based on your input
# MongoDB URL: mongodb+srv://s09084711_db_user:gUuX0HPEcOhUW1oA@cluster0.udzsilh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
# Database Name: Cluster0
client = MongoClient("mongodb+srv://s09084711_db_user:gUuX0HPEcOhUW1oA@cluster0.udzsilh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["Cluster0"]
keys_collection = db.api_keys

# Owner API Key for management operations
OWNER_API_KEY = "Nilay-Rishika"

# --- Scheduler Setup ---
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def reset_remaining_requests():
    """
    Reset remaining requests for all active keys to their total_requests.
    This function is scheduled to run daily at midnight UTC.
    """
    try:
        now = datetime.utcnow()
        app.logger.info(f"Running daily reset of API requests at {now} UTC.")

        # Update all active keys whose expiry date is in the future
        result = keys_collection.update_many(
            {
                "is_active": True,
                "expires_at": {"$gt": now}
            },
            [
                {"$set": {"remaining_requests": "$total_requests"}}
            ]
        )
        app.logger.info(f"Reset remaining requests for {result.modified_count} API keys.")
    except Exception as e:
        app.logger.error(f"Error during daily request reset: {e}")

# Schedule daily reset at midnight UTC
scheduler.add_job(
    reset_remaining_requests,
    'cron',
    hour=0,
    minute=0,
    second=0,
    timezone='UTC'
)

# --- Helper Functions for Free Fire API Interaction ---

def load_tokens(server_name):
    """
    Loads authentication tokens from JSON files based on the server name.
    Expects token_ind.json, token_br.json, token_bd.json in the same directory.
    """
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else: # Default for BD and any other server
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except FileNotFoundError:
        app.logger.error(f"Token file not found for server {server_name}. Please ensure token_ind.json, token_br.json, token_bd.json exist.")
        return None
    except json.JSONDecodeError:
        app.logger.error(f"Error decoding JSON from token file for server {server_name}.")
        return None
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    """
    Encrypts a plaintext byte string using AES CBC mode with a fixed key and IV.
    Returns the hexadecimal representation of the encrypted message.
    """
    try:
        key = b'Yg&tc%DEuh6%Zc^8' # 16-byte key
        iv = b'6oyZDr22E3ychjM%'  # 16-byte IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    """
    Creates a protobuf message for a 'like' operation.
    """
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid_hex, token, url):
    """
    Sends an individual asynchronous HTTP POST request to the Free Fire API.
    """
    try:
        edata = bytes.fromhex(encrypted_uid_hex)
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
                # Log non-200 responses but don't necessarily fail the entire batch
                if response.status != 200:
                    app.logger.warning(f"Request to {url} failed with status code: {response.status}")
                return response.status # Return status for aggregation
    except Exception as e:
        app.logger.error(f"Exception in send_request to {url}: {e}")
        return 500 # Return a generic error status code

async def send_multiple_requests(uid, server_name, url):
    """
    Prepares and sends 100 'like' requests concurrently using available tokens.
    """
    try:
        region = server_name.upper() # Ensure region is uppercase as expected by protobuf
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message for UID %s, region %s.", uid, region)
            return {"error": "Failed to prepare request data"}, 500

        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed for UID %s.", uid)
            return {"error": "Failed to encrypt request data"}, 500

        tokens = load_tokens(server_name)
        if tokens is None or not tokens:
            app.logger.error("Failed to load tokens for server %s.", server_name)
            return {"error": "Failed to load authentication tokens"}, 500

        tasks = []
        # Send 100 requests, cycling through available tokens
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for r in results if isinstance(r, int) and r == 200)
        failure_count = len(results) - success_count
        app.logger.info(f"Sent 100 like requests for UID {uid} in {server_name}. Success: {success_count}, Failures: {failure_count}.")

        # Return a summary of the results
        return {
            "message": f"Attempted to send 100 likes to UID {uid} in {server_name}.",
            "success_count": success_count,
            "failure_count": failure_count
        }, 200
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests for UID {uid}, server {server_name}: {e}")
        return {"error": f"An internal server error occurred: {str(e)}"}, 500

# --- Functions for Player Info Retrieval (not used by /like but kept as per original code) ---

def create_protobuf(uid):
    """Creates a protobuf message for UID generation (likely for player info)."""
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    """Encrypts a UID protobuf message."""
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def decode_protobuf(binary):
    """Decodes binary data into a like_count_pb2.Info protobuf message."""
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

def make_request(encrypt, server_name, token):
    """
    Makes a request to GetPlayerPersonalShow (likely for retrieving player info).
    Note: This is a synchronous function and is not used by the async /like endpoint.
    """
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else: # Default for BD and others
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
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10) # Added timeout
        response.raise_for_status() # Raise an exception for bad status codes

        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None for make_request.")
            return None
        return decode
    except requests.exceptions.Timeout:
        app.logger.error(f"Request to {url} timed out.")
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"HTTP Request error in make_request: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# --- API Key Management Functions ---

def authenticate_key(api_key, allow_owner=False):
    """
    Checks if an API key exists, is active, not expired, and has remaining requests.
    If allow_owner is True, the OWNER_API_KEY is also considered valid.
    Returns key data if valid, None otherwise.
    """
    if allow_owner and api_key == OWNER_API_KEY:
        return {"key": OWNER_API_KEY, "is_owner": True}

    key_data = keys_collection.find_one({"key": api_key})
    if not key_data:
        app.logger.warning(f"Authentication failed: Key '{api_key}' not found.")
        return None

    if not key_data.get("is_active"):
        app.logger.warning(f"Authentication failed: Key '{api_key}' is inactive.")
        return None

    if "expires_at" in key_data and key_data["expires_at"] < datetime.utcnow():
        app.logger.warning(f"Authentication failed: Key '{api_key}' has expired.")
        # Optionally, mark key as inactive if expired
        keys_collection.update_one({"key": api_key}, {"$set": {"is_active": False}})
        return None

    if key_data.get("remaining_requests", 0) <= 0:
        app.logger.warning(f"Authentication failed: Key '{api_key}' has no remaining requests.")
        return None

    return key_data

def update_key_usage(api_key, decrement=1):
    """Decrement remaining requests count for a key."""
    try:
        keys_collection.update_one(
            {"key": api_key, "is_active": True}, # Only update active keys
            {
                "$inc": {"remaining_requests": -decrement},
                "$set": {"last_used": datetime.utcnow()}
            }
        )
        app.logger.info(f"Key '{api_key}' usage updated. Decremented by {decrement}.")
    except Exception as e:
        app.logger.error(f"Error updating key usage for '{api_key}': {e}")

# --- API Endpoints ---

@app.route('/api/key/create', methods=['POST'])
def create_key():
    """
    Endpoint to create a new API key.
    Requires OWNER_API_KEY for authorization.
    """
    owner_api_key = request.headers.get('X-API-KEY')
    if owner_api_key != OWNER_API_KEY:
        return jsonify({"error": "Unauthorized. Owner API key required."}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    custom_key = data.get('custom_key')
    try:
        total_requests = int(data.get('total_requests', 1000))
        if total_requests <= 0:
            return jsonify({"error": "total_requests must be a positive integer"}), 400
    except ValueError:
        return jsonify({"error": "total_requests must be an integer"}), 400

    try:
        expiry_days = int(data.get('expiry_days', 30))
        if expiry_days <= 0:
            return jsonify({"error": "expiry_days must be a positive integer"}), 400
    except ValueError:
        return jsonify({"error": "expiry_days must be an integer"}), 400

    notes = data.get('notes', '')

    if custom_key:
        if keys_collection.find_one({"key": custom_key}):
            return jsonify({"error": "Custom API key already exists"}), 409
        api_key = custom_key
    else:
        # Generate a random API key
        api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        while keys_collection.find_one({"key": api_key}): # Ensure uniqueness
            api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

    expires_at = datetime.utcnow() + timedelta(days=expiry_days)

    new_key_data = {
        "key": api_key,
        "total_requests": total_requests,
        "remaining_requests": total_requests,
        "created_at": datetime.utcnow(),
        "expires_at": expires_at,
        "is_active": True,
        "notes": notes,
        "last_used": None
    }
    keys_collection.insert_one(new_key_data)
    app.logger.info(f"New API key created: {api_key}")
    return jsonify({
        "message": "API key created successfully",
        "key": api_key,
        "total_requests": total_requests,
        "remaining_requests": total_requests,
        "expires_at": expires_at.isoformat(),
        "is_active": True,
        "notes": notes
    }), 201

@app.route('/api/key/check', methods=['GET'])
def check_key():
    """
    Check the status and details of an API key.
    Can be used with any valid API key (user or owner).
    """
    api_key = request.headers.get('X-API-KEY') or request.args.get('key')
    if not api_key:
        return jsonify({"error": "API key is required"}), 401

    if api_key == OWNER_API_KEY:
        return jsonify({
            "key": OWNER_API_KEY,
            "message": "This is the owner key with unlimited access.",
            "is_owner": True
        }), 200

    key_data = keys_collection.find_one({"key": api_key})
    if not key_data:
        return jsonify({"error": "API key not found"}), 404

    # Convert ObjectId to string for JSON serialization
    key_data['_id'] = str(key_data['_id'])
    # Convert datetime objects to ISO format strings
    for k in ["created_at", "expires_at", "last_used"]:
        if k in key_data and isinstance(key_data[k], datetime):
            key_data[k] = key_data[k].isoformat()

    return jsonify(key_data), 200

@app.route('/api/key/remove', methods=['DELETE'])
def remove_key():
    """
    Remove an API key (marks it as inactive).
    Requires OWNER_API_KEY for authorization.
    """
    owner_api_key = request.headers.get('X-API-KEY')
    if owner_api_key != OWNER_API_KEY:
        return jsonify({"error": "Unauthorized. Owner API key required."}), 401

    api_key_to_remove = request.args.get('key')
    if not api_key_to_remove:
        return jsonify({"error": "API key to remove is required as a query parameter 'key'"}), 400

    if api_key_to_remove == OWNER_API_KEY:
        return jsonify({"error": "Cannot remove the owner API key"}), 403

    result = keys_collection.update_one(
        {"key": api_key_to_remove},
        {"$set": {"is_active": False, "removed_at": datetime.utcnow()}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "API key not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"message": "API key was already inactive or no change needed."}), 200
    else:
        app.logger.info(f"API key '{api_key_to_remove}' marked as inactive.")
        return jsonify({"message": f"API key '{api_key_to_remove}' has been marked as inactive"}), 200

@app.route('/api/key/update', methods=['PUT'])
def update_key():
    """
    Update an API key's properties (total_requests, expiry_days, is_active, notes).
    Requires OWNER_API_KEY for authorization.
    """
    owner_api_key = request.headers.get('X-API-KEY')
    if owner_api_key != OWNER_API_KEY:
        return jsonify({"error": "Unauthorized. Owner API key required."}), 401

    api_key_to_update = request.args.get('key')
    if not api_key_to_update:
        return jsonify({"error": "API key to update is required as a query parameter 'key'"}), 400

    if api_key_to_update == OWNER_API_KEY:
        return jsonify({"error": "Cannot update the owner API key via this endpoint"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    update_fields = {}
    if 'total_requests' in data:
        try:
            total_requests = int(data['total_requests'])
            if total_requests <= 0:
                return jsonify({"error": "total_requests must be a positive integer"}), 400
            update_fields["total_requests"] = total_requests
            # If total_requests is updated, optionally reset remaining to new total
            update_fields["remaining_requests"] = total_requests
        except ValueError:
            return jsonify({"error": "total_requests must be an integer"}), 400

    if 'expiry_days' in data:
        try:
            expiry_days = int(data['expiry_days'])
            if expiry_days <= 0:
                return jsonify({"error": "expiry_days must be a positive integer"}), 400
            update_fields["expires_at"] = datetime.utcnow() + timedelta(days=expiry_days)
        except ValueError:
            return jsonify({"error": "expiry_days must be an integer"}), 400

    if 'is_active' in data:
        if not isinstance(data['is_active'], bool):
            return jsonify({"error": "is_active must be a boolean"}), 400
        update_fields["is_active"] = data['is_active']

    if 'notes' in data:
        update_fields["notes"] = str(data['notes'])

    if not update_fields:
        return jsonify({"message": "No valid fields provided for update"}), 200

    result = keys_collection.update_one({"key": api_key_to_update}, {"$set": update_fields})

    if result.matched_count == 0:
        return jsonify({"error": "API key not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"message": "API key found but no changes applied (perhaps values were identical).", "key": api_key_to_update}), 200
    else:
        app.logger.info(f"API key '{api_key_to_update}' updated with fields: {list(update_fields.keys())}")
        updated_key_data = keys_collection.find_one({"key": api_key_to_update})
        updated_key_data['_id'] = str(updated_key_data['_id']) # For JSON serialization
        for k in ["created_at", "expires_at", "last_used"]:
             if k in updated_key_data and isinstance(updated_key_data[k], datetime):
                 updated_key_data[k] = updated_key_data[k].isoformat()
        return jsonify({"message": f"API key '{api_key_to_update}' updated successfully", "updated_key": updated_key_data}), 200

@app.route('/like', methods=['GET'])
async def handle_requests():
    """
    Endpoint to send 'likes' to a Free Fire player.
    Requires a valid user API key, UID, and server name.
    Example: /like?uid=1855692619&server_name=ind&key=YOUR_API_KEY
    """
    api_key = request.args.get('key')
    uid = request.args.get('uid')
    server_name = request.args.get('server_name')

    if not api_key:
        return jsonify({"error": "API key is required"}), 401
    if not uid:
        return jsonify({"error": "User ID (uid) is required"}), 400
    if not server_name:
        return jsonify({"error": "Server name (server_name) is required"}), 400

    # Validate API Key
    key_data = authenticate_key(api_key, allow_owner=False) # Owner key cannot be used for user actions
    if not key_data:
        # authenticate_key already logs specific failure reasons
        return jsonify({"error": "Invalid, inactive, or expired API key, or no requests remaining."}), 403

    # Determine the target URL based on server_name
    if server_name.upper() == "IND":
        target_url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name.upper() in {"BR", "US", "SAC", "NA"}:
        target_url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else: # Default for BD and any other server
        target_url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    try:
        # Perform the async request operation
        # send_multiple_requests returns (response_data, status_code)
        response_data, status_code = await send_multiple_requests(uid, server_name, target_url)

        # If requests were attempted (even if all failed), decrement usage.
        # This design choice reflects that the API service was used to *attempt* sending likes.
        if status_code == 200 or ("success_count" in response_data and response_data["success_count"] > 0):
             update_key_usage(api_key, decrement=1)
             app.logger.info(f"Successfully processed like request for UID {uid} using key {api_key}. Remaining requests: {key_data['remaining_requests'] - 1 if 'remaining_requests' in key_data else 'N/A'}")

        return jsonify(response_data), status_code

    except Exception as e:
        app.logger.error(f"Unhandled exception in /like for UID {uid}, server {server_name}: {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    # It's good practice to run in production using a WSGI server like Gunicorn,
    # but for local development, this is fine.
    # Set debug=False in production for security.
    app.run(debug=True, host='0.0.0.0', port=5000)
