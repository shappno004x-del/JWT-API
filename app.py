#!/usr/bin/env python3
"""
JWT Generator API – uses the same logic as the Long Bio API.
Endpoints:
  GET /token?access_token=<access_token>
  GET /token?uid=<uid>&password=<password>
Port: 5002
"""

import logging
from flask import Flask, request, jsonify
import requests
import binascii
import jwt
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# Import the necessary protobuf modules (must exist in the same directory)
try:
    import my_pb2
    import output_pb2
except ImportError:
    logging.error("my_pb2 or output_pb2 not found – cannot start API")
    exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ---------- Constants (same as long bio API) ----------
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
FREEFIRE_VERSION = "OB53"

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION
}

# ---------- Helper functions ----------
def encrypt_data(data_bytes):
    """AES-CBC encrypt with the hardcoded KEY and IV."""
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

def get_name_region_from_reward(access_token):
    """Fetch UID, name, region from the reward API using access_token."""
    try:
        url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        headers = {
            "authority": "prod-api.reward.ff.garena.com",
            "method": "GET",
            "path": "/redemption/api/auth/inspect_token/",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "access-token": access_token,
            "cookie": "_gid=GA1.2.444482899.1724033242; _ga_XB5PSHEQB4=GS1.1.1724040177.1.1.1724040732.0.0.0; token_session=cb73a97aaef2f1c7fd138757dc28a08f92904b1062e66c; _ga_KE3SY7MRSD=GS1.1.1724041788.0.0.1724041788.0; _ga_RF9R6YT614=GS1.1.1724041788.0.0.1724041788.0; _ga=GA1.1.1843180339.1724033241; apple_state_key=817771465df611ef8ab00ac8aa985783; _ga_G8QGMJPWWV=GS1.1.1724049483.1.1.1724049880.0.0; datadome=HBTqAUPVsbBJaOLirZCUkN3rXjf4gRnrZcNlw2WXTg7bn083SPey8X~ffVwr7qhtg8154634Ee9qq4bCkizBuiMZ3Qtqyf3Isxmsz6GTH_b6LMCKWF4Uea_HSPk;",
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "sec-ch-ua": '"Not.A/Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, verify=False, timeout=10)
        data = resp.json()
        return data.get("uid"), data.get("name"), data.get("region")
    except Exception as e:
        logging.error(f"Reward API error: {e}")
        return None, None, None

def get_openid_from_shop2game(uid):
    """Retrieve open_id from Shop2Game API using UID."""
    if not uid:
        return None
    try:
        url = "https://topup.pk/api/auth/player_id_login"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-MM,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/json",
            "Origin": "https://topup.pk",
            "Referer": "https://topup.pk/",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Android WebView";v="138"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5070 Build/UKQ1.231108.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
            "X-Requested-With": "mark.via.gp",
            "Cookie": "source=mb; region=PK; mspid2=13c49fb51ece78886ebf7108a4907756; _fbp=fb.1.1753985808817.794945392376454660; language=en; datadome=WQaG3HalUB3PsGoSXY3TdcrSQextsSFwkOp1cqZtJ7Ax4YkiERHUgkgHlEAIccQO~w8dzTGM70D9SzaH7vymmEqOrVeX5pIsPVE22Uf3TDu6W3WG7j36ulnTg2DltRO7; session_key=hq02g63z3zjcumm76mafcooitj7nc79y",
        }
        payload = {"app_id": 100067, "login_id": str(uid)}
        resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        data = resp.json()
        return data.get("open_id")
    except Exception as e:
        logging.error(f"Shop2Game API error: {e}")
        return None

def perform_major_login(access_token, open_id):
    """Send MajorLogin request and return the JWT token."""
    platforms = [8, 3, 4, 6]  # try multiple platform types
    for platform_type in platforms:
        try:
            game_data = my_pb2.GameData()
            game_data.timestamp = "2024-12-05 18:15:32"
            game_data.game_name = "free fire"
            game_data.game_version = 1
            game_data.version_code = "1.120.2"
            game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game_data.device_type = "Handheld"
            game_data.network_provider = "Verizon Wireless"
            game_data.connection_type = "WIFI"
            game_data.screen_width = 1280
            game_data.screen_height = 960
            game_data.dpi = "240"
            game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game_data.total_ram = 5951
            game_data.gpu_name = "Adreno (TM) 640"
            game_data.gpu_version = "OpenGL ES 3.0"
            game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            game_data.ip_address = "172.190.111.97"
            game_data.language = "en"
            game_data.open_id = open_id
            game_data.access_token = access_token
            game_data.platform_type = platform_type
            game_data.field_99 = str(platform_type)
            game_data.field_100 = str(platform_type)

            serialized = game_data.SerializeToString()
            encrypted = encrypt_data(serialized)
            hex_encrypted = binascii.hexlify(encrypted).decode()
            edata = bytes.fromhex(hex_encrypted)

            resp = requests.post(MAJOR_LOGIN_URL, data=edata, headers=LOGIN_HEADERS,
                                 verify=False, timeout=10)
            if resp.status_code == 200:
                try:
                    msg = output_pb2.Garena_420()
                    msg.ParseFromString(resp.content)
                    # search for the 'token' field
                    for field in msg.DESCRIPTOR.fields:
                        if field.name == "token":
                            return getattr(msg, field.name)
                except Exception:
                    pass
        except Exception as e:
            logging.error(f"MajorLogin attempt failed for platform {platform_type}: {e}")
            continue
    return None

def perform_guest_login(uid, password):
    """Perform guest login to obtain access_token and open_id."""
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive"
    }
    try:
        resp = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=10, verify=False)
        data = resp.json()
        if 'access_token' in data:
            return data['access_token'], data.get('open_id')
    except Exception as e:
        logging.error(f"Guest login failed: {e}")
    return None, None

@app.route('/')
def index():
    return jsonify({
        "api": "JWT Generator API",
        "credit": "MG24 GAMER",
        "telegram": "@MG24_CODEX",
        "endpoints": {
            "/token": {
                "method": "GET",
                "parameters": {
                    "access_token": "string (optional, alternative: uid+password)",
                    "uid": "string (optional, requires password)",
                    "password": "string (optional, requires uid)"
                },
                "example1": "/token?access_token=xxxxxxxx",
                "example2": "/token?uid=12345&password=mypass"
            }
        },
        "note": "JWT token is returned in the 'token' field of the response."
    })

# ---------- API Endpoint ----------
@app.route('/token', methods=['GET'])
def token_endpoint():
    access_token = request.args.get('access_token')
    uid = request.args.get('uid')
    password = request.args.get('password')

    if access_token:
        logging.info("Generating JWT from access_token")
        uid_found, name, region = get_name_region_from_reward(access_token)
        if not uid_found:
            return jsonify({"status": "error", "message": "Invalid access_token"}), 400
        open_id = get_openid_from_shop2game(uid_found)
        if not open_id:
            return jsonify({"status": "error", "message": "Could not fetch open_id"}), 400
        jwt_token = perform_major_login(access_token, open_id)
        if jwt_token:
            return jsonify({"status": "success", "token": jwt_token, "uid": uid_found, "open_id": open_id})
        else:
            return jsonify({"status": "error", "message": "JWT generation failed"}), 500

    elif uid and password:
        logging.info(f"Generating JWT for UID: {uid}")
        acc_token, open_id = perform_guest_login(uid, password)
        if not acc_token or not open_id:
            return jsonify({"status": "error", "message": "Guest login failed"}), 401
        jwt_token = perform_major_login(acc_token, open_id)
        if jwt_token:
            return jsonify({"status": "success", "token": jwt_token, "uid": uid, "open_id": open_id})
        else:
            return jsonify({"status": "error", "message": "JWT generation failed"}), 500

    else:
        return jsonify({
            "status": "error",
            "message": "Provide 'access_token' or both 'uid' and 'password'."
        }), 400

# ---------- Main ----------
if __name__ == "__main__":
    logging.info("Starting JWT Generator API on port 5002")
    app.run(host="0.0.0.0", port=5002, debug=False, use_reloader=False)