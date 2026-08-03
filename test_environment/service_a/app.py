
import os
import time
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = os.getenv("JWT_SECRET", "test-secret-key-for-development")
JWT_VALIDATION = os.getenv("JWT_VALIDATION", "true").lower() == "true"

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "auth"}), 200

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    payload = {"sub": data.get("username", "test_user"), "role": data.get("role", "user"),
               "iat": int(time.time()), "exp": int(time.time()) + 3600}
    return jsonify({"token": jwt.encode(payload, JWT_SECRET, algorithm="HS256")}), 200

@app.route("/auth/verify")
def verify():
    if not JWT_VALIDATION:                       # neaizsargata: validacija atslegta
        return jsonify({"valid": True, "payload": {"sub": "unverified", "role": "user"}}), 200
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({"valid": True, "payload": payload}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidSignatureError:
        return jsonify({"error": "Invalid signature"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)