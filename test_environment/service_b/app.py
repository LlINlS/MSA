# merka pakalpojums ar jwt validaciju

import os
import time
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = os.getenv("JWT_SECRET", "test-secret-key-for-development")

ORDERS = [
    {"id": 1, "item": "Laptop", "user": "alice", "amount": 999.99},
    {"id": 2, "item": "Phone", "user": "bob", "amount": 499.99},
]

REQUEST_LOG = []
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"

def verify_token(required_role=None):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, (jsonify({"error": "Missing Authorization header"}), 401)
    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"error": "Token expired"}), 401)
    except jwt.InvalidSignatureError:
        return None, (jsonify({"error": "Invalid signature"}), 401)
    except jwt.InvalidTokenError as e:
        return None, (jsonify({"error": str(e)}), 401)
    if required_role and payload.get("role") != required_role:
        return None, (jsonify({"error": "Insufficient permissions"}), 403)
    return payload, None

@app.before_request
def rate_limiter():
    if not RATE_LIMIT_ENABLED or request.path == "/health":
        return
    now = time.time()
    REQUEST_LOG[:] = [t for t in REQUEST_LOG if now - t < 60]
    if len(REQUEST_LOG) >= RATE_LIMIT:
        return jsonify({"error": "Rate limit exceeded"}), 429
    REQUEST_LOG.append(now)

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "orders"}), 200

@app.route("/orders")
def get_orders():
    payload, error = verify_token()
    if error:
        return error
    return jsonify({"orders": ORDERS}), 200

@app.route("/orders", methods=["POST"])
def create_order():
    payload, error = verify_token(required_role="admin")
    if error:
        return error
    data = request.get_json() or {}
    new_order = {"id": len(ORDERS) + 1, "item": data.get("item"), "user": payload["sub"], "amount": data.get("amount", 0)}
    ORDERS.append(new_order)
    return jsonify({"order": new_order}), 201

@app.route("/orders/search")
def search_orders():
    query = request.args.get("q", "")
    if any(kw in query.upper() for kw in ["DROP", "DELETE", "INSERT", "UPDATE", "--", ";"]):
        if os.getenv("INPUT_VALIDATION", "true").lower() == "true":
            return jsonify({"error": "Potentially malicious input detected"}), 400
        else:
            return jsonify({"warning": "Query executed without validation", "query": query}), 200
    results = [o for o in ORDERS if query.lower() in o["item"].lower()]
    return jsonify({"results": results}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)