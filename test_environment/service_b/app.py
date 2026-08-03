# merka pakalpojums: JWT validacija, tempa ierobezosana, ievades validacija, noslepumu parvaldiba
import os
import time
import traceback
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", "test-secret-key-for-development")
JWT_VALIDATION = os.getenv("JWT_VALIDATION", "true").lower() == "true"
INPUT_VALIDATION = os.getenv("INPUT_VALIDATION", "true").lower() == "true"
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "10"))
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

ORDERS = [
    {"id": 1, "item": "Laptop", "user": "alice", "amount": 999.99},
    {"id": 2, "item": "Phone", "user": "bob", "amount": 499.99},
]
ADMIN_USERS = {"admin", "root"}          
REQUEST_LOG = []
RATE_LIMITED_PATHS = {"/ping"}           # tempa ierobezosana TIKAI seit -> neietekme AUTH/INJ
SQL_PATTERNS = ["DROP", "DELETE", "INSERT", "UPDATE", "UNION", "SELECT", "--", ";", "'", "="]

def verify_token(required_role=None):
    if not JWT_VALIDATION:                # NEAIZSARGATA: validacija atslegta -> viss iet cauri
        return {"sub": "unverified", "role": required_role or "user"}, None
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
    if required_role == "admin":
        if payload.get("role") != "admin" or payload.get("sub") not in ADMIN_USERS:
            return None, (jsonify({"error": "Insufficient permissions"}), 403)
    elif required_role and payload.get("role") != required_role:
        return None, (jsonify({"error": "Insufficient permissions"}), 403)
    return payload, None


@app.before_request
def rate_limiter():
    if not RATE_LIMIT_ENABLED or request.path not in RATE_LIMITED_PATHS:
        return
    now = time.time()
    REQUEST_LOG[:] = [t for t in REQUEST_LOG if now - t < 60]
    if len(REQUEST_LOG) >= RATE_LIMIT:
        return jsonify({"error": "Rate limit exceeded"}), 429
    REQUEST_LOG.append(now)


@app.after_request
def leak_headers(resp):
    if DEBUG_MODE:
        resp.headers["X-Powered-By"] = "Flask/Werkzeug"
        resp.headers["X-Debug"] = "true"
    return resp


@app.route("/ping")
def ping():
    return jsonify({"pong": True}), 200


@app.route("/internal/reset", methods=["POST"])
def reset_state():
    REQUEST_LOG.clear()
    return jsonify({"reset": True}), 200


@app.route("/health")
def health():
    body = {"status": "healthy", "service": "orders"}
    if DEBUG_MODE:                        # env_exposure: atklaj vides mainigos
        body["config"] = {
            "JWT_SECRET": JWT_SECRET,
            "RATE_LIMIT": RATE_LIMIT,
            "DATABASE_URL": os.getenv("DATABASE_URL", "postgres://user:password@db:5432/orders"),
        }
    return jsonify(body), 200


@app.route("/config")
def config_endpoint():
    if not DEBUG_MODE:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"jwt_secret": JWT_SECRET, "rate_limit": RATE_LIMIT, "env": dict(os.environ)}), 200


@app.route("/orders")
def get_orders():
    payload, error = verify_token()
    if error:
        return error
    return jsonify({"orders": ORDERS}), 200


@app.route("/orders", methods=["POST"])
def create_order():
    try:
        data = request.get_json(force=True)
    except Exception as e:
        if DEBUG_MODE:
            return jsonify({
                "error": str(e),
                "trace": traceback.format_exc(),
                "jwt_secret": JWT_SECRET,
                "database_connection_string": "postgres://user:password@db:5432",
            }), 400
        return jsonify({"error": "Bad request"}), 400
    payload, error = verify_token(required_role="admin")
    if error:
        return error
    data = data or {}
    new_order = {"id": len(ORDERS) + 1, "item": data.get("item"),
                 "user": payload["sub"], "amount": data.get("amount", 0)}
    ORDERS.append(new_order)
    return jsonify({"order": new_order}), 201


@app.route("/orders/search")
def search_orders():
    query = request.args.get("q", "")
    # kluda ja q pa lielu
    if len(query) > 1000:
        if DEBUG_MODE:
            return jsonify({
                "error": "Query processing failed",
                "trace": 'Traceback (most recent call last):\n  File "app.py", line 90, in search_orders\n    raise ValueError(query)\nValueError',
            }), 500
        return jsonify({"error": "Bad request"}), 400
    is_malicious = any(p in query.upper() for p in SQL_PATTERNS)
    if is_malicious:
        if INPUT_VALIDATION:
            return jsonify({"error": "Potentially malicious input detected"}), 400
        return jsonify({"warning": "Query executed without validation", "query": query}), 200
    results = [o for o in ORDERS if query.lower() in o["item"].lower()]
    return jsonify({"results": results}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)