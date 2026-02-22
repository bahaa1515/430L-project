import os
from dotenv import load_dotenv
import math
from flask import Flask, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from sqlalchemy.sql import func
from datetime import datetime, timedelta
import csv
import io
import json
from functools import wraps
from typing import Optional, Dict, Any


# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)

# Read DB config from .env
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "exchange")

# Build SQLAlchemy URI (no hardcoded secrets)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT config
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-only-change-me")

# Phase 5: token lifetimes (using timedelta for clarity)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)
CORS(app)
jwt = JWTManager(app)

# Phase 5: simple in-memory token blocklist (logout)
jwt_blocklist = set()
jwt_refresh_blocklist = set()  # FIX B: Separate blocklist for refresh tokens



@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    # FIX B: Check token type and use appropriate blocklist
    jti = jwt_payload["jti"]
    token_type = jwt_payload.get("type", "access")
    if token_type == "refresh":
        return jti in jwt_refresh_blocklist
    return jti in jwt_blocklist


db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ----------------------------
# Models
# ----------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)

    # Phase 6: optional relationship (clean, not required)
    transactions = db.relationship("Transaction", backref="user", lazy=True)

    # STEP 8: RBAC - Role and Status tracking
    # Roles: "USER", "ADMIN"
    # Statuses: "ACTIVE", "SUSPENDED", "BANNED"
    role = db.Column(db.String(10), nullable=False, default="USER")
    status = db.Column(db.String(12), nullable=False, default="ACTIVE")

    def __init__(self, user_name, password):
        super(User, self).__init__(user_name=user_name)
        self.hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usd_amount = db.Column(db.Float, nullable=False)
    lbp_amount = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)

    # Phase 6: transaction belongs to a user
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())

class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        exclude = ("hashed_password",)

user_schema = UserSchema()

class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    creator_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    give_currency = db.Column(db.String(3), nullable=False)   # "USD" or "LBP"
    give_amount = db.Column(db.Float, nullable=False)

    want_currency = db.Column(db.String(3), nullable=False)   # "USD" or "LBP"
    want_amount = db.Column(db.Float, nullable=False)

    status = db.Column(db.String(10), nullable=False, default="OPEN")  # OPEN/CANCELLED/COMPLETED
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())


class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    offer_id = db.Column(db.Integer, db.ForeignKey("offer.id"), nullable=False)

    buyer_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    seller_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # "usd_to_lbp" or "lbp_to_usd"
    direction = db.Column(db.String(12), nullable=False)

    # "above" or "below"
    condition = db.Column(db.String(5), nullable=False)

    threshold = db.Column(db.Float, nullable=False)

    # if you want to "disable" an alert without deleting it later
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # set when it first triggers (prevents spamming)
    triggered_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())

class WatchlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # "direction" or "threshold"
    item_type = db.Column(db.String(10), nullable=False)

    # used for both types
    direction = db.Column(db.String(12), nullable=False)  # "usd_to_lbp" or "lbp_to_usd"

    # used only for threshold type (can be null for direction type)
    condition = db.Column(db.String(5), nullable=True)    # "above" or "below"
    threshold = db.Column(db.Float, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())

class UserPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)

    # Defaults used when user doesn’t pass query params
    default_range_hours = db.Column(db.Integer, nullable=False, default=72)
    default_bucket = db.Column(db.String(10), nullable=False, default="hour")

    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())
    updated_at = db.Column(db.DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

# STEP 9: Audit Logging Model
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())
    
    # Who performed the action (null for anonymous login attempts)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    actor_username = db.Column(db.String(30), nullable=True)
    
    # Target of the action (for admin actions affecting another user)
    target_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    
    # Event classification
    event_type = db.Column(db.String(50), nullable=False)  # AUTH_LOGIN_SUCCESS, TX_CREATE, etc.
    action = db.Column(db.String(20), nullable=False)      # CREATE, UPDATE, DELETE, ACCESS, AUTH, etc.
    
    # Result and HTTP context
    success = db.Column(db.Boolean, nullable=False, default=True)
    http_method = db.Column(db.String(10), nullable=True)
    path = db.Column(db.String(255), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    
    # Request metadata
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    
    # Details
    message = db.Column(db.String(255), nullable=True)
    metadata_json = db.Column(db.Text, nullable=True)  # Stored as JSON string
    
    def __repr__(self):
        return f"<AuditLog {self.id} {self.event_type} {self.created_at}>"




# Flask-Limiter (v4+ style)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

# STEP 9: Audit Logging Helpers ########################

def sanitize_metadata(data: Any) -> Any:
    """Remove sensitive keys from metadata dict/list before logging.
    Recursively sanitizes nested structures to remove sensitive data.
    Preserves structure: dict stays dict, list stays list, scalars stay scalars.
    """
    sensitive_keys = {
        'password', 'hashed_password', 'access_token', 'refresh_token',
        'token', 'authorization', 'jwt', 'secret', 'api_key'
    }
    
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            # Skip sensitive keys (case-insensitive)
            if k.lower() in sensitive_keys:
                continue
            # Recursively sanitize nested structures
            result[k] = sanitize_metadata(v)
        return result
    
    if isinstance(data, list):
        # Recursively sanitize list items
        return [sanitize_metadata(item) for item in data]
    
    # Return scalars unchanged
    return data

def write_audit_log(
    event_type: str,
    action: str,
    success: bool = True,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    target_user_id: Optional[int] = None,
    status_code: Optional[int] = None,
    message: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Safely write an audit log entry. Never raises; logs warnings if it fails.
    STEP 9: Immutable append-only logging.
    """
    try:
        # Sanitize metadata
        safe_metadata = sanitize_metadata(metadata) if metadata else {}
        metadata_str = None
        if safe_metadata:
            metadata_str = json.dumps(safe_metadata)
        
        # Capture request context
        http_method = request.method if request else None
        path = request.path if request else None
        user_agent = request.user_agent.string if request and request.user_agent else None
        # STEP 9 FIX: Use get_remote_address() for proxy-safe IP detection
        ip_address = get_remote_address() if request else None
        
        # Create and insert log
        log_entry = AuditLog(
            event_type=event_type,
            action=action,
            success=success,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            target_user_id=target_user_id,
            status_code=status_code,
            message=message,
            metadata_json=metadata_str,
            http_method=http_method,
            path=path,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # Never break the application due to logging failure
        print(f"[WARNING] Audit log write failed: {type(e).__name__}: {str(e)}", flush=True)

# step 1 helper functionss##########################

def parse_iso_datetime(s):
    # Accepts "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SS"
    # output real datetime objects to filter DB
    try:
        if len(s) == 10:
            return datetime.fromisoformat(s + "T00:00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None

def compute_rate(t: Transaction):
    # rate in LBP per USD for usd_to_lbp transactions
    # and USD per LBP for lbp_to_usd transactions
    if t.usd_to_lbp:
        return t.lbp_amount / t.usd_amount
    return t.usd_amount / t.lbp_amount

#step 2 helper functions #####################################

def bucket_start(dt: datetime, bucket: str):
    if bucket == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return None

#step 3 helper functions #####################################

def valid_currency(c):
    return c in ["USD", "LBP"]

#step 4 helper functions #####################################
def valid_direction(d):
    return d in ["usd_to_lbp", "lbp_to_usd"]

def valid_condition(c):
    return c in ["above", "below"]

def compute_current_rate_for_user(user_id: int, direction: str):
    """
    Uses the same logic as /exchangeRate (last 72 hours),
    but returns a single float for the selected direction.
    """
    # Use datetime.now() instead of utcnow() to match MySQL NOW() timezone
    cutoff = datetime.now() - timedelta(hours=72)

    usd_to_lbp_bool = (direction == "usd_to_lbp")

    txns = (
        Transaction.query
        .filter_by(user_id=user_id, usd_to_lbp=usd_to_lbp_bool)
        .filter(Transaction.created_at >= cutoff)
        .all()
    )

    if not txns:
        return None

    if usd_to_lbp_bool:
        total_usd = sum(t.usd_amount for t in txns)
        total_lbp = sum(t.lbp_amount for t in txns)
        if total_usd <= 0:
            return None
        return total_lbp / total_usd
    else:
        total_usd = sum(t.usd_amount for t in txns)
        total_lbp = sum(t.lbp_amount for t in txns)
        if total_lbp <= 0:
            return None
        return total_usd / total_lbp

#step 5 helper functions #####################################
def valid_watchlist_type(t):
    return t in ["direction", "threshold"]        

#step 7 helper functions #####################################
def get_or_create_preferences(user_id: int) -> UserPreferences:
    prefs = UserPreferences.query.filter_by(user_id=user_id).first()
    if not prefs:
        prefs = UserPreferences(user_id=user_id, default_range_hours=72, default_bucket="hour")
        db.session.add(prefs)
        db.session.commit()
    return prefs

# STEP 8: RBAC Decorators ################################

# FIX A: Active user decorator (blocks suspended/banned users immediately)
def active_user_required(fn):
    """Decorator: Requires active user account"""
    @wraps(fn)
    @jwt_required()
    def decorator(*args, **kwargs):
        uid = int(get_jwt_identity())
        user = User.query.get(uid)
        if not user or user.status != "ACTIVE":
            return jsonify({"error": "Account is not active"}), 403
        return fn(*args, **kwargs)
    return decorator

def admin_required(fn):
    """Decorator: Requires admin role (FIX C: validates DB)"""
    @wraps(fn)
    @jwt_required()
    def decorator(*args, **kwargs):
        uid = int(get_jwt_identity())
        user = User.query.get(uid)
        if not user or user.role != "ADMIN":
            return jsonify({"error": "Admin only"}), 403
        if user.status != "ACTIVE":
            return jsonify({"error": "Account is not active"}), 403
        return fn(*args, **kwargs)
    return decorator

def admin_fresh_required(fn):
    """Decorator: Requires admin role + fresh token (FIX C: validates DB)"""
    @wraps(fn)
    @jwt_required(fresh=True)
    def decorator(*args, **kwargs):
        uid = int(get_jwt_identity())
        user = User.query.get(uid)
        if not user or user.role != "ADMIN":
            return jsonify({"error": "Admin only"}), 403
        if user.status != "ACTIVE":
            return jsonify({"error": "Account is not active"}), 403
        return fn(*args, **kwargs)
    return decorator

###########################################################
# ----------------------------
# Auth endpoints (Phase 4/5)
# ----------------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        # STEP 9: Log failed login - missing body
        write_audit_log(
            event_type="AUTH_LOGIN_FAIL",
            action="AUTH",
            success=False,
            message="Missing JSON body",
            metadata={"failure_reason": "missing_body"}
        )
        return jsonify({"error": "Missing JSON body"}), 400

    user_name = data.get("user_name")
    password = data.get("password")

    if not user_name or not password:
        # STEP 9: Log failed login - missing fields
        write_audit_log(
            event_type="AUTH_LOGIN_FAIL",
            action="AUTH",
            success=False,
            actor_username=user_name,
            message="Missing required fields",
            metadata={"failure_reason": "missing_fields", "attempted_username": user_name}
        )
        return jsonify({"error": "Missing fields: user_name, password"}), 400

    user = User.query.filter_by(user_name=user_name).first()
    
    # STEP 9 FIX: Separate logic for user not found vs password wrong
    # This allows users to see their own failed login attempts in /logs
    if not user:
        # User doesn't exist: actor_user_id=None (can't track them in their logs)
        write_audit_log(
            event_type="AUTH_LOGIN_FAIL",
            action="AUTH",
            success=False,
            actor_username=user_name,
            message="Invalid credentials (user not found)",
            metadata={"failure_reason": "invalid_credentials", "attempted_username": user_name}
        )
        return jsonify({"error": "Invalid credentials"}), 401
    
    if not bcrypt.check_password_hash(user.hashed_password, password):
        # User exists but password wrong: track as their failed attempt
        write_audit_log(
            event_type="AUTH_LOGIN_FAIL",
            action="AUTH",
            success=False,
            actor_user_id=user.id,
            actor_username=user.user_name,
            message="Invalid credentials (wrong password)",
            metadata={"failure_reason": "invalid_credentials", "attempted_username": user_name}
        )
        return jsonify({"error": "Invalid credentials"}), 401

    # STEP 8: Check account status before allowing login
    if user.status != "ACTIVE":
        error_msg = "Account is suspended" if user.status == "SUSPENDED" else "Account is banned"
        # STEP 9: Log failed login - account not active
        write_audit_log(
            event_type="AUTH_LOGIN_FAIL",
            action="AUTH",
            success=False,
            actor_user_id=user.id,
            actor_username=user.user_name,
            message=error_msg,
            metadata={"failure_reason": user.status.lower(), "attempted_username": user.user_name}
        )
        return jsonify({"error": error_msg}), 403

    identity = str(user.id)
    # STEP 8: Include role in JWT claims
    access_token = create_access_token(identity=identity, additional_claims={"role": user.role}, fresh=True)
    refresh_token = create_refresh_token(identity=identity)

    # STEP 9: Log successful login
    write_audit_log(
        event_type="AUTH_LOGIN_SUCCESS",
        action="AUTH",
        success=True,
        actor_user_id=user.id,
        actor_username=user.user_name,
        status_code=200,
        metadata={"username": user.user_name}
    )

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    user = User.query.get(int(identity))
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user.status != "ACTIVE":
        return jsonify({"error": "Account is not active"}), 403
    
    new_access_token = create_access_token(identity=identity, additional_claims={"role": user.role})
    return jsonify({"access_token": new_access_token}), 200


@app.route("/logout", methods=["POST"])
@active_user_required
def logout():
    current_user_id = int(get_jwt_identity())
    jti = get_jwt()["jti"]
    jwt_blocklist.add(jti)
    
    # STEP 9: Log successful logout
    write_audit_log(
        event_type="AUTH_LOGOUT",
        action="AUTH",
        success=True,
        actor_user_id=current_user_id,
        status_code=200
    )
    
    return jsonify({"message": "Successfully logged out"}), 200


@app.route("/logout_refresh", methods=["POST"])
@jwt_required(refresh=True)
def logout_refresh():
    """FIX B: Revoke refresh token explicitly"""
    current_user_id = int(get_jwt_identity())
    jti = get_jwt()["jti"]
    jwt_refresh_blocklist.add(jti)
    
    # STEP 9: Log refresh token revocation
    write_audit_log(
        event_type="AUTH_LOGOUT_REFRESH",
        action="AUTH",
        success=True,
        actor_user_id=current_user_id,
        status_code=200
    )
    
    return jsonify({"message": "Refresh token revoked"}), 200


# ----------------------------
# User creation (Phase 3)
# ----------------------------

@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    user_name = data.get("user_name")
    password = data.get("password")
    if not user_name or not password:
        return jsonify({"error": "Missing fields: user_name, password"}), 400

    existing = User.query.filter_by(user_name=user_name).first()
    if existing:
        return jsonify({"error": "user_name already exists"}), 400

    user = User(user_name=user_name, password=password)
    db.session.add(user)
    db.session.commit()

    return jsonify(user_schema.dump(user)), 201


# ----------------------------
# Transactions (Phase 6)
# ----------------------------

@app.route("/transaction", methods=["POST"])
@limiter.limit("10 per minute")
@active_user_required
def add_transaction():
    # Phase 6: identify the logged in user
    current_user_id = int(get_jwt_identity())

    data = request.get_json(silent=True)
    if not data:
        # STEP 9: Log failed transaction - missing body
        write_audit_log(
            event_type="TX_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Missing JSON body"
        )
        return jsonify({"error": "Missing JSON body"}), 400

    if "usd_amount" not in data or "lbp_amount" not in data or "usd_to_lbp" not in data:
        # STEP 9: Log failed transaction - missing fields
        write_audit_log(
            event_type="TX_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Missing required fields"
        )
        return jsonify({"error": "Missing fields: usd_amount, lbp_amount, usd_to_lbp"}), 400

    try:
        usd_amount = float(data["usd_amount"])
        lbp_amount = float(data["lbp_amount"])
    except (TypeError, ValueError):
        # STEP 9: Log failed transaction - non-numeric amounts
        write_audit_log(
            event_type="TX_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Amounts must be numeric"
        )
        return jsonify({"error": "usd_amount and lbp_amount must be numbers"}), 400

    if not math.isfinite(usd_amount) or not math.isfinite(lbp_amount):
        # STEP 9: Log failed transaction - non-finite amounts
        write_audit_log(
            event_type="TX_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Amounts must be finite"
        )
        return jsonify({"error": "Amounts must be finite numbers"}), 400

    if usd_amount <= 0 or lbp_amount <= 0:
        # STEP 9: Log failed transaction - non-positive amounts
        write_audit_log(
            event_type="TX_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Amounts must be positive"
        )
        return jsonify({"error": "Amounts must be positive"}), 400

    usd_to_lbp = data["usd_to_lbp"]
    if usd_to_lbp not in [True, False]:
        # STEP 9: Log failed transaction - invalid boolean
        write_audit_log(
            event_type="TX_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="usd_to_lbp must be boolean"
        )
        return jsonify({"error": "usd_to_lbp must be boolean (true/false)"}), 400

    transaction = Transaction(
        usd_amount=usd_amount,
        lbp_amount=lbp_amount,
        usd_to_lbp=usd_to_lbp,
        user_id=current_user_id
    )

    db.session.add(transaction)
    db.session.commit()

    # STEP 9: Log successful transaction creation
    direction = "usd_to_lbp" if usd_to_lbp else "lbp_to_usd"
    write_audit_log(
        event_type="TX_CREATE",
        action="CREATE",
        success=True,
        actor_user_id=current_user_id,
        status_code=201,
        metadata={
            "transaction_id": transaction.id,
            "usd_amount": usd_amount,
            "lbp_amount": lbp_amount,
            "usd_to_lbp": usd_to_lbp,
            "direction": direction
        }
    )

    return jsonify({"message": "Transaction added successfully"}), 201


@app.route("/transactions", methods=["GET"])
@active_user_required
def list_transactions():
    # Phase 6: list only current user transactions
    current_user_id = int(get_jwt_identity())

    txns = (
        Transaction.query
        .filter_by(user_id=current_user_id)
        .order_by(Transaction.id.desc())
        .all()
    )

    result = []
    for t in txns:
        result.append({
            "id": t.id,
            "usd_amount": t.usd_amount,
            "lbp_amount": t.lbp_amount,
            "usd_to_lbp": t.usd_to_lbp
        })

    return jsonify(result), 200


@app.route("/exchangeRate", methods=["GET"])
@active_user_required
def get_exchange_rate():
    # Phase 6: compute rate only from current user's transactions
    current_user_id = int(get_jwt_identity())
    # Use datetime.now() instead of utcnow() to match MySQL NOW() timezone
    cutoff = datetime.now() - timedelta(hours=72)
    usd_to_lbp_txns = Transaction.query.filter_by(user_id=current_user_id, usd_to_lbp=True).filter(Transaction.created_at >= cutoff).all()
    lbp_to_usd_txns = Transaction.query.filter_by(user_id=current_user_id, usd_to_lbp=False).filter(Transaction.created_at >= cutoff).all()

    usd_to_lbp_rate = None
    lbp_to_usd_rate = None

    if usd_to_lbp_txns:
        total_usd = sum(t.usd_amount for t in usd_to_lbp_txns)
        total_lbp = sum(t.lbp_amount for t in usd_to_lbp_txns)
        if total_usd > 0:
            usd_to_lbp_rate = total_lbp / total_usd

    if lbp_to_usd_txns:
        total_usd = sum(t.usd_amount for t in lbp_to_usd_txns)
        total_lbp = sum(t.lbp_amount for t in lbp_to_usd_txns)
        if total_lbp > 0:
            lbp_to_usd_rate = total_usd / total_lbp

    return jsonify({
        "usd_to_lbp": usd_to_lbp_rate,
        "lbp_to_usd": lbp_to_usd_rate
    }), 200


#step 1
@app.route("/analytics/exchange-rate", methods=["GET"])
@active_user_required
def analytics_exchange_rate():
    current_user_id = int(get_jwt_identity())

    direction = request.args.get("direction")  # required to avoid mixing incompatible rate units

    # Direction is required to avoid mixing incompatible rate units
    if direction is None:
        return jsonify({"error": "direction is required: 'usd_to_lbp' or 'lbp_to_usd'"}), 400

    if direction not in ["usd_to_lbp", "lbp_to_usd"]:
        return jsonify({"error": "direction must be 'usd_to_lbp' or 'lbp_to_usd'"}), 400

    from_str = request.args.get("from")
    to_str = request.args.get("to")

    prefs = get_or_create_preferences(current_user_id)

    # If from/to not provided, use preferences default_range_hours ending now
    if not from_str and not to_str:
        # Use datetime.now() instead of utcnow() to match MySQL NOW() timezone
        end = datetime.now()
        start = end - timedelta(hours=prefs.default_range_hours)
    else:
        if not from_str or not to_str:
            return jsonify({"error": "Provide both 'from' and 'to' OR neither (to use defaults)"}), 400

        start = parse_iso_datetime(from_str)
        end = parse_iso_datetime(to_str)

        if not start or not end:
            return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400

    if end < start:
        return jsonify({"error": "'to' must be >= 'from'"}), 400

    query = (
        Transaction.query
        .filter_by(user_id=current_user_id)
        .filter(Transaction.created_at >= start)
        .filter(Transaction.created_at <= end)
        .order_by(Transaction.created_at.asc())
    )

    # Filter by direction (required at top, so always applied)
    query = query.filter(Transaction.usd_to_lbp == (direction == "usd_to_lbp"))

    txns = query.all()

    if not txns:
        return jsonify({"error": "No transactions in selected range"}), 404

    rates = []
    for t in txns:
        # your POST /transaction already validates >0, so this is safe
        rates.append(compute_rate(t))

    min_rate = min(rates)
    max_rate = max(rates)
    avg_rate = sum(rates) / len(rates)

    first_rate = rates[0]
    last_rate = rates[-1]

    pct_change = None
    if first_rate != 0:
        pct_change = ((last_rate - first_rate) / first_rate) * 100.0

    return jsonify({
        "from": start.isoformat(),
        "to": end.isoformat(),
        "direction": direction,
        "total_transactions": len(rates),
        "min_rate": min_rate,
        "max_rate": max_rate,
        "avg_rate": avg_rate,
        "first_rate": first_rate,
        "last_rate": last_rate,
        "percentage_change": pct_change
    }), 200

#step 2
@app.route("/history/exchange-rate", methods=["GET"])
@active_user_required
def history_exchange_rate():
    current_user_id = int(get_jwt_identity())

    from_str = request.args.get("from")
    to_str = request.args.get("to")
    bucket = request.args.get("bucket")       # optional, uses preference default
    direction = request.args.get("direction") # required

    # Direction is required to avoid mixing incompatible rate units
    if direction is None:
        return jsonify({"error": "direction is required: 'usd_to_lbp' or 'lbp_to_usd'"}), 400

    if direction not in ["usd_to_lbp", "lbp_to_usd"]:
        return jsonify({"error": "direction must be 'usd_to_lbp' or 'lbp_to_usd'"}), 400

    prefs = get_or_create_preferences(current_user_id)

    if bucket is None:
        bucket = prefs.default_bucket

    if bucket not in ["hour", "day"]:
        return jsonify({"error": "bucket must be 'hour' or 'day'"}), 400

    # Default date window if from/to not provided
    if not from_str and not to_str:
        # Use datetime.now() instead of utcnow() to match MySQL NOW() timezone
        end = datetime.now()
        start = end - timedelta(hours=prefs.default_range_hours)
    else:
        if not from_str or not to_str:
            return jsonify({"error": "Provide both 'from' and 'to' OR neither (to use defaults)"}), 400

        start = parse_iso_datetime(from_str)
        end = parse_iso_datetime(to_str)

        if not start or not end:
            return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400

    if end < start:
        return jsonify({"error": "'to' must be >= 'from'"}), 400

    query = (
        Transaction.query
        .filter_by(user_id=current_user_id)
        .filter(Transaction.created_at >= start)
        .filter(Transaction.created_at <= end)
        .order_by(Transaction.created_at.asc())
    )

    # Filter by direction (required at top, so always applied)
    query = query.filter(Transaction.usd_to_lbp == (direction == "usd_to_lbp"))

    txns = query.all()
    if not txns:
        return jsonify({
            "bucket": bucket,
            "direction": direction,
            "from": start.isoformat(),
            "to": end.isoformat(),
            "points": []
        }), 200

    # Group into buckets in Python (simple + safe)
    buckets = {}  # key: bucket_datetime -> {"sum":..., "count":...}

    for t in txns:
        b = bucket_start(t.created_at, bucket)
        if b is None:
            return jsonify({"error": "Invalid bucket"}), 400

        rate = compute_rate(t)

        if b not in buckets:
            buckets[b] = {"sum": 0.0, "count": 0}
        buckets[b]["sum"] += rate
        buckets[b]["count"] += 1

    # Convert to sorted points
    points = []
    for b in sorted(buckets.keys()):
        cnt = buckets[b]["count"]
        avg_rate = buckets[b]["sum"] / cnt if cnt > 0 else None
        points.append({
            "t": b.isoformat(),
            "rate": avg_rate,
            "count": cnt
        })

    return jsonify({
        "bucket": bucket,
        "direction": direction,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "points": points
    }), 200


#step 3
@app.route("/market/offers", methods=["POST"])
@active_user_required
def create_offer():
    current_user_id = int(get_jwt_identity())
    data = request.get_json() or {}

    give_currency = data.get("give_currency")
    give_amount = data.get("give_amount")
    want_currency = data.get("want_currency")
    want_amount = data.get("want_amount")

    if not give_currency or not want_currency or give_amount is None or want_amount is None:
        # STEP 9: Log OFFER_CREATE failure - missing fields
        write_audit_log(
            event_type="OFFER_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Missing required fields",
            metadata={"failure_reason": "missing_fields"}
        )
        return jsonify({"error": "Missing fields"}), 400

    if not valid_currency(give_currency) or not valid_currency(want_currency):
        # STEP 9: Log OFFER_CREATE failure - invalid currency
        write_audit_log(
            event_type="OFFER_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Invalid currency",
            metadata={"failure_reason": "invalid_currency", "give_currency": give_currency, "want_currency": want_currency}
        )
        return jsonify({"error": "Currencies must be USD or LBP"}), 400

    if give_currency == want_currency:
        # STEP 9: Log OFFER_CREATE failure - same currency
        write_audit_log(
            event_type="OFFER_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Currencies must be different",
            metadata={"failure_reason": "same_currency", "give_currency": give_currency}
        )
        return jsonify({"error": "give_currency must be different from want_currency"}), 400

    try:
        give_amount = float(give_amount)
        want_amount = float(want_amount)
    except Exception:
        # STEP 9: Log OFFER_CREATE failure - invalid numbers
        write_audit_log(
            event_type="OFFER_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Amounts must be valid numbers",
            metadata={"failure_reason": "invalid_numbers"}
        )
        return jsonify({"error": "Amounts must be numbers"}), 400

    if give_amount <= 0 or want_amount <= 0:
        # STEP 9: Log OFFER_CREATE failure - amounts <= 0
        write_audit_log(
            event_type="OFFER_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Amounts must be positive",
            metadata={"failure_reason": "non_positive_amount"}
        )
        return jsonify({"error": "Amounts must be > 0"}), 400

    offer = Offer(
        creator_user_id=current_user_id,
        give_currency=give_currency,
        give_amount=give_amount,
        want_currency=want_currency,
        want_amount=want_amount,
        status="OPEN"
    )

    db.session.add(offer)
    db.session.commit()

    # STEP 9: Log OFFER_CREATE success
    write_audit_log(
        event_type="OFFER_CREATE",
        action="CREATE",
        success=True,
        actor_user_id=current_user_id,
        status_code=201,
        message="Offer created successfully",
        metadata={
            "offer_id": offer.id,
            "give_currency": give_currency,
            "give_amount": give_amount,
            "want_currency": want_currency,
            "want_amount": want_amount
        }
    )

    return jsonify({
        "id": offer.id,
        "status": offer.status
    }), 201

@app.route("/market/offers", methods=["GET"])
@active_user_required
def list_open_offers():
    current_user_id = int(get_jwt_identity())

    # Optional query param: include_mine=true to include your own offers but by default system will not include them
    include_mine = request.args.get("include_mine", "false").lower() == "true"

    q = Offer.query.filter_by(status="OPEN")
    if not include_mine:
        q = q.filter(Offer.creator_user_id != current_user_id)

    offers = q.order_by(Offer.created_at.desc()).all()

    return jsonify([{
        "id": o.id,
        "creator_user_id": o.creator_user_id,
        "give_currency": o.give_currency,
        "give_amount": o.give_amount,
        "want_currency": o.want_currency,
        "want_amount": o.want_amount,
        "status": o.status,
        "created_at": o.created_at.isoformat() if o.created_at else None
    } for o in offers]), 200

@app.route("/market/offers/<int:offer_id>", methods=["DELETE"])
@active_user_required
def cancel_offer(offer_id):
    current_user_id = int(get_jwt_identity())

    offer = Offer.query.get(offer_id)
    if not offer:
        # STEP 9: Log OFFER_CANCEL failure - not found
        write_audit_log(
            event_type="OFFER_CANCEL",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=404,
            message="Offer not found",
            metadata={"offer_id": offer_id}
        )
        return jsonify({"error": "Offer not found"}), 404

    if offer.creator_user_id != current_user_id:
        # STEP 9: Log OFFER_CANCEL failure - not allowed
        write_audit_log(
            event_type="OFFER_CANCEL",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=403,
            message="Not authorized to cancel this offer",
            metadata={"offer_id": offer_id}
        )
        return jsonify({"error": "Not allowed"}), 403

    if offer.status != "OPEN":
        # STEP 9: Log OFFER_CANCEL failure - not open
        write_audit_log(
            event_type="OFFER_CANCEL",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Only OPEN offers can be cancelled",
            metadata={"offer_id": offer_id, "offer_status": offer.status}
        )
        return jsonify({"error": "Only OPEN offers can be cancelled"}), 400

    offer.status = "CANCELLED"
    db.session.commit()

    # STEP 9: Log OFFER_CANCEL success
    write_audit_log(
        event_type="OFFER_CANCEL",
        action="DELETE",
        success=True,
        actor_user_id=current_user_id,
        status_code=200,
        message="Offer cancelled successfully",
        metadata={"offer_id": offer_id}
    )

    return jsonify({"message": "Offer cancelled"}), 200

@app.route("/market/offers/<int:offer_id>/accept", methods=["POST"])
@active_user_required
def accept_offer(offer_id):
    current_user_id = int(get_jwt_identity())

    # Use row lock to prevent race condition (two users accepting same offer)
    offer = Offer.query.filter_by(id=offer_id).with_for_update().first()
    if not offer:
        # STEP 9: Log OFFER_ACCEPT failure - not found
        write_audit_log(
            event_type="OFFER_ACCEPT",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=404,
            message="Offer not found",
            metadata={"offer_id": offer_id}
        )
        return jsonify({"error": "Offer not found"}), 404

    if offer.creator_user_id == current_user_id:
        # STEP 9: Log OFFER_ACCEPT failure - own offer
        write_audit_log(
            event_type="OFFER_ACCEPT",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Cannot accept your own offer",
            metadata={"offer_id": offer_id}
        )
        return jsonify({"error": "You cannot accept your own offer"}), 400

    if offer.status != "OPEN":
        # STEP 9: Log OFFER_ACCEPT failure - not open
        write_audit_log(
            event_type="OFFER_ACCEPT",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Offer is not open",
            metadata={"offer_id": offer_id, "offer_status": offer.status}
        )
        return jsonify({"error": "Offer is not open"}), 400

    # Determine buyer/seller based on offer currency pair
    # Rule: if offer gives USD and wants LBP, creator is seller (receives LBP, gives USD)
    #       if offer gives LBP and wants USD, creator is buyer (receives USD, gives LBP)
    if offer.give_currency == "USD" and offer.want_currency == "LBP":
        # Creator gives USD, wants LBP → creator is seller, acceptor is buyer
        seller_user_id = offer.creator_user_id
        buyer_user_id = current_user_id
    elif offer.give_currency == "LBP" and offer.want_currency == "USD":
        # Creator gives LBP, wants USD → creator is buyer, acceptor is seller
        buyer_user_id = offer.creator_user_id
        seller_user_id = current_user_id
    else:
        # Invalid currency pair
        write_audit_log(
            event_type="OFFER_ACCEPT",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Invalid offer currency pair",
            metadata={"offer_id": offer_id, "give_currency": offer.give_currency, "want_currency": offer.want_currency}
        )
        return jsonify({"error": "Invalid offer currency pair"}), 400

    # Complete the offer + create trade
    offer.status = "COMPLETED"

    trade = Trade(
        offer_id=offer.id,
        buyer_user_id=buyer_user_id,
        seller_user_id=seller_user_id
    )

    db.session.add(trade)
    db.session.commit()

    # STEP 9: Log OFFER_ACCEPT success
    write_audit_log(
        event_type="OFFER_ACCEPT",
        action="CREATE",
        success=True,
        actor_user_id=current_user_id,
        target_user_id=offer.creator_user_id,
        status_code=201,
        message="Offer accepted and trade created",
        metadata={
            "offer_id": offer_id,
            "trade_id": trade.id,
            "buyer_user_id": buyer_user_id,
            "seller_user_id": seller_user_id
        }
    )

    return jsonify({
        "message": "Offer accepted",
        "trade_id": trade.id
    }), 201

@app.route("/market/trades", methods=["GET"])
@active_user_required
def my_trades():
    current_user_id = int(get_jwt_identity())

    trades = (Trade.query
              .filter((Trade.buyer_user_id == current_user_id) | (Trade.seller_user_id == current_user_id))
              .order_by(Trade.created_at.desc())
              .all())

    return jsonify([{
        "id": t.id,
        "offer_id": t.offer_id,
        "buyer_user_id": t.buyer_user_id,
        "seller_user_id": t.seller_user_id,
        "created_at": t.created_at.isoformat() if t.created_at else None
    } for t in trades]), 200

#step 4
@app.route("/alerts", methods=["POST"])
@active_user_required
def create_alert():
    current_user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    direction = data.get("direction")
    condition = data.get("condition")
    threshold = data.get("threshold")

    if not direction or not condition or threshold is None:
        # STEP 9: Log ALERT_CREATE failure - missing fields
        write_audit_log(
            event_type="ALERT_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Missing required fields",
            metadata={"failure_reason": "missing_fields"}
        )
        return jsonify({"error": "Missing fields: direction, condition, threshold"}), 400

    if not valid_direction(direction):
        # STEP 9: Log ALERT_CREATE failure - invalid direction
        write_audit_log(
            event_type="ALERT_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Invalid direction",
            metadata={"failure_reason": "invalid_direction", "direction": direction}
        )
        return jsonify({"error": "direction must be 'usd_to_lbp' or 'lbp_to_usd'"}), 400

    if not valid_condition(condition):
        # STEP 9: Log ALERT_CREATE failure - invalid condition
        write_audit_log(
            event_type="ALERT_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Invalid condition",
            metadata={"failure_reason": "invalid_condition", "condition": condition}
        )
        return jsonify({"error": "condition must be 'above' or 'below'"}), 400

    try:
        threshold = float(threshold)
    except Exception:
        # STEP 9: Log ALERT_CREATE failure - invalid threshold
        write_audit_log(
            event_type="ALERT_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Threshold must be a valid number",
            metadata={"failure_reason": "invalid_threshold"}
        )
        return jsonify({"error": "threshold must be a number"}), 400

    if not math.isfinite(threshold) or threshold <= 0:
        # STEP 9: Log ALERT_CREATE failure - non-positive threshold
        write_audit_log(
            event_type="ALERT_CREATE",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Threshold must be positive and finite",
            metadata={"failure_reason": "invalid_threshold_range"}
        )
        return jsonify({"error": "threshold must be a positive finite number"}), 400

    alert = Alert(
        user_id=current_user_id,
        direction=direction,
        condition=condition,
        threshold=threshold,
        is_active=True,
        triggered_at=None
    )

    db.session.add(alert)
    db.session.commit()

    # STEP 9: Log ALERT_CREATE success
    write_audit_log(
        event_type="ALERT_CREATE",
        action="CREATE",
        success=True,
        actor_user_id=current_user_id,
        status_code=201,
        message="Alert created successfully",
        metadata={
            "alert_id": alert.id,
            "direction": direction,
            "condition": condition,
            "threshold": threshold
        }
    )

    return jsonify({
        "id": alert.id,
        "direction": alert.direction,
        "condition": alert.condition,
        "threshold": alert.threshold,
        "is_active": alert.is_active,
        "triggered_at": alert.triggered_at,
        "created_at": alert.created_at.isoformat() if alert.created_at else None
    }), 201

@app.route("/alerts", methods=["GET"])
@active_user_required
def list_alerts():
    current_user_id = int(get_jwt_identity())

    alerts = (
        Alert.query
        .filter_by(user_id=current_user_id)
        .order_by(Alert.created_at.desc())
        .all()
    )

    return jsonify([{
        "id": a.id,
        "direction": a.direction,
        "condition": a.condition,
        "threshold": a.threshold,
        "is_active": a.is_active,
        "triggered_at": a.triggered_at.isoformat() if a.triggered_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None
    } for a in alerts]), 200

@app.route("/alerts/<int:alert_id>", methods=["DELETE"])
@active_user_required
def delete_alert(alert_id):
    current_user_id = int(get_jwt_identity())

    alert = Alert.query.get(alert_id)
    if not alert:
        # STEP 9: Log ALERT_DELETE failure - not found
        write_audit_log(
            event_type="ALERT_DELETE",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=404,
            message="Alert not found",
            metadata={"alert_id": alert_id}
        )
        return jsonify({"error": "Alert not found"}), 404

    if alert.user_id != current_user_id:
        # STEP 9: Log ALERT_DELETE failure - not allowed
        write_audit_log(
            event_type="ALERT_DELETE",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=403,
            message="Not authorized to delete this alert",
            metadata={"alert_id": alert_id}
        )
        return jsonify({"error": "Not allowed"}), 403

    db.session.delete(alert)
    db.session.commit()

    # STEP 9: Log ALERT_DELETE success
    write_audit_log(
        event_type="ALERT_DELETE",
        action="DELETE",
        success=True,
        actor_user_id=current_user_id,
        status_code=200,
        message="Alert deleted successfully",
        metadata={"alert_id": alert_id}
    )

    return jsonify({"message": "Alert deleted"}), 200

@app.route("/alerts/triggered", methods=["GET"])
@active_user_required
def triggered_alerts():
    current_user_id = int(get_jwt_identity())

    alerts = (
        Alert.query
        .filter_by(user_id=current_user_id, is_active=True)
        .order_by(Alert.created_at.asc())
        .all()
    )

    # Compute current rates once per direction
    current_usd_to_lbp = compute_current_rate_for_user(current_user_id, "usd_to_lbp")
    current_lbp_to_usd = compute_current_rate_for_user(current_user_id, "lbp_to_usd")

    # Use datetime.now() instead of utcnow() to match MySQL NOW() timezone
    now = datetime.now()
    triggered_now = []

    for a in alerts:
        current_rate = current_usd_to_lbp if a.direction == "usd_to_lbp" else current_lbp_to_usd

        # If we can't compute a current rate, skip
        if current_rate is None:
            continue

        is_triggered = False
        if a.condition == "above" and current_rate >= a.threshold:
            is_triggered = True
        if a.condition == "below" and current_rate <= a.threshold:
            is_triggered = True

        # Mark first trigger time (prevents returning it forever as "new")
        if is_triggered and a.triggered_at is None:
            a.triggered_at = now
            db.session.add(a)

        if is_triggered:
            triggered_now.append({
                "id": a.id,
                "direction": a.direction,
                "condition": a.condition,
                "threshold": a.threshold,
                "current_rate": current_rate,
                "triggered_at": a.triggered_at.isoformat() if a.triggered_at else None
            })

    db.session.commit()

    return jsonify({
        "current_rates": {
            "usd_to_lbp": current_usd_to_lbp,
            "lbp_to_usd": current_lbp_to_usd
        },
        "triggered": triggered_now
    }), 200            

#step 5
@app.route("/watchlist", methods=["POST"])
@active_user_required
def add_watchlist_item():
    current_user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    item_type = data.get("item_type")
    direction = data.get("direction")
    condition = data.get("condition")
    threshold = data.get("threshold")

    if not item_type or not direction:
        # STEP 9: Log WATCHLIST_ADD failure - missing fields
        write_audit_log(
            event_type="WATCHLIST_ADD",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Missing required fields",
            metadata={"failure_reason": "missing_fields"}
        )
        return jsonify({"error": "Missing fields: item_type, direction"}), 400

    if not valid_watchlist_type(item_type):
        # STEP 9: Log WATCHLIST_ADD failure - invalid type
        write_audit_log(
            event_type="WATCHLIST_ADD",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Invalid watchlist item type",
            metadata={"failure_reason": "invalid_type", "item_type": item_type}
        )
        return jsonify({"error": "item_type must be 'direction' or 'threshold'"}), 400

    if not valid_direction(direction):
        # STEP 9: Log WATCHLIST_ADD failure - invalid direction
        write_audit_log(
            event_type="WATCHLIST_ADD",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="Invalid direction",
            metadata={"failure_reason": "invalid_direction", "direction": direction}
        )
        return jsonify({"error": "direction must be 'usd_to_lbp' or 'lbp_to_usd'"}), 400

    # Validate based on type
    if item_type == "direction":
        condition = None
        threshold = None

    if item_type == "threshold":
        if not condition or threshold is None:
            # STEP 9: Log WATCHLIST_ADD failure - missing threshold fields
            write_audit_log(
                event_type="WATCHLIST_ADD",
                action="CREATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="Threshold items require condition and threshold",
                metadata={"failure_reason": "missing_threshold_fields"}
            )
            return jsonify({"error": "For threshold items, provide: condition, threshold"}), 400

        if not valid_condition(condition):
            # STEP 9: Log WATCHLIST_ADD failure - invalid condition
            write_audit_log(
                event_type="WATCHLIST_ADD",
                action="CREATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="Invalid condition",
                metadata={"failure_reason": "invalid_condition", "condition": condition}
            )
            return jsonify({"error": "condition must be 'above' or 'below'"}), 400

        try:
            threshold = float(threshold)
        except Exception:
            # STEP 9: Log WATCHLIST_ADD failure - invalid threshold
            write_audit_log(
                event_type="WATCHLIST_ADD",
                action="CREATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="Threshold must be a valid number",
                metadata={"failure_reason": "invalid_threshold"}
            )
            return jsonify({"error": "threshold must be a number"}), 400

        if not math.isfinite(threshold) or threshold <= 0:
            # STEP 9: Log WATCHLIST_ADD failure - non-positive threshold
            write_audit_log(
                event_type="WATCHLIST_ADD",
                action="CREATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="Threshold must be positive and finite",
                metadata={"failure_reason": "invalid_threshold_range"}
            )
            return jsonify({"error": "threshold must be a positive finite number"}), 400

    # Prevent duplicates (same user, same type, same fields)
    existing_q = WatchlistItem.query.filter_by(
        user_id=current_user_id,
        item_type=item_type,
        direction=direction
    )

    if item_type == "threshold":
        existing_q = existing_q.filter_by(condition=condition, threshold=threshold)

    if existing_q.first():
        # STEP 9: Log WATCHLIST_ADD failure - duplicate
        write_audit_log(
            event_type="WATCHLIST_ADD",
            action="CREATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="This watchlist item already exists",
            metadata={"failure_reason": "duplicate"}
        )
        return jsonify({"error": "This watchlist item already exists"}), 400

    item = WatchlistItem(
        user_id=current_user_id,
        item_type=item_type,
        direction=direction,
        condition=condition,
        threshold=threshold
    )

    db.session.add(item)
    db.session.commit()

    # STEP 9: Log WATCHLIST_ADD success
    metadata = {
        "item_id": item.id,
        "item_type": item_type,
        "direction": direction
    }
    if item_type == "threshold":
        metadata["condition"] = condition
        metadata["threshold"] = threshold
    
    write_audit_log(
        event_type="WATCHLIST_ADD",
        action="CREATE",
        success=True,
        actor_user_id=current_user_id,
        status_code=201,
        message="Watchlist item added successfully",
        metadata=metadata
    )

    return jsonify({
        "id": item.id,
        "item_type": item.item_type,
        "direction": item.direction,
        "condition": item.condition,
        "threshold": item.threshold,
        "created_at": item.created_at.isoformat() if item.created_at else None
    }), 201

@app.route("/watchlist", methods=["GET"])
@active_user_required
def list_watchlist():
    current_user_id = int(get_jwt_identity())

    items = (
        WatchlistItem.query
        .filter_by(user_id=current_user_id)
        .order_by(WatchlistItem.created_at.desc())
        .all()
    )

    return jsonify([{
        "id": i.id,
        "item_type": i.item_type,
        "direction": i.direction,
        "condition": i.condition,
        "threshold": i.threshold,
        "created_at": i.created_at.isoformat() if i.created_at else None
    } for i in items]), 200


@app.route("/watchlist/<int:item_id>", methods=["DELETE"])
@active_user_required
def delete_watchlist_item(item_id):
    current_user_id = int(get_jwt_identity())

    item = WatchlistItem.query.get(item_id)
    if not item:
        # STEP 9: Log WATCHLIST_DELETE failure - not found
        write_audit_log(
            event_type="WATCHLIST_DELETE",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=404,
            message="Watchlist item not found",
            metadata={"item_id": item_id}
        )
        return jsonify({"error": "Watchlist item not found"}), 404

    if item.user_id != current_user_id:
        # STEP 9: Log WATCHLIST_DELETE failure - not allowed
        write_audit_log(
            event_type="WATCHLIST_DELETE",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            status_code=403,
            message="Not authorized to delete this watchlist item",
            metadata={"item_id": item_id}
        )
        return jsonify({"error": "Not allowed"}), 403

    db.session.delete(item)
    db.session.commit()

    # STEP 9: Log WATCHLIST_DELETE success
    write_audit_log(
        event_type="WATCHLIST_DELETE",
        action="DELETE",
        success=True,
        actor_user_id=current_user_id,
        status_code=200,
        message="Watchlist item deleted successfully",
        metadata={"item_id": item_id}
    )

    return jsonify({"message": "Watchlist item deleted"}), 200    

#step 6
@app.route("/transactions/export", methods=["GET"])
@active_user_required
def export_transactions_csv():
    current_user_id = int(get_jwt_identity())

    from_str = request.args.get("from")
    to_str = request.args.get("to")
    direction = request.args.get("direction")  # optional

    query = (
        Transaction.query
        .filter_by(user_id=current_user_id)
        .order_by(Transaction.created_at.asc())
    )

    # Optional date range filtering (same style as your other endpoints)
    if from_str and to_str:
        start = parse_iso_datetime(from_str)
        end = parse_iso_datetime(to_str)

        if not start or not end:
            return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400

        if end < start:
            return jsonify({"error": "'to' must be >= 'from'"}), 400

        query = query.filter(Transaction.created_at >= start).filter(Transaction.created_at <= end)
    elif from_str or to_str:
        return jsonify({"error": "Provide both 'from' and 'to' together"}), 400

    # Optional direction filtering
    if direction is not None:
        if direction not in ["usd_to_lbp", "lbp_to_usd"]:
            return jsonify({"error": "direction must be 'usd_to_lbp' or 'lbp_to_usd'"}), 400
        query = query.filter(Transaction.usd_to_lbp == (direction == "usd_to_lbp"))

    txns = query.all()

    # Build CSV in-memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "id",
        "usd_amount",
        "lbp_amount",
        "usd_to_lbp",
        "direction",
        "rate",
        "created_at"
    ])

    for t in txns:
        dir_str = "usd_to_lbp" if t.usd_to_lbp else "lbp_to_usd"
        rate = compute_rate(t)
        writer.writerow([
            t.id,
            t.usd_amount,
            t.lbp_amount,
            t.usd_to_lbp,
            dir_str,
            rate,
            t.created_at.isoformat() if t.created_at else ""
        ])

    csv_data = output.getvalue()
    output.close()

    # Download response
    filename = f"transactions_user{current_user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


#step 7
@app.route("/preferences", methods=["GET"])
@active_user_required
def get_preferences():
    current_user_id = int(get_jwt_identity())
    prefs = get_or_create_preferences(current_user_id)

    return jsonify({
        "default_range_hours": prefs.default_range_hours,
        "default_bucket": prefs.default_bucket
    }), 200

@app.route("/preferences", methods=["PUT"])
@active_user_required
def update_preferences():
    current_user_id = int(get_jwt_identity())
    prefs = get_or_create_preferences(current_user_id)

    data = request.get_json(silent=True) or {}

    default_range_hours = data.get("default_range_hours")
    default_bucket = data.get("default_bucket")

    if default_range_hours is None and default_bucket is None:
        # STEP 9: Log failed preference update
        write_audit_log(
            event_type="PREF_UPDATE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            status_code=400,
            message="No fields provided to update"
        )
        return jsonify({"error": "Provide at least one field: default_range_hours, default_bucket"}), 400

    # Track changes for audit log
    changed_fields = {}
    old_values = {
        "default_range_hours": prefs.default_range_hours,
        "default_bucket": prefs.default_bucket
    }

    if default_range_hours is not None:
        try:
            default_range_hours = int(default_range_hours)
        except Exception:
            # STEP 9: Log failed preference update - invalid type
            write_audit_log(
                event_type="PREF_UPDATE",
                action="UPDATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="default_range_hours must be integer"
            )
            return jsonify({"error": "default_range_hours must be an integer"}), 400

        if default_range_hours <= 0 or default_range_hours > 24 * 30:
            # STEP 9: Log failed preference update - out of range
            write_audit_log(
                event_type="PREF_UPDATE",
                action="UPDATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="default_range_hours out of valid range"
            )
            return jsonify({"error": "default_range_hours must be between 1 and 720 (30 days)"}), 400

        prefs.default_range_hours = default_range_hours
        changed_fields["default_range_hours"] = {
            "old": old_values["default_range_hours"],
            "new": default_range_hours
        }

    if default_bucket is not None:
        if default_bucket not in ["hour", "day"]:
            # STEP 9: Log failed preference update - invalid bucket
            write_audit_log(
                event_type="PREF_UPDATE",
                action="UPDATE",
                success=False,
                actor_user_id=current_user_id,
                status_code=400,
                message="default_bucket must be 'hour' or 'day'"
            )
            return jsonify({"error": "default_bucket must be 'hour' or 'day'"}), 400
        prefs.default_bucket = default_bucket
        changed_fields["default_bucket"] = {
            "old": old_values["default_bucket"],
            "new": default_bucket
        }

    db.session.commit()

    # STEP 9: Log successful preference update
    write_audit_log(
        event_type="PREF_UPDATE",
        action="UPDATE",
        success=True,
        actor_user_id=current_user_id,
        status_code=200,
        metadata={
            "changed_fields": list(changed_fields.keys()),
            "changes": changed_fields
        }
    )

    return jsonify({
        "message": "Preferences updated",
        "default_range_hours": prefs.default_range_hours,
        "default_bucket": prefs.default_bucket
    }), 200

# ==========================================
# STEP 8: ADMIN & MODERATION ENDPOINTS
# ==========================================

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    """Admin: List all users with role and status"""
    users = User.query.all()
    
    return jsonify([{
        "id": u.id,
        "user_name": u.user_name,
        "role": u.role,
        "status": u.status
    } for u in users]), 200

@app.route("/admin/stats/transactions", methods=["GET"])
@admin_required
def admin_stats_transactions():
    """Admin: System-wide transaction statistics"""
    # All-time stats
    total_all_time = Transaction.query.count()
    
    # Last 72 hours
    cutoff_72h = datetime.now() - timedelta(hours=72)
    total_72h = Transaction.query.filter(Transaction.created_at >= cutoff_72h).count()
    
    # Count by direction (last 72h)
    usd_to_lbp_72h = Transaction.query.filter(Transaction.created_at >= cutoff_72h, Transaction.usd_to_lbp.is_(True)).count()
    lbp_to_usd_72h = Transaction.query.filter(Transaction.created_at >= cutoff_72h, Transaction.usd_to_lbp.is_(False)).count()
    
    return jsonify({
        "total_transactions_all_time": total_all_time,
        "total_transactions_last_72h": total_72h,
        "usd_to_lbp_last_72h": usd_to_lbp_72h,
        "lbp_to_usd_last_72h": lbp_to_usd_72h,
        "window_start": cutoff_72h.isoformat(),
        "window_end": datetime.now().isoformat()
    }), 200

@app.route("/admin/users/<int:user_id>/status", methods=["PUT"])
@admin_fresh_required
def admin_update_user_status(user_id):
    """Admin: Change user status (ACTIVE, SUSPENDED, BANNED)"""
    current_user_id = int(get_jwt_identity())
    # Look up admin username for audit logging
    admin_user = User.query.get(current_user_id)
    admin_username = admin_user.user_name if admin_user else None
    
    user = User.query.get(user_id)
    if not user:
        # STEP 9: Log ADMIN_USER_STATUS_CHANGE failure - not found
        write_audit_log(
            event_type="ADMIN_USER_STATUS_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=404,
            message="User not found",
            metadata={"user_id": user_id}
        )
        return jsonify({"error": "User not found"}), 404
    
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    
    if not new_status:
        # STEP 9: Log ADMIN_USER_STATUS_CHANGE failure - missing field
        write_audit_log(
            event_type="ADMIN_USER_STATUS_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=400,
            message="Missing field: status",
            metadata={"failure_reason": "missing_field"}
        )
        return jsonify({"error": "Missing field: status"}), 400
    
    if new_status not in ["ACTIVE", "SUSPENDED", "BANNED"]:
        # STEP 9: Log ADMIN_USER_STATUS_CHANGE failure - invalid status
        write_audit_log(
            event_type="ADMIN_USER_STATUS_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=400,
            message="Invalid status value",
            metadata={"failure_reason": "invalid_status", "status": new_status}
        )
        return jsonify({"error": "status must be ACTIVE, SUSPENDED, or BANNED"}), 400
    
    if user_id == current_user_id and new_status in ["SUSPENDED", "BANNED"]:
        # STEP 9: Log ADMIN_USER_STATUS_CHANGE failure - self suspension
        write_audit_log(
            event_type="ADMIN_USER_STATUS_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=400,
            message="Cannot suspend or ban yourself",
            metadata={"failure_reason": "self_suspension", "new_status": new_status}
        )
        return jsonify({"error": "You cannot suspend/ban yourself"}), 400
    
    old_status = user.status
    user.status = new_status
    db.session.commit()
    
    # STEP 9: Log ADMIN_USER_STATUS_CHANGE success
    write_audit_log(
        event_type="ADMIN_USER_STATUS_CHANGE",
        action="UPDATE",
        success=True,
        actor_user_id=current_user_id,
        actor_username=admin_username,
        target_user_id=user_id,
        status_code=200,
        message=f"User status changed from {old_status} to {new_status}",
        metadata={
            "user_id": user_id,
            "old_status": old_status,
            "new_status": new_status
        }
    )
    
    return jsonify({
        "message": f"User status updated to {new_status}",
        "user_id": user.id,
        "status": user.status
    }), 200

@app.route("/admin/users/<int:user_id>/role", methods=["PUT"])
@admin_fresh_required
def admin_update_user_role(user_id):
    """Admin: Change user role (USER, ADMIN)"""
    current_user_id = int(get_jwt_identity())
    # Look up admin username for audit logging
    admin_user = User.query.get(current_user_id)
    admin_username = admin_user.user_name if admin_user else None
    
    user = User.query.get(user_id)
    if not user:
        # STEP 9: Log ADMIN_USER_ROLE_CHANGE failure - not found
        write_audit_log(
            event_type="ADMIN_USER_ROLE_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=404,
            message="User not found",
            metadata={"user_id": user_id}
        )
        return jsonify({"error": "User not found"}), 404
    
    data = request.get_json(silent=True) or {}
    new_role = data.get("role")
    
    if not new_role:
        # STEP 9: Log ADMIN_USER_ROLE_CHANGE failure - missing field
        write_audit_log(
            event_type="ADMIN_USER_ROLE_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=400,
            message="Missing field: role",
            metadata={"failure_reason": "missing_field"}
        )
        return jsonify({"error": "Missing field: role"}), 400
    
    if new_role not in ["USER", "ADMIN"]:
        # STEP 9: Log ADMIN_USER_ROLE_CHANGE failure - invalid role
        write_audit_log(
            event_type="ADMIN_USER_ROLE_CHANGE",
            action="UPDATE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            target_user_id=user_id,
            status_code=400,
            message="Invalid role value",
            metadata={"failure_reason": "invalid_role", "role": new_role}
        )
        return jsonify({"error": "role must be USER or ADMIN"}), 400
    
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    # STEP 9: Log ADMIN_USER_ROLE_CHANGE success
    write_audit_log(
        event_type="ADMIN_USER_ROLE_CHANGE",
        action="UPDATE",
        success=True,
        actor_user_id=current_user_id,
        actor_username=admin_username,
        target_user_id=user_id,
        status_code=200,
        message=f"User role changed from {old_role} to {new_role}",
        metadata={
            "user_id": user_id,
            "old_role": old_role,
            "new_role": new_role
        }
    )
    
    return jsonify({
        "message": f"User role updated to {new_role}",
        "user_id": user.id,
        "role": user.role
    }), 200

@app.route("/admin/users/<int:user_id>/preferences", methods=["GET"])
@admin_required
def admin_get_user_preferences(user_id):
    """Admin: View user's preferences"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    prefs = get_or_create_preferences(user_id)
    
    return jsonify({
        "default_range_hours": prefs.default_range_hours,
        "default_bucket": prefs.default_bucket
    }), 200

@app.route("/admin/users/<int:user_id>/preferences", methods=["PUT"])
@admin_fresh_required
def admin_update_user_preferences(user_id):
    """Admin: Modify user's preferences"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    prefs = get_or_create_preferences(user_id)
    data = request.get_json(silent=True) or {}
    
    default_range_hours = data.get("default_range_hours")
    default_bucket = data.get("default_bucket")
    
    if default_range_hours is None and default_bucket is None:
        return jsonify({"error": "Provide at least one field: default_range_hours, default_bucket"}), 400
    
    if default_range_hours is not None:
        try:
            default_range_hours = int(default_range_hours)
        except Exception:
            return jsonify({"error": "default_range_hours must be an integer"}), 400
        
        if default_range_hours <= 0 or default_range_hours > 24 * 30:
            return jsonify({"error": "default_range_hours must be between 1 and 720 (30 days)"}), 400
        
        prefs.default_range_hours = default_range_hours
    
    if default_bucket is not None:
        if default_bucket not in ["hour", "day"]:
            return jsonify({"error": "default_bucket must be 'hour' or 'day'"}), 400
        prefs.default_bucket = default_bucket
    
    db.session.commit()
    
    return jsonify({
        "message": "User preferences updated",
        "default_range_hours": prefs.default_range_hours,
        "default_bucket": prefs.default_bucket
    }), 200

@app.route("/admin/users/<int:user_id>/alerts", methods=["GET"])
@admin_required
def admin_get_user_alerts(user_id):
    """Admin: View all alerts for a user"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    alerts = Alert.query.filter_by(user_id=user_id).order_by(Alert.created_at.desc()).all()
    
    return jsonify([{
        "id": a.id,
        "direction": a.direction,
        "condition": a.condition,
        "threshold": a.threshold,
        "is_active": a.is_active,
        "triggered_at": a.triggered_at.isoformat() if a.triggered_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None
    } for a in alerts]), 200

@app.route("/admin/alerts/<int:alert_id>", methods=["DELETE"])
@admin_fresh_required
def admin_delete_alert(alert_id):
    """Admin: Delete any alert"""
    current_user_id = int(get_jwt_identity())
    # Look up admin username for audit logging
    admin_user = User.query.get(current_user_id)
    admin_username = admin_user.user_name if admin_user else None
    
    alert = Alert.query.get(alert_id)
    if not alert:
        # STEP 9: Log ADMIN_ALERT_DELETE failure - not found
        write_audit_log(
            event_type="ADMIN_ALERT_DELETE",
            action="DELETE",
            success=False,
            actor_user_id=current_user_id,
            actor_username=admin_username,
            status_code=404,
            message="Alert not found",
            metadata={"alert_id": alert_id}
        )
        return jsonify({"error": "Alert not found"}), 404
    
    target_user_id = alert.user_id
    db.session.delete(alert)
    db.session.commit()
    
    # STEP 9: Log ADMIN_ALERT_DELETE success
    write_audit_log(
        event_type="ADMIN_ALERT_DELETE",
        action="DELETE",
        success=True,
        actor_user_id=current_user_id,
        actor_username=admin_username,
        target_user_id=target_user_id,
        status_code=200,
        message="Alert deleted by admin",
        metadata={
            "alert_id": alert_id,
            "target_user_id": target_user_id
        }
    )
    
    return jsonify({"message": "Alert deleted"}), 200

# ==========================================
# STEP 9: AUDIT LOG VIEWING ENDPOINTS
# ==========================================
# STEP 9 IMPLEMENTATION STATUS:
# ✓ AuditLog model added (immutable, append-only)
# ✓ write_audit_log() helper with sanitization
# ✓ Logging integrated in: /login, /logout, /logout_refresh, /transaction, /preferences
# ✓ Logging integrated in: /market/offers (POST, DELETE, ACCEPT), /alerts (POST, DELETE)
# ✓ Logging integrated in: /watchlist (POST, DELETE), /admin endpoints (status, role, alert delete)
# ✓ Log viewing endpoints: GET /logs (user) and GET /admin/logs (admin)
# ✓ Database migration: flask db migrate -m "step9_audit_logs" && flask db upgrade
# =====================================

@app.route("/logs", methods=["GET"])
@active_user_required
def view_user_logs():
    """User: View own audit logs (append-only, read-only)"""
    current_user_id = int(get_jwt_identity())
    
    # Parse optional query parameters
    from_str = request.args.get("from")
    to_str = request.args.get("to")
    event_type = request.args.get("event_type")
    success = request.args.get("success")  # "true" or "false"
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    
    # Validate and clamp limits
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    
    # STEP 9 FIX: Validate from/to datetime parsing, return 400 if invalid
    if from_str:
        start = parse_iso_datetime(from_str)
        if not start:
            return jsonify({"error": "Invalid 'from' datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400
    else:
        start = None
    
    if to_str:
        end = parse_iso_datetime(to_str)
        if not end:
            return jsonify({"error": "Invalid 'to' datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400
    else:
        end = None
    
    # Build query for user's own logs only
    query = AuditLog.query.filter_by(actor_user_id=current_user_id)
    
    # Apply date range filtering
    if start:
        query = query.filter(AuditLog.created_at >= start)
    
    if end:
        query = query.filter(AuditLog.created_at <= end)
    
    # Optional event type filter
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    # Optional success filter
    if success:
        success_bool = success.lower() in ["true", "1", "yes"]
        query = query.filter_by(success=success_bool)
    
    # Sort newest first, apply pagination
    total_count = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    
    # Format response
    log_records = []
    for log in logs:
        record = {
            "id": log.id,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "event_type": log.event_type,
            "action": log.action,
            "success": log.success,
            "status_code": log.status_code,
            "message": log.message,
            "http_method": log.http_method,
            "path": log.path,
            "ip_address": log.ip_address,
            "actor_user_id": log.actor_user_id,
            "metadata_json": None
        }
        # Try to parse metadata JSON for cleaner output
        if log.metadata_json:
            try:
                record["metadata_json"] = json.loads(log.metadata_json)
            except (json.JSONDecodeError, TypeError):
                record["metadata_json"] = log.metadata_json
        log_records.append(record)
    
    return jsonify({
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "logs": log_records
    }), 200

@app.route("/admin/logs", methods=["GET"])
@admin_required
def view_all_logs():
    """Admin: View all audit logs (append-only, read-only)"""
    # Parse optional query parameters
    from_str = request.args.get("from")
    to_str = request.args.get("to")
    actor_user_id = request.args.get("actor_user_id", type=int)
    target_user_id = request.args.get("target_user_id", type=int)
    event_type = request.args.get("event_type")
    success = request.args.get("success")  # "true" or "false"
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    
    # Validate and clamp limits
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    
    # STEP 9 FIX: Validate from/to datetime parsing, return 400 if invalid
    if from_str:
        start = parse_iso_datetime(from_str)
        if not start:
            return jsonify({"error": "Invalid 'from' datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400
    else:
        start = None
    
    if to_str:
        end = parse_iso_datetime(to_str)
        if not end:
            return jsonify({"error": "Invalid 'to' datetime format. Use YYYY-MM-DD or ISO like 2026-02-18T23:59:59"}), 400
    else:
        end = None
    
    # Build query for all logs
    query = AuditLog.query
    
    # Apply date range filtering
    if start:
        query = query.filter(AuditLog.created_at >= start)
    
    if end:
        query = query.filter(AuditLog.created_at <= end)
    
    # Optional actor filter
    if actor_user_id:
        query = query.filter_by(actor_user_id=actor_user_id)
    
    # Optional target filter
    if target_user_id:
        query = query.filter_by(target_user_id=target_user_id)
    
    # Optional event type filter
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    # Optional success filter
    if success:
        success_bool = success.lower() in ["true", "1", "yes"]
        query = query.filter_by(success=success_bool)
    
    # Sort newest first, apply pagination
    total_count = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    
    # Format response
    log_records = []
    for log in logs:
        record = {
            "id": log.id,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "event_type": log.event_type,
            "action": log.action,
            "success": log.success,
            "actor_user_id": log.actor_user_id,
            "actor_username": log.actor_username,
            "target_user_id": log.target_user_id,
            "status_code": log.status_code,
            "message": log.message,
            "http_method": log.http_method,
            "path": log.path,
            "ip_address": log.ip_address,
            "metadata_json": None
        }
        # Try to parse metadata JSON for cleaner output
        if log.metadata_json:
            try:
                record["metadata_json"] = json.loads(log.metadata_json)
            except (json.JSONDecodeError, TypeError):
                record["metadata_json"] = log.metadata_json
        log_records.append(record)
    
    return jsonify({
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "logs": log_records
    }), 200

# ==========================================
# ==========================================
# TESTING INSTRUCTIONS FOR STEP 8 & STEP 9
# ==========================================
"""
HOW TO TEST STEP 8:

1. Create a test user:
   POST /user {"user_name": "testadmin", "password": "password123"}

2. Promote to admin (via SQL or manually):
   UPDATE user SET role='ADMIN' WHERE user_name='testadmin';

3. Login as admin:
   POST /login {"user_name": "testadmin", "password": "password123"}
   Save the access_token and refresh_token

4. Test /admin/users:
   GET /admin/users
   Header: Authorization: Bearer <access_token>
   Should list all users with role and status

5. Test user suspension and login failure:
   PUT /admin/users/<user_id>/status
   Body: {"status": "SUSPENDED"}
   Try to login as that user -> should get 403

6. Test RBAC rejection (normal user):
   Create normal user and login
   Try GET /admin/users -> should get 403 "Admin only"

7. Test fresh token requirement:
   Generate access token without fresh=True from older code
   Try PUT /admin/users/<id>/status -> should fail on fresh requirement

8. Test stats endpoint:
   GET /admin/stats/transactions -> shows all-time and last 72h stats

9. Test token revocation (access + refresh):
   POST /logout with Authorization: Bearer <access_token>
   Should return 200 {"message": "Successfully logged out"}
   Try POST /transaction with same access_token -> should fail (token revoked)

10. Test refresh token revocation:
    POST /logout_refresh with Authorization: Bearer <refresh_token>
    Should return 200 {"message": "Refresh token revoked"}
    Try POST /refresh with same refresh_token -> should fail (token revoked)

========================================
HOW TO TEST STEP 9 - AUDIT LOGGING & COMPLIANCE:
========================================

PREREQUISITES:
1. Run migrations: flask db migrate -m "step9_audit_logs" && flask db upgrade
   (If migration already exists, just run: flask db upgrade)

2. Create test users:
   POST /user {"user_name": "alice", "password": "pass123"}
   POST /user {"user_name": "bob", "password": "pass123"}

3. Promote alice to admin:
   UPDATE user SET role='ADMIN' WHERE user_name='alice';

========================================
TEST 1: Failed login visibility
========================================
- Alice logs in successfully: 
  POST /login {"user_name": "alice", "password": "pass123"}
  Save access_token_alice
- Alice calls GET /logs (with Authorization header using access_token_alice)
  Should see AUTH_LOGIN_SUCCESS in her logs
- Try wrong password as alice: 
  POST /login {"user_name": "alice", "password": "wrong"}
- Call GET /logs as alice again -> should see AUTH_LOGIN_FAIL with actor_user_id=alice.id
  (This is the FIX: now invalid password logs the actual user)
- Try non-existent user: 
  POST /login {"user_name": "nonexistent", "password": "pass"}
  /logs query won't show this (actor_user_id=None), BUT:
  Admin GET /admin/logs?event_type=AUTH_LOGIN_FAIL -> sees all failed logins
         including the non-existent user attempt with actor_username="nonexistent"

========================================
TEST 2: Offer logging (OFFER_CREATE, OFFER_CANCEL, OFFER_ACCEPT)
========================================
- Bob logs in: 
  POST /login {"user_name": "bob", "password": "pass123"}
  Save access_token_bob

- Create valid offer as bob:
  POST /market/offers {
    "give_currency": "USD", "give_amount": 100,
    "want_currency": "LBP", "want_amount": 1500000
  }
  GET /logs (as bob) -> should see OFFER_CREATE success with offer_id in metadata
  GET /admin/logs (as alice) -> should also see OFFER_CREATE with bob as actor

- Try invalid currency as bob:
  POST /market/offers {
    "give_currency": "EUR", "give_amount": 100, ...
  }
  GET /logs (as bob) -> should see OFFER_CREATE fail with success=false

- Bob cancels his offer:
  DELETE /market/offers/<offer_id> (from earlier successful create)
  GET /logs (as bob) -> should see OFFER_CANCEL success

- Alice creates an offer, bob accepts it:
  POST /market/offers (as alice) -> save offer_id_alice
  POST /market/offers/<offer_id_alice>/accept (as bob)
  GET /logs (as bob) -> should see OFFER_ACCEPT success with trade_id and buyer/seller info
  GET /admin/logs (as alice) -> should see OFFER_ACCEPT with target_user_id=alice.id

- Bob tries to accept his own offer:
  POST /market/offers (as bob, create new)
  POST /market/offers/<bob_offer_id>/accept (as bob)
  GET /logs (as bob) -> should see OFFER_ACCEPT fail with success=false, mention "own offer"

========================================
TEST 3: Alert logging (ALERT_CREATE, ALERT_DELETE)
========================================
- Bob creates alert:
  POST /alerts {
    "direction": "usd_to_lbp", "condition": "above", "threshold": 90000
  }
  GET /logs (as bob) -> should see ALERT_CREATE success with alert_id and threshold

- Try invalid condition as bob:
  POST /alerts {
    "direction": "usd_to_lbp", "condition": "invalid", "threshold": 90000
  }
  GET /logs (as bob) -> should see ALERT_CREATE fail with failure_reason="invalid_condition"

- Bob deletes his alert:
  DELETE /alerts/<alert_id>
  GET /logs (as bob) -> should see ALERT_DELETE success

- Alice creates alert, bob tries to delete it:
  POST /alerts (as alice)
  DELETE /alerts/<alice_alert_id> (as bob)
  GET /logs (as bob) -> should see ALERT_DELETE fail with 403 message "Not allowed"

========================================
TEST 4: Watchlist logging (WATCHLIST_ADD, WATCHLIST_DELETE)
========================================
- Bob adds watchlist item (direction type):
  POST /watchlist {
    "item_type": "direction", "direction": "usd_to_lbp"
  }
  GET /logs (as bob) -> should see WATCHLIST_ADD success with item_id

- Try duplicate watchlist item:
  POST /watchlist (same as above)
  GET /logs (as bob) -> should see WATCHLIST_ADD fail with failure_reason="duplicate"

- Bob adds watchlist item (threshold type):
  POST /watchlist {
    "item_type": "threshold", "direction": "lbp_to_usd",
    "condition": "below", "threshold": 0.001
  }
  GET /logs (as bob) -> should see WATCHLIST_ADD success with condition and threshold in metadata

- Bob deletes watchlist item:
  DELETE /watchlist/<item_id>
  GET /logs (as bob) -> should see WATCHLIST_DELETE success

========================================
TEST 5: Admin moderation logging
========================================
- Alice (admin) suspends bob:
  PUT /admin/users/<bob_id>/status {"status": "SUSPENDED"}
  GET /admin/logs (as alice) -> should see ADMIN_USER_STATUS_CHANGE success
                                with target_user_id=bob.id, old_status/new_status in metadata
  Try to login as bob:
    POST /login {"user_name": "bob", ...}
    Returns 403, log shows AUTH_LOGIN_FAIL with message about suspension

- Alice tries to suspend herself:
  PUT /admin/users/<alice_id>/status {"status": "SUSPENDED"}
  Returns 400 with "cannot suspend yourself" message
  GET /admin/logs (as alice) -> should see ADMIN_USER_STATUS_CHANGE fail with 
                                failure_reason="self_suspension"

- Alice changes bob's role to ADMIN:
  PUT /admin/users/<bob_id>/role {"role": "ADMIN"}
  GET /admin/logs (as alice) -> should see ADMIN_USER_ROLE_CHANGE success
                                with old_role="USER", new_role="ADMIN"

- Alice (admin) deletes a random alert (alice creates one, then deletes via admin endpoint):
  POST /alerts (as alice)
  DELETE /admin/alerts/<alert_id> (as alice admin endpoint)
  GET /admin/logs (as alice) -> should see ADMIN_ALERT_DELETE success
                                with target_user_id=alice.id (the alert owner), alert_id in metadata

========================================
TEST 6: Log endpoint validation (FIX: return 400 for bad dates)
========================================
- Invalid from/to datetime:
  GET /logs?from=2026-13-45 -> should return 400 with helpful error message
  GET /logs?to=invalid -> should return 400
  GET /admin/logs?from=2026-99-99 -> should return 400

- Valid date range:
  GET /logs?from=2026-02-01&to=2026-02-28 -> should filter by date range
  Verify logs are <= now and >= from date

- Invalid limit/offset:
  GET /logs?limit=1000 -> should clamp to max 200 (no error, just clamped)
  GET /logs?offset=-5 -> should clamp to min 0 (no error, just clamped)

- Event type filter:
  GET /logs?event_type=OFFER_CREATE -> should only show OFFER_CREATE events
  GET /admin/logs?event_type=AUTH_LOGIN_FAIL -> should filter correctly

- Success filter:
  GET /logs?success=true -> should only show successful events
  GET /logs?success=false -> should only show failed events

- Actor/target filtering (admin only):
  GET /admin/logs?actor_user_id=<bob_id> -> should show only bob's actions
  GET /admin/logs?target_user_id=<bob_id> -> should show only actions targeting bob

========================================
TEST 7: Sensitive data sanitization
========================================
- Check that no passwords appear in logs:
  GET /logs -> iterate through metadata_json fields, verify:
               "password", "hashed_password", "access_token", "refresh_token" never appear
  GET /admin/logs -> same check

- Verify request context is captured:
  Check that each log has:
    - http_method (GET, POST, PUT, DELETE)
    - path (/login, /market/offers, /alerts, etc.)
    - ip_address (actual IP, not None)
    - user_agent (browser/REST client info)
    - status_code (200, 201, 400, 403, 404)

========================================
TEST 8: User data isolation
========================================
- Alice logs in: 
  GET /logs -> should only see alice's own logs (actor_user_id=alice.id)
  Should NOT see bob's logs

- Bob logs in:
  GET /logs -> should only see bob's own logs (actor_user_id=bob.id)
  Should NOT see alice's logs

- Alice (admin):
  GET /admin/logs -> should see BOTH alice's and bob's logs
  Can filter by actor_user_id to see specific user's actions

- Non-admin user tries:
  GET /admin/logs -> should return 403 "Admin only"

========================================
TEST 9: Audit log immutability
========================================
- Verify no DELETE endpoint for logs:
  DELETE /logs/<log_id> -> should get 404 (no such endpoint)
  DELETE /admin/logs/<log_id> -> should get 404 or 405

- Verify no UPDATE endpoint for logs:
  PUT /logs/<log_id> -> should get 404
  PATCH /logs -> should get 404

- Logs are append-only (no transactions or deletions allowed)

========================================
FULL END-TO-END SCENARIO:
========================================
1. Create test users: alice (admin), bob (user)
2. Run login test: successful and failed logins appear in logs
3. Run marketplace test: create->accept offer chain logged
4. Run alert test: create->delete alerts logged
5. Run admin test: alice suspends bob, bob can't login, appears in admin logs
6. Run log query test: filter by date/event/status, pagination works
7. Run isolation test: bob can't see alice's logs, alice can see all via /admin/logs
8. Verify immutability: no log deletion possible
9. Verify sanitization: no passwords/tokens in any log
10. Verify request context: all logs have method, path, IP, user-agent, status_code

========================================
DATABASE MIGRATION:
========================================
If this is the first run of Step 9:
    flask db migrate -m "step9_audit_logs"
    flask db upgrade

If migration already exists:
    flask db upgrade

(The migration creates the AuditLog table with immutable design)
"""


if __name__ == "__main__":
    app.run(debug=False)
