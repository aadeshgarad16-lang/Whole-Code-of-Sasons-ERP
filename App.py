import os
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime
from dateutil import parser

def format_db_date(date_str):
    if not date_str:
        return None
    try:
        parsed_date = parser.parse(date_str)
        return parsed_date.strftime('%Y-%m-%d')
    except Exception:
        try:
            return datetime.fromisoformat(date_str.replace('Z', '')).strftime('%Y-%m-%d')
        except Exception:
            return date_str

# IMPORT YOUR DATABASE CONNECTION FUNCTION FROM YOUR OTHER FILE
from Main import get_db_connection

# Load key variables from your .env file
load_dotenv()

from datetime import date, datetime
from flask.json.provider import DefaultJSONProvider

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*", "allow_headers": ["Content-Type", "Authorization", "X-API-Key", "X-User-Contact"]}})

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        headers = None
        if 'Access-Control-Request-Headers' in request.headers:
            headers = request.headers['Access-Control-Request-Headers']
        h = response.headers
        h['Access-Control-Allow-Origin'] = '*'
        h['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, PUT, DELETE'
        if headers:
            h['Access-Control-Allow-Headers'] = headers
        return response


# =====================================================================
# ISO-8601 STANDARDIZATION PROVIDER
# =====================================================================
class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)

app.json = CustomJSONProvider(app)

# =====================================================================
# STAGE NORMALIZATION ARCHITECTURE
# =====================================================================
VALID_ORDER_STAGES = [
    'Initiation', 'Order Initiation', 'Specifications', 'Order Specifications', 
    'Stock Check', 'BOM Calculation', 'Inventory Check', 'Material Allocation', 
    'Procurement', 'Material Release', 'Production', 'Quality & Packing', 'Dispatched'
]
STAGE_MAP = {stage.lower(): stage for stage in VALID_ORDER_STAGES}

def normalize_stage(raw_stage, default='Specifications'):
    """
    Sanitizes, trims, and normalizes the stage string against strict ENUM boundaries.
    Defaults to 'Specifications' if invalid or empty.
    """
    if not raw_stage:
        return default
    
    clean_stage = str(raw_stage).strip().lower()
    return STAGE_MAP.get(clean_stage, default)


# =====================================================================
# DIAGNOSTIC TOOL: Test Database Connection
# =====================================================================
@app.route('/api/test-db', methods=['GET'])
def test_db():
    try:
        conn = get_db_connection()
        conn.close()
        return jsonify({"message": "Database Connected Successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =====================================================================
# DIAGNOSTIC TOOL: Reset/Clear Database
# =====================================================================
@app.route('/api/reset-database', methods=['POST'])
def reset_database():
    if not verify_write_key('User Management'): 
        return "Unauthorized: Invalid Write API Key", 401
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
        cursor.execute("TRUNCATE TABLE specifications;")
        cursor.execute("TRUNCATE TABLE bill_of_materials;")
        cursor.execute("TRUNCATE TABLE procurement;")
        cursor.execute("TRUNCATE TABLE purchase_orders;")
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
        conn.commit()
        cursor.close(); conn.close()
        return jsonify({"success": True, "message": "Database reset successfully!"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- SECURITY INTERCEPTORS ---
def verify_access_detailed(module_name=None, is_write=False):
    client_key = request.headers.get('X-API-Key')
    expected_key = os.environ.get("ERP_WRITE_API_KEY", "sasons_write_only_key_2026_xyz") if is_write else os.environ.get("ERP_READ_API_KEY", "sasons_read_only_key_2026_abc")
    
    # Fallback to write key if read key fails (write key has higher privilege)
    if client_key != expected_key and not (not is_write and client_key == os.environ.get("ERP_WRITE_API_KEY", "sasons_write_only_key_2026_xyz")):
        return False, f"Missing or Invalid {'Write' if is_write else 'Read'} API Key"
        
    if module_name:
        contact = request.headers.get('X-User-Contact')
        if not contact:
            return False, "Missing X-User-Contact header. Please re-login."
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE contact_number = %s OR email_id = %s OR username = %s", (contact, contact, contact))
            user = cursor.fetchone()
            
            if not user:
                # Auto-migrate legacy user into the Users table to preserve their access
                is_email = '@' in contact
                email_val = contact if is_email else f"{contact}@sasons.local"
                contact_val = contact[:10] if not is_email else '9999999999'
                hashed_pw = generate_password_hash('Admin@123')
                
                print(f"Auto-migrating legacy user {contact} into the Users table...")
                cursor.execute("""
                    INSERT INTO users (full_name, contact_number, email_id, designation, role, username, password_hash, modules_access, status) 
                    VALUES ('Test Case', %s, %s, 'System Administrator', 'Super Admin', %s, %s, '[]', 'Active')
                """, (contact_val, email_val, contact_val, hashed_pw))
                conn.commit()
                
                user = {'role': 'Super Admin', 'modules_access': '[]'}
                
            if user['role'] == 'Super Admin':
                return True, ""
            modules = []
            if user.get('modules_access'):
                modules = json.loads(user['modules_access']) if isinstance(user['modules_access'], str) else user['modules_access']
            if module_name in modules:
                return True, ""
            else:
                return False, f"Insufficient permissions for module: {module_name}"
        except Exception as e:
            if conn: conn.rollback()
            return False, f"Database error in authorization: {str(e)}"
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    return True, ""

def verify_write_access_detailed(module_name=None):
    return verify_access_detailed(module_name, is_write=True)

def verify_read_access_detailed(module_name=None):
    return verify_access_detailed(module_name, is_write=False)

def verify_write_key(module_name=None):
    is_auth, _ = verify_write_access_detailed(module_name)
    return is_auth
    
def verify_read_key(module_name=None):
    is_auth, _ = verify_read_access_detailed(module_name)
    return is_auth

# =====================================================================
# MODULE 0: USERS (RBAC)
# =====================================================================

@app.route('/api/users/list', methods=['GET', 'OPTIONS'])
@app.route('/users/view', methods=['GET', 'OPTIONS'])
def get_users():
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_read_key('User Management'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT user_id, full_name, contact_number, email_id, designation, role, username, modules_access, status, last_login, created_at FROM users")
        results = cursor.fetchall()
        for res in results:
            if res.get('modules_access'):
                res['modules_access'] = json.loads(res['modules_access']) if isinstance(res['modules_access'], str) else res['modules_access']
            if res.get('last_login'):
                res['last_login'] = str(res['last_login'])
            if res.get('created_at'):
                res['created_at'] = str(res['created_at'])
        return jsonify(results)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/users/view/<int:user_id>', methods=['GET', 'OPTIONS'])
def get_user_by_id(user_id):
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_read_key('User Management'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT user_id, full_name, contact_number, email_id, designation, role, username, modules_access, status, last_login, created_at, updated_at FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found."}), 404
            
        if user.get('modules_access'):
            user['modules_access'] = json.loads(user['modules_access']) if isinstance(user['modules_access'], str) else user['modules_access']
        if user.get('last_login'):
            user['last_login'] = str(user['last_login'])
        if user.get('created_at'):
            user['created_at'] = str(user['created_at'])
        if user.get('updated_at'):
            user['updated_at'] = str(user['updated_at'])
            
        return jsonify({"success": True, "user": user})
    except Exception as e:
        return jsonify({"success": False, "error": "Unable to load user details."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/users/add', methods=['POST', 'OPTIONS'])
def add_user():
    if request.method == 'OPTIONS':
        return '', 200
        
    print("\n" + "="*50)
    print("=== INCOMING REQUEST: POST /users/add ===")
    print("=== HEADERS ===")
    for key, value in request.headers.items():
        print(f"{key}: {value}")
        
    is_auth, err_msg = verify_write_access_detailed('User Management')
    if not is_auth:
        print(f"=== AUTHORIZATION FAILED ===\nReason: {err_msg}")
        return jsonify({"success": False, "message": err_msg}), 401
        
    data = request.json or {}
    print("=== REQUEST BODY ===")
    print(json.dumps(data, indent=2))
    try:
        import traceback
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        email = data.get('email_id')
        if email and email.strip():
            cursor.execute("SELECT * FROM users WHERE contact_number = %s OR email_id = %s OR username = %s", 
                           (data.get('contactNumber'), email, data.get('username')))
        else:
            cursor.execute("SELECT * FROM users WHERE contact_number = %s OR username = %s", 
                           (data.get('contactNumber'), data.get('username')))
            
        if cursor.fetchone():
            err_msg = "User with this contact number, email, or username already exists"
            return jsonify({"success": False, "error": err_msg, "message": err_msg}), 400            
        
        password = data.get('password')
        hashed_password = generate_password_hash(password) if password else generate_password_hash('default123')
        role = data.get('role', '')
        submitted_modules = data.get('modulesAccess')
        
        ALLOWED_MODULES = [
            "Dashboard", "Order Initiation", "Specifications", "Stock Check",
            "BOM Calculation", "Inventory Check", "Material Allocation", "Procurement",
            "Production", "Quality & Packing", "Logistics", "Accounts",
            "Store", "Reports", "System Logs", "User Management"
        ]
        
        if submitted_modules is None:
            if role == 'Super Admin':
                submitted_modules = ALLOWED_MODULES.copy()
            elif role == 'Admin':
                submitted_modules = ["Dashboard", "Reports", "Inventory Check", "Accounts", "User Management"]
            elif 'Manager' in role:
                submitted_modules = ["Dashboard", "Order Initiation", "Production", "Reports"]
            elif 'User' in role or role in ["Operator", "Viewer"]:
                submitted_modules = ["Dashboard", "Order Initiation"]
            else:
                submitted_modules = []
                
        # Validate final set of permissions
        final_modules = [m for m in submitted_modules if m in ALLOWED_MODULES]
        modules_json = json.dumps(final_modules)
        
        # Handle optional email uniqueness constraint
        final_email = email.strip() if email and email.strip() else f"no-email-{data.get('contactNumber')}@sasons.local"
        
        query = """INSERT INTO users (full_name, contact_number, email_id, designation, role, username, password_hash, modules_access, status) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        params = (data.get('fullName'), data.get('contactNumber'), final_email, data.get('designation', ''), data.get('role'), data.get('username'), hashed_password, modules_json, data.get('status', 'Active'))
        
        print("=== SQL EXECUTION ===")
        print("Executing SQL:", query)
        print("With parameters:", params)
        
        cursor.execute(query, params)
        conn.commit()
        cursor.close(); conn.close()
        
        print("=== RESPONSE STATUS: 201 Created ===")
        print("="*50 + "\n")
        return jsonify({"success": True, "message": "User created successfully"}), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        if conn: conn.rollback()
        
        err_response = {"success": False, "error": str(e), "message": str(e)}
        print("=== RESPONSE STATUS: 500 Internal Server Error ===")
        print(json.dumps(err_response, indent=2))
        print("="*50 + "\n")
        return jsonify(err_response), 500

@app.route('/users/update/<int:user_id>', methods=['PUT', 'OPTIONS'])
def update_user(user_id):
    if request.method == 'OPTIONS':
        return '', 200
    is_auth, err_msg = verify_write_access_detailed('User Management')
    if not is_auth:
        return jsonify({"success": False, "message": err_msg}), 401
    data = request.json or {}
    try:
        import traceback
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch the existing user
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        existing_user = cursor.fetchone()
        if not existing_user:
            return jsonify({"success": False, "message": "User not found"}), 404
            
        # 2. Extract values, defaulting to existing if not provided
        full_name = data.get('fullName') if 'fullName' in data and data.get('fullName') is not None else existing_user.get('full_name')
        contact_number = data.get('contactNumber') if 'contactNumber' in data and data.get('contactNumber') is not None else existing_user.get('contact_number')
        email_id = data.get('email_id') if 'email_id' in data and data.get('email_id') is not None else existing_user.get('email_id')
        designation = data.get('designation') if 'designation' in data and data.get('designation') is not None else existing_user.get('designation')
        role = data.get('role') if 'role' in data and data.get('role') is not None else existing_user.get('role')
        username = data.get('username') if 'username' in data and data.get('username') is not None else existing_user.get('username')
        status = data.get('status') if 'status' in data and data.get('status') is not None else existing_user.get('status')
        
        ALLOWED_MODULES = [
            "Dashboard", "Order Initiation", "Specifications", "Stock Check",
            "BOM Calculation", "Inventory Check", "Material Allocation", "Procurement",
            "Production", "Quality & Packing", "Logistics", "Accounts",
            "Store", "Reports", "System Logs", "User Management"
        ]

        if 'modulesAccess' in data and data.get('modulesAccess') is not None:
            submitted_modules = data.get('modulesAccess')
            if not isinstance(submitted_modules, list):
                submitted_modules = []
        else:
            if role == 'Super Admin':
                submitted_modules = ALLOWED_MODULES.copy()
            elif role == 'Admin':
                submitted_modules = ["Dashboard", "Reports", "Inventory Check", "Accounts", "User Management"]
            elif 'Manager' in role:
                submitted_modules = ["Dashboard", "Order Initiation", "Production", "Reports"]
            elif 'User' in role or role in ["Operator", "Viewer"]:
                submitted_modules = ["Dashboard", "Order Initiation"]
            else:
                existing_modules = existing_user.get('modules_access')
                submitted_modules = json.loads(existing_modules) if isinstance(existing_modules, str) else (existing_modules or [])

        # Validate final set of permissions
        final_modules = [m for m in submitted_modules if m in ALLOWED_MODULES]
        modules_json = json.dumps(final_modules)
            
        # Check duplicates for other users
        if email_id and isinstance(email_id, str) and email_id.strip():
            cursor.execute("SELECT * FROM users WHERE (contact_number = %s OR email_id = %s OR username = %s) AND user_id != %s", 
                           (contact_number, email_id, username, user_id))
        else:
            cursor.execute("SELECT * FROM users WHERE (contact_number = %s OR username = %s) AND user_id != %s", 
                           (contact_number, username, user_id))
                           
        if cursor.fetchone():
            err_msg = "User with this contact number, email, or username already exists"
            return jsonify({"success": False, "error": err_msg, "message": err_msg}), 400
            
        final_email = email_id.strip() if email_id and isinstance(email_id, str) and email_id.strip() else f"no-email-{contact_number}@sasons.local"
        
        # 3. Handle password
        password_hash = existing_user.get('password_hash')
        if data.get('password') and data.get('password').strip():
            password_hash = generate_password_hash(data.get('password'))

        query = """UPDATE users SET full_name=%s, contact_number=%s, email_id=%s, designation=%s, role=%s, 
                   username=%s, password_hash=%s, modules_access=%s, status=%s WHERE user_id=%s"""
        params = (full_name, contact_number, final_email, designation, role, username, password_hash, modules_json, status, user_id)
        
        print("Executing SQL:", query)
        print("With parameters:", params)
        cursor.execute(query, params)
            
        conn.commit()
        cursor.close(); conn.close()
        return jsonify({"success": True, "message": "User updated successfully"}), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        if conn: conn.rollback()
        return jsonify({"success": False, "error": str(e), "message": str(e)}), 500

@app.route('/users/delete/<int:user_id>', methods=['DELETE', 'OPTIONS'])
def delete_user(user_id):
    if request.method == 'OPTIONS':
        return '', 200
    is_auth, err_msg = verify_write_access_detailed('User Management')
    if not is_auth:
        return jsonify({"success": False, "message": err_msg}), 401
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        
        # Reset AUTO_INCREMENT safely after deletion
        cursor.execute("SELECT COALESCE(MAX(user_id), 0) + 1 AS next_id FROM users")
        row = cursor.fetchone()
        next_id = row['next_id'] if row else 1
        cursor.execute(f"ALTER TABLE users AUTO_INCREMENT = {next_id}")
        
        conn.commit()
        cursor.close(); conn.close()
        return jsonify({"success": True, "message": "User deleted successfully"}), 200
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/users/login', methods=['POST', 'OPTIONS'])
def login_user():
    if request.method == 'OPTIONS':
        return '', 200
        
    data = request.json or {}
    contact = data.get('contactNumber') or data.get('contactNo') or data.get('email')
    password = data.get('password')
    
    try:
        import traceback
        
        # Log variables before processing
        print("=== LOGIN API DEBUG ===")
        print(f"data: {data}")
        print(f"contact: {contact}")
        print(f"password: {'***' if password else None}")
        
        if not contact or not password:
            return jsonify({"success": False, "error": "Invalid username or password"}), 401
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE contact_number = %s OR email_id = %s OR username = %s", (contact, contact, contact))
        user = cursor.fetchone()
        
        print(f"user found in DB: {bool(user)}")
        
        if not user:
            cursor.close(); conn.close()
            return jsonify({"success": False, "error": "User does not exist."}), 404
                
        try:
            is_valid_password = check_password_hash(user['password_hash'], password)
        except Exception as e:
            traceback.print_exc()
            cursor.close(); conn.close()
            return jsonify({"success": False, "error": f"Password verification failed: {str(e)}"}), 500
            
        if not is_valid_password:
            cursor.close(); conn.close()
            return jsonify({"success": False, "error": "Incorrect password."}), 401
            
        if user.get('status') == 'Disabled':
            cursor.close(); conn.close()
            return jsonify({
                "success": False, 
                "message": "Your account has been deactivated. Please contact your Super Admin."
            }), 403
            
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = %s", (user['user_id'],))
        conn.commit()
        
        if user.get('modules_access'):
            user['modules_access'] = json.loads(user['modules_access']) if isinstance(user['modules_access'], str) else user['modules_access']
        else:
            user['modules_access'] = []
            
        if 'password_hash' in user:
            del user['password_hash']
        
        # FIX FOR LEGACY FRONTEND AUTH CONTEXT MAPPING
        user['contact_no'] = user.get('contact_number')
        user['email'] = user.get('email_id')
        user['id'] = user.get('user_id')
        
        cursor.close(); conn.close()
        return jsonify({"success": True, "user": user}), 200
    except Exception as e:
        import traceback
        import os
        
        print("\n" + "="*50)
        print("=== LOGIN EXCEPTION CAUGHT ===")
        print(f"Request Payload: {data}")
        print(f"Database Selected: {os.getenv('DB_NAME')}")
        print("Table Used: users")
        print("Exception Traceback:")
        traceback.print_exc()
        print("="*50 + "\n")
        
        return jsonify({"success": False, "error": "Internal server error. Please check backend logs."}), 500


# =====================================================================
# MODULE 1: CUSTOMERS (FULLY INSTALLED WITH ALL 8 COLUMNS)
# =====================================================================

@app.route('/customers/view', methods=['GET'])
def get_customers():
    if not verify_read_key('Order Initiation'): 
        return "Unauthorized: Invalid View API Key", 401
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customers")
    results = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(results)

@app.route('/customers/add', methods=['POST'])
def add_customer():
    if not verify_write_key('Sales'): 
        return "Unauthorized: Invalid Write API Key or RBAC", 401
    
    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "Request body must be valid JSON"}), 400
            
        # Ensure name is provided as required by your DB schema
        if not data.get('customer_name'):
            return jsonify({"success": False, "error": "customer_name is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # SQL execution map including all 8 descriptive columns matching your MySQL schema
        query = """
            INSERT INTO customers (
                customer_name, contact_person, phone, email, 
                shipping_address, billing_address, gst_number, cin_number
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            data.get('customer_name'),
            data.get('contact_person') or 'Default Contact',
            data.get('phone') or '',
            data.get('email') or '',
            data.get('shipping_address') or '',
            data.get('billing_address') or '',
            data.get('gst_number') or '',
            data.get('cin_number') or ''
        )
        
        cursor.execute(query, values)
        conn.commit()
        
        new_customer_id = cursor.lastrowid
        cursor.close(); conn.close()
        
        return jsonify({
            "success": True,
            "message": "Customer saved directly to database successfully!",
            "customer_id": new_customer_id
        }), 201

    except Exception as e:
        return jsonify({"success": False, "error": f"Database insertion error: {str(e)}"}), 500

@app.route('/api/customers/validate_address', methods=['POST'])
def validate_customer_address():
    if not verify_read_key('Order Initiation') and not verify_read_key('Sales'): 
        return "Unauthorized", 401
    
    data = request.json
    address = data.get('address')
    pin = data.get('pin_code')
    
    if not address or not pin:
        return jsonify({"exists": False, "error": "Address and pin code required"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT customer_name FROM customers WHERE delivery_address = %s AND pin_code = %s", (address, pin))
    match = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if match:
        return jsonify({"exists": True, "data": match})
    return jsonify({"exists": False})

@app.route('/api/customers/update_address', methods=['POST'])
def update_customer_address():
    if not verify_write_key('Order Initiation') and not verify_write_key('Sales'): 
        return "Unauthorized", 401
    
    data = request.json
    customer_name = data.get('customer_name')
    address = data.get('address')
    pin_code = data.get('pin_code')
    
    if not customer_name:
        return jsonify({"success": False, "error": "customer_name is required"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Update both fields as a single transaction block
        cursor.execute(
            "UPDATE customers SET delivery_address = %s, pin_code = %s WHERE customer_name = %s",
            (address, pin_code, customer_name)
        )
        conn.commit()
        return jsonify({"success": True, "message": "Address updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# =====================================================================
# MODULE 2: PURCHASE ORDERS
# =====================================================================

@app.route('/purchase_orders/view', methods=['GET'])
def get_purchase_orders():
    if not verify_read_key('Order Initiation'):
        return jsonify({"success": False, "error": "Unauthorized: Invalid View API Key"}), 401
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM purchase_orders ")
    results = cursor.fetchall()
    
    unique_results = []
    seen_pos = set()
    for row in results:
        po = row.get("po_number")
        if po and po not in seen_pos:
            unique_results.append(row)
            seen_pos.add(po)
            
    cursor.close(); conn.close()
    return jsonify(unique_results)

@app.route('/api/orders', methods=['GET'])
def get_orders_by_stage():
    import urllib.parse
    stage = request.args.get('stage')
    if stage:
        stage = urllib.parse.unquote(stage).strip()
    if not stage:
        return jsonify([]), 200
    
    if not verify_read_key('Order Initiation'):
        return jsonify([]), 200
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # Filter by stage and exclude completed orders (status != 'COMPLETED')
        query = "SELECT po_number, order_date, delivery_date, customer_name, status, stage FROM purchase_orders WHERE stage = %s AND status != 'COMPLETED'"
        cursor.execute(query, (stage,))
        results = cursor.fetchall()
        
        if not results:
            results = []
            
        # Clean dates for consistency
        for row in results:
            if row.get('order_date'):
                row['order_date'] = clean_mysql_date(str(row['order_date']))
            if row.get('delivery_date'):
                row['delivery_date'] = clean_mysql_date(str(row['delivery_date']))
                
        return jsonify(results), 200
    except Exception as e:
        print(f"Error in /api/orders: {e}")
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/purchase_orders/po-numbers', methods=['GET'])
def get_existing_po_numbers():
    """Returns a list of all PO numbers already saved in the database.
    Used by the frontend to prevent generating duplicate PO numbers."""
    if not verify_read_key('Order Initiation'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT DISTINCT po_number FROM purchase_orders WHERE po_number IS NOT NULL")
    results = cursor.fetchall()
    cursor.close(); conn.close()
    
    # Use a Python set to ensure absolute uniqueness before jsonifying
    unique_pos = list(set([r["po_number"] for r in results]))
    return jsonify({"success": True, "po_numbers": unique_pos})

@app.route('/purchase_orders/details/<string:po_number>', methods=['GET'])
def get_purchase_order_details(po_number):
    if not verify_read_key('Order Initiation'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch main PO details (This contains the real total value/pieces)
        cursor.execute("SELECT * FROM purchase_orders WHERE po_number = %s", (po_number,))
        po_data = cursor.fetchone()
        
        if not po_data:
            cursor.close(); conn.close()
            return jsonify({"success": False, "error": "Purchase order not found"}), 404
            
        if po_data.get('order_date'):
            po_data['order_date'] = clean_mysql_date(str(po_data['order_date']))
            
        if po_data.get('delivery_date'):
            po_data['delivery_date'] = clean_mysql_date(str(po_data['delivery_date']))
            
        # 2. Fetch specifications
        cursor.execute("SELECT * FROM specifications WHERE po_number = %s", (po_number,))
        specs = cursor.fetchall()
        
        # CORE FIX: If the specification row is missing a quantity, 
        # pull the quantity or pieces directly from the parent purchase order!
        fallback_qty = po_data.get('total_pieces') or po_data.get('quantity') or 100 # DO NOT fallback to total_value
        
        for spec in specs:
            if not spec.get('quantity') or spec['quantity'] == 0:
                spec['quantity'] = fallback_qty  # Force the 0 to become the real order size!
                
            # Calculate dynamic stock available based on SKU, sizes, and colors
            garment_desc = str(spec.get('item_description') or '').strip()
            sizes = [sz.strip() for sz in str(spec.get('size') or '').split(',') if sz.strip() and sz.strip() != 'Standard']
            colors = [c.strip() for c in str(spec.get('color') or '').split(',') if c.strip()]
            
            stock_query = "SELECT SUM(available_qty) as total, SUM(min_required) as total_min, MAX(description) as g_desc FROM store_garments WHERE is_deleted = 0 AND (LOWER(sku_no) = LOWER(%s) OR LOWER(description) LIKE LOWER(%s))"
            params = [garment_desc, f"%{garment_desc}%"]
            
            if sizes:
                placeholders = ','.join(['%s'] * len(sizes))
                stock_query += f" AND size IN ({placeholders})"
                params.extend(sizes)
                
            if colors:
                placeholders = ','.join(['%s'] * len(colors))
                stock_query += f" AND color IN ({placeholders})"
                params.extend(colors)
                
            cursor.execute(stock_query, tuple(params))
            res = cursor.fetchone()
            stock_available = float(res['total'] or 0) if res else 0
            min_req = float(res['total_min'] or 0) if res else 0
            
            spec['stock_available'] = stock_available
            spec['garment_name'] = res['g_desc'] if res and res.get('g_desc') else garment_desc
            
            if stock_available <= 0:
                stock_status = "Out of Stock"
            elif stock_available <= min_req:
                stock_status = "Low Stock"
            else:
                stock_status = "Available"
                
            spec['stockStatus'] = stock_status
            
            # Persist accurate stock status in the database
            if spec.get('spec_id'):
                cursor.execute("UPDATE specifications SET stock_available = %s, stock_status = %s WHERE spec_id = %s", (stock_available, stock_status, spec['spec_id']))
                conn.commit()
            
            # Log the complete matching process as requested
            print(f"--- MATCHING PROCESS LOG ---")
            print(f"Selected PO: {po_number}")
            print(f"Garment ID/SKU: {garment_desc}")
            print(f"Size: {sizes}")
            print(f"Color: {colors}")
            print(f"Required Qty: {spec['quantity']}")
            print(f"Store Available Qty: {stock_available}")
            print(f"Store Min Required Qty: {min_req}")
            print(f"Final Status: {stock_status}")
            print(f"----------------------------")
                
            # Explicitly separate physical count from financial totals for the frontend
            spec['required_qty'] = spec['quantity']
            spec['total_cost_value'] = po_data.get('total_value', 0.0)
            
            desc_str = str(spec.get('item_description') or '').lower()
            name_str = str(spec.get('garment_name') or '').lower()
            cat_str = str(spec.get('category') or '').lower()
            
            if ('uniform' in desc_str or 'uniform' in name_str) and cat_str in ['shirt', 'pant']:
                spec['is_uniform'] = True
            else:
                spec['is_uniform'] = False
        
        po_data["specs"] = specs
        
        cursor.execute("SELECT * FROM order_specifications WHERE LOWER(po_number) = LOWER(%s)", (po_number,))
        order_specs = cursor.fetchall()
        for row in order_specs:
            if row.get('sizes') and isinstance(row['sizes'], str):
                row['sizes'] = [s.strip() for s in row['sizes'].split(',') if s.strip()]
            if row.get('colors') and isinstance(row['colors'], str):
                row['colors'] = [c.strip() for c in row['colors'].split(',') if c.strip()]
        po_data["specifications"] = order_specs
        
        # 3. Fetch BOM calculations
        cursor.execute(
            """
            SELECT 
                bom.*, 
                bom.final_qty AS required_qty,
                bom.amount AS total_cost_value,
                mat.material_name, 
                mat.unit, 
                mat.unit_price,
                mat.available_qty,
                mat.min_required
            FROM bill_of_materials bom
            JOIN store_materials mat ON bom.material_id = mat.material_id
            WHERE bom.po_number = %s
            """, (po_number,)
        )
        
        bom_calcs = cursor.fetchall()
        for item in bom_calcs:
            # Cast numerical fields explicitly to eliminate frontend string comparison glitches
            req_qty = float(item.get('required_qty') or 0)
            avail_qty = float(item.get('available_qty') or 0)
            min_req = float(item.get('min_required') or 0)
            
            item['required_qty'] = req_qty
            item['available_qty'] = avail_qty
            
            # Status rules: Base Availability
            if avail_qty <= 0:
                item['status'] = "Out of Stock"
            elif avail_qty <= min_req:
                item['status'] = "Low Stock"
            else:
                item['status'] = "Available"
                
            # Allocation Status (BOM Check)
            if avail_qty >= req_qty:
                item['allocation_status'] = "Fully Available"
            else:
                item['allocation_status'] = "Shortage"
                
            if item.get('bom_id'):
                cursor.execute("UPDATE bill_of_materials SET material_status = %s, allocation_status = %s WHERE bom_id = %s", (item['status'], item['allocation_status'], item['bom_id']))
                
        conn.commit()
                
        po_data["bom_calculations"] = bom_calcs
        
        cursor.close(); conn.close()
        
        # Frontend expects the PO object returned directly at the top level
        po_data['success'] = True
        po_data['poNumber'] = po_data.get('po_number')
        return jsonify(po_data)

    except Exception as e:
        if cursor: cursor.close()
        if conn: conn.close()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200


def clean_mysql_date(date_string):
    """
    Robust wrapper leveraging format_db_date (dateutil.parser) to ensure incoming strings
    from the frontend (e.g., ISO formats) are strictly cast to YYYY-MM-DD for MySQL storage.
    """
    return format_db_date(date_string)


@app.route('/purchase_orders/add', methods=['POST'])
def add_purchase_order():
    if not verify_write_key('Order Initiation'):
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400
        
    # DIAGNOSTIC PRINT: Check your terminal to see what the frontend sent!
    print("--- RECEIVED FRONTEND DATA ---")
    print(data)
    print("------------------------------")
        
    if data.get('status') == 'SUBMITTED':
        if not data.get('total_value') or not data.get('order_date'):
            return jsonify({"success": False, "error": "Missing required fields for submission."}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        po_num = data.get('poNumber') or data.get('po_number')
        
        if po_num:
            import re, urllib.parse
            clean_po = urllib.parse.unquote(str(po_num)).strip()
            clean_po = re.sub(r'^PO:\s*', '', clean_po, flags=re.IGNORECASE)
            clean_po = clean_po.split('|')[0].strip()
            po_num = re.sub(r'\s*\(.*?\)', '', clean_po).strip()
        
        # Look across all possible naming variations from the frontend
        cust_input = (
            data.get('customerName') or 
            data.get('customer_id') or 
            data.get('customer_name') or 
            data.get('customer')
        )
        
        # =====================================================================
        # BULLETPROOF NESTED CUSTOMER HANDLING
        # =====================================================================
        final_customer_id = None

        if cust_input:
            cust_input = str(cust_input).strip()

        # If customer input is missing, default to a fallback string row
        if not cust_input or cust_input == "":
            cust_input = "Default Walk-in Customer"

        # If it is a name string rather than an ID integer, process the logic
        if not str(cust_input).isdigit():
            # Check if this customer already exists to avoid duplicate rows
            cursor.execute("SELECT customer_id FROM customers WHERE customer_name = %s", (str(cust_input),))
            existing_cust = cursor.fetchone()
            
            if existing_cust:
                final_customer_id = existing_cust[0]
            else:
                # Dynamically create the parent customer record first
                c_person = data.get('contactPerson') or data.get('contact_person') or 'Default Contact'
                c_phone = data.get('contactPhone') or data.get('contact_phone') or '0000000000'
                c_email = data.get('contactEmail') or data.get('contact_email') or 'info@customer.com'
                
                cust_query = """
                    INSERT INTO customers (customer_name, contact_person, phone, email) 
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(cust_query, (str(cust_input), c_person, c_phone, c_email))
                final_customer_id = cursor.lastrowid
        else:
            final_customer_id = int(cust_input)

        # Check if this PO number already exists
        cursor.execute("SELECT po_number FROM purchase_orders WHERE po_number = %s", (po_num,))
        existing = cursor.fetchone()

        status = data.get('status') or 'DRAFT'
        tot_val = data.get('poAmount') or data.get('total_value') or 0
        
        formatted_order_date = clean_mysql_date(data.get('poDate') or data.get('order_date'))
        o_date = formatted_order_date
        
        # New delivery_date logic
        del_date = clean_mysql_date(data.get('deliveryDate') or data.get('delivery_date'))
        
        c_person = data.get('contactPerson') or data.get('contact_person') or data.get('contact_name') or ''
        c_phone = data.get('contactPhone') or data.get('contact_phone') or ''
        c_email = data.get('contactEmail') or data.get('contact_email') or ''
        d_type = data.get('deliveryType') or data.get('delivery_type') or ''
        d_addr = data.get('deliveryAddress') or data.get('delivery_address') or ''
        d_pin = data.get('deliveryPin') or data.get('delivery_pin') or ''
        b_comp = data.get('billTo') or data.get('billing_company') or ''
        b_addr = data.get('billingAddress') or data.get('billing_address') or ''
        b_pin = data.get('billingPin') or data.get('billing_pin') or ''
        gst = data.get('gstNo') or data.get('gst_number') or data.get('gst_no') or ''
        cin = data.get('cinNo') or data.get('cin_number') or data.get('cin_no') or ''
        tc = data.get('testCertificate') or data.get('test_certificate')
        t_cost = data.get('transportCost') or data.get('transport_cost')
        adv = data.get('advancedAmount') or data.get('advance_amount') or 0
        stg = normalize_stage(data.get('stage'))
        pt = data.get('paymentTerm') or data.get('payment_term')

        if existing:
            cursor.execute(
                """
                UPDATE purchase_orders SET 
                customer_id=%s, status=%s, total_value=%s, order_date=%s, delivery_date=%s, contact_person=%s, contact_phone=%s, contact_email=%s, delivery_type=%s, delivery_address=%s, delivery_pin=%s, billing_company=%s, billing_address=%s, billing_pin=%s, gst_number=%s, cin_number=%s, test_certificate=%s, transport_cost=%s, advance_amount=%s, stage=%s, payment_term=%s 
                WHERE po_number=%s
                """,
                (final_customer_id, status, tot_val, o_date, del_date, c_person, c_phone, c_email, d_type, d_addr, d_pin, b_comp, b_addr, b_pin, gst, cin, tc, t_cost, adv, stg, pt, po_num)
            )
        else:
            cursor.execute(
                """
                INSERT INTO purchase_orders (po_number, customer_id, status, total_value, order_date, delivery_date, contact_person, contact_phone, contact_email, delivery_type, delivery_address, delivery_pin, billing_company, billing_address, billing_pin, gst_number, cin_number, test_certificate, transport_cost, advance_amount, stage, payment_term) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (po_num, final_customer_id, status, tot_val, o_date, del_date, c_person, c_phone, c_email, d_type, d_addr, d_pin, b_comp, b_addr, b_pin, gst, cin, tc, t_cost, adv, stg, pt)
            )
        conn.commit()

        # Fetch the complete freshly generated order object
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM purchase_orders WHERE po_number = %s", (po_num,))
        order_record = cursor.fetchone()

        return jsonify({"success": True, "message": "Purchase Order updated successfully", "data": order_record}), 201
    except Exception as e:
        if conn:
            conn.rollback()
        err_str = str(e)
        if '1048' in err_str or 'ER_BAD_NULL_ERROR' in err_str or '23502' in err_str or 'constraint failed' in err_str.lower():
            return jsonify({"success": False, "orders": [], "message": str(e)}), 200
        return jsonify({"success": False, "error": err_str}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =====================================================================
# ALLOCATE PARTIAL
# =====================================================================
@app.route('/api/orders/allocate-partial', methods=['POST'])
def allocate_partial():
    if not verify_write_key('Stock Check'):
        return jsonify({"success": False, "error": "Unauthorized: Invalid Write API Key or RBAC"}), 401
    
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400
        
    po_number = data.get('poNumber')
    req_type = data.get('type')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if req_type == 'quality_packing':
            allocations = data.get('allocations', [])
            for alloc in allocations:
                garment_id = alloc.get('garment_id')
                allocate_qty = alloc.get('allocate_qty', 0)
                spec_id = alloc.get('spec_id')
                
                # Update store_garments by subtracting allocated_qty
                cursor.execute(
                    "UPDATE store_garments SET available_qty = GREATEST(0, available_qty - %s), blocked_qty = COALESCE(blocked_qty, 0) + %s WHERE garment_id = %s",
                    (allocate_qty, allocate_qty, garment_id)
                )
                
                # Update the allocated quantity persistently in specifications
                if spec_id:
                    cursor.execute(
                        "UPDATE specifications SET allocated_qty = COALESCE(allocated_qty, 0) + %s WHERE spec_id = %s",
                        (allocate_qty, spec_id)
                    )
            # Update PO stage to 'Quality & Packing'
            cursor.execute(
                "UPDATE purchase_orders SET stage = 'Quality & Packing' WHERE po_number = %s",
                (po_number,)
            )
        elif req_type == 'bom_calculation':
            # Update PO stage to 'BOM Calculation'
            cursor.execute(
                "UPDATE purchase_orders SET stage = 'BOM Calculation' WHERE po_number = %s",
                (po_number,)
            )
            
        conn.commit()
        return jsonify({"success": True, "message": "Allocation successful"}), 200
        
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# =====================================================================
# MODULE 3: INVENTORY
# =====================================================================

@app.route('/inventory/view', methods=['GET'])
def get_inventory():
    if not verify_read_key('Store'): 
        return "Unauthorized: Invalid View API Key", 401
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM inventory")
        results = cursor.fetchall()
        
        if not results:
            results = []
            
        for res in results:
            qty = float(res.get('current_stock') or 0)
            price = float(res.get('unit_price') or 0)
            res['total_price'] = qty * price
            
        return jsonify(results), 200
    except Exception as e:
        print(f"Error in /inventory/view: {e}")
        return jsonify([]), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/inventory/add', methods=['POST'])
def add_inventory():
    if not verify_write_key('Store'): 
        return "Unauthorized: Invalid Write API Key", 401
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inventory (material_name, current_stock, min_threshold, unit, hsn_code, description, blocked_qty, min_required, unit_price, total_price, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (data['material_name'], data['current_stock'], data['min_threshold'], data['unit'], data['hsn_code'], data.get('description', ''), data['blocked_qty'], data['min_required'], data['unit_price'], data['total_price'], data['status'])
    )
    conn.commit()
    cursor.close(); conn.close()
    return "Inventory item added successfully"


# =====================================================================
# MODULE 4: SPECIFICATIONS
# =====================================================================

@app.route('/specifications/view', methods=['GET'])
def get_specifications():
    if not verify_read_key('Order Specifications'): 
        return "Unauthorized: Invalid View API Key", 401
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM specifications")
    results = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(results)

@app.route('/specifications/add', methods=['POST'])
def add_specification():
    if not verify_write_key('Order Specifications'):
        return jsonify({"success": False, "error": "Unauthorized: Invalid Write API Key or RBAC"}), 401
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO specifications (po_number, fabric_type, size, color, style, remarks, item_description, pattern, stock_available, unit_price, photo_name, use_existing_stock) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                data.get('po_number'), data.get('fabric_type'), data.get('size'),
                data.get('color'), data.get('style', 'Regular'), data.get('remarks', ''),
                data.get('item_description'), data.get('pattern', ''),
                data.get('stock_available', 0), data.get('unit_price', 0),
                data.get('photo_name', ''), data.get('use_existing_stock', 0)
            )
        )
        conn.commit()
        return jsonify({"success": True, "message": "Specification added successfully"}), 201
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# =====================================================================
# MODULE 5: BILL OF MATERIALS (BOM)
# =====================================================================

@app.route('/bill_of_materials/view', methods=['GET'])
def get_bom():
    if not verify_read_key('Production'): 
        return "Unauthorized: Invalid View API Key", 401
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM bill_of_materials")
    results = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(results)

@app.route('/bill_of_materials/add', methods=['POST'])
def add_bom():
    if not verify_write_key('Production'): 
        return "Unauthorized: Invalid Write API Key", 401
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO bill_of_materials (po_number, material_id, per_piece_qty, final_qty, amount) VALUES (%s, %s, %s, %s, %s)",
        (data['po_number'], data['material_id'], data['per_piece_qty'], data['final_qty'], data['amount'])
    )
    conn.commit()
    cursor.close(); conn.close()
    return "Bill of Materials added successfully"


# =====================================================================
# MODULE 5.5: UNIFIED STORE ITEMS
# =====================================================================
@app.route('/store_items/view', methods=['GET', 'OPTIONS'])
def get_store_items():
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_read_key('Store'): 
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit
        search = request.args.get('search', '')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 'Material' as type, material_id as id, hsn_code, material_name as name, description, category, unit, 
                   NULL as pattern, NULL as gender, NULL as size, NULL as color, NULL as image_url,
                   available_qty, blocked_qty, min_required, unit_price, total_price, status 
            FROM store_materials 
            WHERE is_deleted = 0
            UNION ALL
            SELECT 'Garment' as type, garment_id as id, hsn_code, sku_no as name, description, category, NULL as unit, 
                   pattern, gender, size, color, image_url,
                   available_qty, blocked_qty, min_required, unit_price, total_price, status 
            FROM store_garments 
            WHERE is_deleted = 0
        """
        params = []
        if search:
            query = f"SELECT * FROM ({query}) as combined WHERE name LIKE %s OR category LIKE %s OR hsn_code LIKE %s"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        else:
            query = f"SELECT * FROM ({query}) as combined"
            
        cursor.execute(f"SELECT COUNT(*) as count FROM ({query}) as t", tuple(params))
        total_records = cursor.fetchone()['count']
        query += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cursor.execute(query, tuple(params))
        items = cursor.fetchall()
        return jsonify({
            "success": True,
            "data": items,
            "totalRecords": total_records,
            "totalPages": (total_records + limit - 1) // limit,
            "currentPage": page
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if 'cursor' in locals() and cursor: cursor.close()
        if 'conn' in locals() and conn: conn.close()

# =====================================================================
# MODULE 6: STORE MATERIALS
# =====================================================================

@app.route('/api/inventory/available-materials', methods=['GET', 'OPTIONS'])
def get_available_materials():
    if request.method == 'OPTIONS':
        return '', 200
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
        SELECT 
            COALESCE(s.item_description, 'Material') AS MATERIAL_NAME,
            0 AS REQUIRED_QTY,
            COALESCE(s.stock_available, 0) AS AVAILABLE_QTY,
            COALESCE(s.stock_available, 0) AS ALLOCATABLE_QTY,
            COALESCE(s.unit, 'units') AS UNIT,
            'Available' AS STATUS
        FROM store_materials s
        """
        cursor.execute(query)
        results = cursor.fetchall() or []
        
        for r in results:
            r['ALLOCATABLE_QTY'] = float(r.get('ALLOCATABLE_QTY') or 0)
            r['REQUIRED_QTY'] = float(r.get('REQUIRED_QTY') or 0)
            r['AVAILABLE_QTY'] = float(r.get('AVAILABLE_QTY') or 0)
            r['STATUS'] = 'Available'
            
        return jsonify(results), 200
    except Exception as e:
        print("[WARN] Error in /api/inventory/available-materials:", str(e))
        return jsonify([]), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/store_materials/view', methods=['GET', 'OPTIONS'])
def get_store_materials():
    if request.method == 'OPTIONS':
        return '', 200
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM store_materials WHERE COALESCE(is_deleted, 0) = 0")
        materials = cursor.fetchall() or []
        return jsonify(materials), 200
    except Exception as e:
        print("[WARN] Error in /store_materials/view:", str(e))
        return jsonify([]), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: INVENTORY CHECK ENDPOINT FOR STOCK CHECK PAGE
# =====================================================================

@app.route('/api/check-inventory', methods=['POST'])
def check_inventory():
    """
    Automatic Stock Checking Endpoint.
    Receives PO Number, fetches specs, compares with store_garments, and returns overall status.
    """
    conn = None
    cursor = None
    try:
        data = request.get_json()
        po_number = data.get('poNumber')
        if not po_number:
            return jsonify({"success": False, "error": "poNumber is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch the BOM for this PO
        cursor.execute("""
            SELECT bom.bom_id, bom.material_id as id, 
                   bom.final_qty as required_qty, 
                   COALESCE(mat.available_qty, 0) as available_qty,
                   COALESCE(mat.material_name, 'Unknown Material') as name,
                   COALESCE(mat.category, 'Unknown') as category,
                   COALESCE(mat.unit, 'units') as unit,
                   COALESCE(mat.min_required, 0) as min_required,
                   COALESCE(mat.status, 'Out of Stock') as original_status
            FROM bill_of_materials bom
            LEFT JOIN store_materials mat ON bom.material_id = mat.material_id
            WHERE bom.po_number = %s
        """, (po_number,))
        
        bom_items = cursor.fetchall()
        
        if not bom_items:
            bom_items = []
            
        status = "AVAILABLE"
        
        for item in bom_items:
            required = float(item.get('required_qty') or 0)
            available = float(item.get('available_qty') or 0)
            min_req = float(item.get('min_required') or 0)
            
            # 1. Base Availability Status
            if available <= 0:
                base_status = "Out of Stock"
            elif available <= min_req:
                base_status = "Low Stock"
            else:
                base_status = "Available"
                
            # 2. Allocation Status (BOM Check)
            allocation_status = "Fully Available"
            if required > available:
                status = "SHORTAGE" # Overall PO status remains SHORTAGE
                allocation_status = "Partially Available" if available > 0 else "Critical Shortage"
                
            item['materialName'] = item.get('name')
            item['requiredQty'] = required
            item['availableQty'] = available
            item['allocatableQty'] = min(required, available)
            item['status'] = base_status
            item['allocationStatus'] = allocation_status
            
            if item.get('bom_id'):
                cursor.execute("UPDATE bill_of_materials SET material_status = %s, allocation_status = %s WHERE bom_id = %s", (base_status, allocation_status, item['bom_id']))
                
        conn.commit()
                    
        return jsonify({
            "success": True,
            "status": status,
            "data": bom_items
        }), 200

    except Exception as e:
        print(f"[ERROR] /api/check-inventory: {str(e)}")
        # Fallback catch block returning [] instead of null
        return jsonify({
            "success": False, 
            "status": "SHORTAGE", 
            "data": [], 
            "error": "Internal database error occurred."
        }), 500
        
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# =====================================================================
# WORKFLOW ROUTER: STOCK CHECK TO BOM TRANSITION
# =====================================================================

@app.route('/purchase_orders/check-stock-allocation/<string:po_number>', methods=['POST'])
def check_stock_allocation(po_number):
    if not verify_write_key('Stock Check'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch the materials required for this specific PO from the Bill of Materials
        cursor.execute(
            """
            SELECT bom.material_id, bom.final_qty, mat.available_qty 
            FROM bill_of_materials bom
            JOIN store_materials mat ON bom.material_id = mat.material_id
            WHERE bom.po_number = %s
            """, (po_number,)
        )
        required_items = cursor.fetchall()
        
        # Assume stock is available until proven otherwise
        stock_is_insufficient = False
        
        # 2. Compare what the order needs against what is physically in the store
        for item in required_items:
            if float(item['final_qty']) > float(item['available_qty']):
                stock_is_insufficient = True
                break # We found a shortage, no need to keep checking
                
        # 3. IF stock is missing, update the PO stage so the application advances
        if stock_is_insufficient:
            cursor.execute(
                "UPDATE purchase_orders SET stage = 'BOM Calculation' WHERE po_number = %s",
                (po_number,)
            )
            conn.commit()
            
            cursor.close(); conn.close()
            return jsonify({
                "success": True, 
                "stock_available": False, 
                "redirectTo": "/bom-calculation",
                "message": "Stock insufficient. Order advanced to BOM Calculation stage."
            }), 200
            
        # Otherwise, if everything is in stock, proceed normally
        cursor.close(); conn.close()
        return jsonify({
            "success": True, 
            "stock_available": True, 
            "redirectTo": "/production",
            "message": "All items available in stock!"
        }), 200

    except Exception as e:
        if conn: conn.rollback()
        if cursor: cursor.close()
        if conn: conn.close()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200




# =====================================================================
# API: STOCK SPLIT & ALLOCATION ENGINE
# =====================================================================

@app.route('/api/orders/split', methods=['POST'])
def split_order():
    if not verify_write_key('Stock Check'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON payload provided"}), 400
        
    po_number = data.get('poNumber')
    route_to = data.get('routeTo')
    
    if not po_number:
        return jsonify({"success": False, "error": "poNumber is required"}), 400
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch main PO details for fallback quantity
        cursor.execute("SELECT * FROM purchase_orders WHERE po_number = %s", (po_number,))
        po_data = cursor.fetchone()
        
        if not po_data:
            return jsonify({"success": False, "error": "Purchase order not found"}), 404
            
        fallback_qty = po_data.get('total_pieces') or po_data.get('quantity') or 100 
        
        # 2. Retrieve all garment specifications for that Purchase Order
        cursor.execute("SELECT * FROM specifications WHERE po_number = %s", (po_number,))
        specs = cursor.fetchall()
        
        # 3. For each spec, check stock and allocate
        all_fully_allocated = True
        total_overall_allocated = 0
        
        for spec in specs:
            required_qty = float(spec.get('quantity') or 0)
            if required_qty == 0:
                required_qty = float(fallback_qty)
                
            garment_desc = str(spec.get('item_description') or '').strip()
            sizes = [sz.strip() for sz in str(spec.get('size') or '').split(',') if sz.strip() and sz.strip() != 'Standard']
            colors = [c.strip() for c in str(spec.get('color') or '').split(',') if c.strip()]
            
            # Fetch available garments matching criteria
            query = """
                SELECT garment_id, available_qty 
                FROM store_garments 
                WHERE is_deleted = 0 AND available_qty > 0 AND (LOWER(sku_no) = LOWER(%s) OR LOWER(description) LIKE LOWER(%s))
            """
            params = [garment_desc, f"%{garment_desc}%"]
            
            if sizes:
                placeholders = ','.join(['%s'] * len(sizes))
                query += f" AND size IN ({placeholders})"
                params.extend(sizes)
                
            if colors:
                placeholders = ','.join(['%s'] * len(colors))
                query += f" AND color IN ({placeholders})"
                params.extend(colors)
                
            cursor.execute(query, tuple(params))
            garments = cursor.fetchall()
            
            # Allocate across matching garments until required_qty is fulfilled
            remaining_req = required_qty
            total_allocated = 0
            
            for garment in garments:
                if remaining_req <= 0:
                    break
                    
                avail_qty = float(garment['available_qty'] or 0)
                if avail_qty > 0:
                    allocate_qty = min(avail_qty, remaining_req)
                    remaining_req -= allocate_qty
                    total_allocated += allocate_qty
                    
                    # Deduct from store
                    cursor.execute("UPDATE store_garments SET available_qty = GREATEST(0, available_qty - %s), blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = GREATEST(0, available_qty - %s) * unit_price WHERE garment_id = %s", (allocate_qty, allocate_qty, allocate_qty, garment['garment_id']))
                    
                    # Log transaction
                    cursor.execute(
                        "INSERT INTO store_transactions (item_type, item_id, transaction_type, quantity, remarks) VALUES ('Garment', %s, 'OUT', %s, %s)",
                        (garment['garment_id'], allocate_qty, f"Allocated for PO {po_number}")
                    )
            
            total_overall_allocated += total_allocated
            
            if remaining_req > 0:
                all_fully_allocated = False
            
            if total_allocated > 0:
                try:
                    cursor.execute("UPDATE specifications SET use_existing_stock = %s WHERE spec_id = %s", (total_allocated, spec['spec_id']))
                except Exception:
                    pass
        
        # 4. Route based on frontend request
        new_stage = "BOM Calculation"
        if route_to in ('split-quality-packing', 'split-bom-calculation'):
            if total_overall_allocated == 0 or all_fully_allocated:
                if conn: conn.rollback()
                return jsonify({"success": False, "error": "Order cannot be split. It must be partially available."}), 400
                
            new_po_number = f"{po_number}-Q"
            cursor.execute("SELECT po_number FROM purchase_orders WHERE po_number = %s", (new_po_number,))
            if cursor.fetchone():
                if conn: conn.rollback()
                return jsonify({"success": False, "error": "This order has already been split."}), 400
                
            # Copy purchase_orders row
            po_keys = [k for k in po_data.keys() if k not in ('id', 'created_at', 'updated_at', 'po_number', 'stage')]
            cols = ['po_number', 'stage'] + po_keys
            vals = [new_po_number, 'Quality & Packing'] + [po_data[k] for k in po_keys]
            placeholders = ', '.join(['%s'] * len(cols))
            cursor.execute(f"INSERT INTO purchase_orders ({', '.join(cols)}) VALUES ({placeholders})", tuple(vals))
            
            # Fetch updated specs to split them
            cursor.execute("SELECT * FROM specifications WHERE po_number = %s", (po_number,))
            updated_specs = cursor.fetchall()
            
            for spec in updated_specs:
                allocated = float(spec.get('use_existing_stock') or 0)
                orig_quantity = float(spec.get('quantity') or fallback_qty)
                
                if allocated > 0:
                    spec_keys = [k for k in spec.keys() if k not in ('spec_id', 'created_at', 'updated_at', 'po_number', 'quantity', 'use_existing_stock')]
                    s_cols = ['po_number', 'quantity', 'use_existing_stock'] + spec_keys
                    s_vals = [new_po_number, allocated, allocated] + [spec[k] for k in spec_keys]
                    s_placeholders = ', '.join(['%s'] * len(s_cols))
                    cursor.execute(f"INSERT INTO specifications ({', '.join(s_cols)}) VALUES ({s_placeholders})", tuple(s_vals))
                
                new_orig_qty = orig_quantity - allocated
                if new_orig_qty > 0:
                    cursor.execute("UPDATE specifications SET quantity = %s, use_existing_stock = 0 WHERE spec_id = %s", (new_orig_qty, spec['spec_id']))
                else:
                    cursor.execute("DELETE FROM specifications WHERE spec_id = %s", (spec['spec_id'],))
                    
            cursor.execute("UPDATE purchase_orders SET stage = %s WHERE po_number = %s", ("BOM Calculation", po_number))
            conn.commit()
            return jsonify({"success": True, "message": f"Order split successfully."}), 200
            
        elif route_to == 'quality-packing':
            if not all_fully_allocated:
                if conn: conn.rollback()
                return jsonify({"success": False, "error": "Cannot skip to Quality & Packing. Stock is not fully available for all items."}), 400
            new_stage = "Quality & Packing"
            
            cursor.execute("UPDATE purchase_orders SET stage = %s WHERE po_number = %s", (new_stage, po_number))
        elif route_to == 'calculate-bom':
            if total_overall_allocated > 0:
                if conn: conn.rollback()
                return jsonify({"success": False, "error": "Cannot skip to BOM Calculation. Stock is not 0."}), 400
            new_stage = "BOM Calculation"
            
            cursor.execute("UPDATE purchase_orders SET stage = %s WHERE po_number = %s", (new_stage, po_number))
        elif route_to == 'bom-calculation':
            new_stage = "BOM Calculation"
            cursor.execute("UPDATE purchase_orders SET stage = %s WHERE po_number = %s", (new_stage, po_number))
        conn.commit()
        
        return jsonify({"success": True, "message": f"Order allocated and routed to {new_stage}"}), 200

    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
        
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: STOCK VALIDATION AND ROUTING ENGINE
# =====================================================================

@app.route('/api/orders/validate-stock', methods=['POST'])
def api_validate_stock():
    if not verify_write_key('Stock Check'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON payload provided"}), 400
        
    po_number = data.get('po_number') or data.get('poNumber')
    sku_no = data.get('sku_no') or data.get('skuNo')
    req_qty_raw = data.get('required_qty') or data.get('requiredQty', 0)
    req_qty = float(req_qty_raw) if req_qty_raw else 0.0
    
    if not po_number or not sku_no:
        return jsonify({"success": False, "error": "po_number and sku_no are required"}), 400
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch pre-stitched stock (mapped to store_garments)
        cursor.execute("SELECT garment_id, available_qty FROM store_garments WHERE sku_no = %s AND is_deleted = 0", (sku_no,))
        garment = cursor.fetchone()
        
        available_qty = float(garment['available_qty']) if garment and garment['available_qty'] else 0.0
        
        # 2. Evaluate Match Scenarios
        if available_qty >= req_qty:
            # SCENARIO A: Full Availability Match
            cursor.execute("UPDATE store_garments SET available_qty = GREATEST(0, available_qty - %s), blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = GREATEST(0, available_qty - %s) * unit_price WHERE sku_no = %s AND is_deleted = 0", (req_qty, req_qty, req_qty, sku_no))
            cursor.execute("UPDATE purchase_orders SET stage = 'Quality & Packing' WHERE po_number = %s", (po_number,))
            if garment and garment.get('garment_id'):
                cursor.execute("INSERT INTO store_transactions (item_type, item_id, transaction_type, quantity, remarks) VALUES ('Garment', %s, 'OUT', %s, %s)", (garment['garment_id'], int(req_qty), f"Allocated fully for PO {po_number}"))
            conn.commit()
            
            return jsonify({
                "success": True,
                "scenario": "A",
                "message": "Full match available. Order routed to Quality Control.",
                "stage": "Quality & Packing",
                "shortage": 0
            }), 200
            
        else:
            # SCENARIO B: Partial Match / Total Shortage
            # Allocate available stock (which drops it to 0 or keeps it 0)
            if available_qty > 0:
                cursor.execute("UPDATE store_garments SET available_qty = 0, blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = 0 WHERE sku_no = %s AND is_deleted = 0", (available_qty, sku_no))
                if garment and garment.get('garment_id'):
                    cursor.execute("INSERT INTO store_transactions (item_type, item_id, transaction_type, quantity, remarks) VALUES ('Garment', %s, 'OUT', %s, %s)", (garment['garment_id'], int(available_qty), f"Allocated partially for PO {po_number}"))
                
            shortage = req_qty - available_qty
            
            # Route to BOM Calculation Engine
            cursor.execute("UPDATE purchase_orders SET stage = 'BOM Calculation Engine' WHERE po_number = %s", (po_number,))
            
            # BOM Integration: Cross check raw materials (store_materials) for the shortage
            cursor.execute("""
                SELECT bom.material_id, bom.per_piece_qty, mat.material_name, mat.available_qty
                FROM bill_of_materials bom
                LEFT JOIN store_materials mat ON bom.material_id = mat.material_id
                WHERE bom.po_number = %s
            """, (po_number,))
            
            raw_materials = cursor.fetchall()
            bom_deficits = []
            
            for rm in raw_materials:
                base_rm_qty = float(rm['per_piece_qty'] or 0)
                needed_raw_qty = shortage * base_rm_qty
                avail_raw = float(rm['available_qty'] or 0)
                
                rm_shortage = max(0.0, needed_raw_qty - avail_raw)
                
                bom_deficits.append({
                    "material_name": rm['material_name'] or rm['material_id'],
                    "needed": needed_raw_qty,
                    "available": avail_raw,
                    "shortage": rm_shortage
                })
                
            conn.commit()
            return jsonify({
                "success": True,
                "scenario": "B",
                "message": "Partial/Total shortage. Order routed to BOM Calculation Engine.",
                "stage": "BOM Calculation Engine",
                "shortage": shortage,
                "bom_deficits": bom_deficits
            }), 200
            
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: SPECIFICATION SUBMISSION TO STOCK CHECK
# =====================================================================

@app.route('/api/specifications/submit', methods=['POST'])
def submit_specifications():
    data = request.json
    if not data or not data.get('po_number'):
        return jsonify({"success": False, "error": "po_number is required"}), 400
        
    po_number = data['po_number']
    sku_no = data.get('sku_no', '')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Save specification to DB (e.g. if sku_no is provided)
        if sku_no:
            # We check if a specification already exists, otherwise insert
            cursor.execute("SELECT spec_id FROM specifications WHERE po_number = %s", (po_number,))
            if cursor.fetchone():
                cursor.execute("UPDATE specifications SET item_description = %s WHERE po_number = %s", (sku_no, po_number))
            else:
                cursor.execute("INSERT INTO specifications (po_number, item_description) VALUES (%s, %s)", (po_number, sku_no))
                
        # Transition the PO workflow flag state to "Stock Check"
        cursor.execute("UPDATE purchase_orders SET stage = 'Stock Check' WHERE po_number = %s", (po_number,))
        
        conn.commit()
        return jsonify({"success": True, "message": "Specifications saved, moved to Stock Check stage."}), 200
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: PRE-STITCHED STOCK VERIFICATION LOGIC (GET METHOD)
# =====================================================================

@app.route('/api/orders/check-stock', methods=['GET'])
def get_check_stock():
    po_number = request.args.get('poNumber') or request.args.get('po_number')
    if not po_number:
        return jsonify({"success": False, "error": "poNumber is required"}), 400
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch PO to get the required_qty
        cursor.execute("SELECT total_pieces, quantity, total_value FROM purchase_orders WHERE po_number = %s", (po_number,))
        po = cursor.fetchone()
        
        if not po:
            return jsonify({"success": False, "error": "Purchase order not found"}), 404
            
        required_qty = float(po.get('total_pieces') or po.get('quantity') or po.get('total_value') or 0)
        
        # 2. Get sku_no (using specifications table or assume standard matching)
        cursor.execute("SELECT item_description FROM specifications WHERE po_number = %s LIMIT 1", (po_number,))
        spec = cursor.fetchone()
        sku_no = spec['item_description'] if spec and spec.get('item_description') else "UNKNOWN_SKU"
        
        # 3. Match against pre_stitched_inventory (mapped to store_garments)
        cursor.execute("SELECT garment_id, available_qty, category FROM store_garments WHERE sku_no = %s AND is_deleted = 0", (sku_no,))
        garment = cursor.fetchone()
        
        available_qty = float(garment['available_qty']) if garment and garment.get('available_qty') else 0.0
        
        # --- DYNAMIC WORKFLOW BUTTON LOGIC ---
        routing_action = "PURCHASE_REQUEST"
        payload_available_qty = 0
        payload_purchase_qty = 0
        
        is_shirt_or_pant = False
        if 'shirt' in sku_no.lower() or 'pant' in sku_no.lower():
            is_shirt_or_pant = True
        if garment and garment.get('category') and ('shirt' in garment['category'].lower() or 'pant' in garment['category'].lower()):
            is_shirt_or_pant = True
            
        is_uniform = 'uniform' in sku_no.lower()

        if is_shirt_or_pant and is_uniform:
            # Permanent bypass: directly target manufacturing breakdown
            cursor.execute("UPDATE purchase_orders SET stage = 'BOM Calculation' WHERE po_number = %s", (po_number,))
            conn.commit()
            
            return jsonify({
                "success": True,
                "has_shortage": True,
                "shortage_qty": required_qty,
                "next_step": "bom_calculation",
                "message": "Uniform detected. Routed directly to BOM Calculation.",
                "routingAction": "BOM_CALCULATION",
                "status": "Out of Stock",
                "isUniform": True,
                "availableQty": 0,
                "purchaseRequestQty": 0
            }), 200

        if available_qty >= required_qty:
            routing_action = "QUALITY_PACKING"
        elif available_qty > 0 and available_qty < required_qty:
            routing_action = "PARTIAL_SPLIT"
            payload_available_qty = available_qty
            payload_purchase_qty = required_qty - available_qty
        elif available_qty == 0:
            routing_action = "PURCHASE_REQUEST"
        # -------------------------------------
        
        # 4. CONDITIONAL WORKFLOW ROUTING ENGINE
        if available_qty >= required_qty:
            # Scenario A: Sufficient Pre-Stitched Garments Available
            cursor.execute("UPDATE store_garments SET available_qty = GREATEST(0, available_qty - %s), blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = GREATEST(0, available_qty - %s) * unit_price WHERE sku_no = %s AND is_deleted = 0", (required_qty, required_qty, required_qty, sku_no))
            cursor.execute("UPDATE purchase_orders SET stage = 'Quality & Packing' WHERE po_number = %s", (po_number,))
            if garment and garment.get('garment_id'):
                cursor.execute("INSERT INTO store_transactions (item_type, item_id, transaction_type, quantity, remarks) VALUES ('Garment', %s, 'OUT', %s, %s)", (garment['garment_id'], int(required_qty), f"Allocated fully for PO {po_number}"))
            conn.commit()
            
            return jsonify({
                "success": True,
                "has_shortage": False,
                "next_step": "quality_packing",
                "message": "100% fulfillment capability. Routed to Quality & Packing.",
                "routingAction": routing_action,
                "isUniform": is_uniform
            }), 200
            
        else:
            # Scenario B: Insufficient / Missing Pre-Stitched Garments (Shortage)
            if available_qty > 0:
                # Allocate available to sub-batch (deduct pool to 0)
                cursor.execute("UPDATE store_garments SET available_qty = 0, blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = 0 WHERE sku_no = %s AND is_deleted = 0", (available_qty, sku_no))
                if garment and garment.get('garment_id'):
                    cursor.execute("INSERT INTO store_transactions (item_type, item_id, transaction_type, quantity, remarks) VALUES ('Garment', %s, 'OUT', %s, %s)", (garment['garment_id'], int(available_qty), f"Allocated partially for PO {po_number}"))
                
            shortage_qty = required_qty - available_qty
            
            # Update PO workflow flag
            cursor.execute("UPDATE purchase_orders SET stage = 'BOM Calculation' WHERE po_number = %s", (po_number,))
            conn.commit()
            
            return jsonify({
                "success": True,
                "has_shortage": True,
                "shortage_qty": shortage_qty,
                "next_step": "bom_calculation",
                "message": f"Shortage detected ({shortage_qty} units). Routed to BOM Calculation.",
                "routingAction": routing_action,
                "availableQty": payload_available_qty,
                "purchaseRequestQty": payload_purchase_qty,
                "isUniform": is_uniform
            }), 200
            
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# =====================================================================
# API: WORKFLOW STATE TRANSITION (BYPASS TO PACKING)
# =====================================================================

@app.route('/purchase_orders/bypass_to_packing', methods=['POST'])
def bypass_to_packing():
    data = request.get_json()
    if not data or not data.get('poNumber'):
        return jsonify({"success": False, "items": [], "message": "poNumber is required"}), 200
        
    po_number = data['poNumber']
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Update the master workflow tracking status record
        cursor.execute("UPDATE purchase_orders SET stage = 'Quality & Packing' WHERE po_number = %s", (po_number,))
        
        # 2. Log transaction audit entries and adjust stock logs
        # Attempt to deduct from stock safely
        cursor.execute("SELECT item_description, quantity FROM specifications WHERE po_number = %s LIMIT 1", (po_number,))
        spec = cursor.fetchone()
        
        if spec and spec.get('item_description'):
            sku_no = spec['item_description']
            try:
                requested_qty = float(spec.get('quantity') or 0)
            except (ValueError, TypeError):
                requested_qty = 0.0
            
            if requested_qty > 0:
                cursor.execute("SELECT garment_id FROM store_garments WHERE sku_no = %s AND is_deleted = 0", (sku_no,))
                garment = cursor.fetchone()
                if garment:
                    cursor.execute("UPDATE store_garments SET available_qty = GREATEST(0, available_qty - %s), blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = GREATEST(0, available_qty - %s) * unit_price WHERE sku_no = %s AND is_deleted = 0", (requested_qty, requested_qty, requested_qty, sku_no))
                    cursor.execute("INSERT INTO store_transactions (item_type, item_id, transaction_type, quantity, remarks) VALUES ('Garment', %s, 'OUT', %s, %s)", (garment['garment_id'], int(requested_qty), f"Allocated fully for PO {po_number} (Bypass to Packing)"))
                
        conn.commit()
        return jsonify({"success": True, "message": "State transitioned seamlessly"})
        
    except Exception as e:
        print(f"Error in bypass_to_packing: {str(e)}")
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# =====================================================================
# API: PROCESS STOCK ALLOCATION (SINGLE PO WORKFLOW)
# =====================================================================

# =====================================================================
# API: PROCESS STOCK ALLOCATION (DUAL BUTTON SPLIT WORKFLOW)
# =====================================================================

@app.route('/api/orders/split', methods=['POST'])
def split_purchase_order():
    data = request.get_json()
    if not data or not data.get('poNumber'):
        return jsonify({"success": False, "items": [], "message": "poNumber is required"}), 200
        
    po_number = data.get('poNumber')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch main PO details
        cursor.execute("SELECT * FROM purchase_orders WHERE po_number = %s", (po_number,))
        po_data = cursor.fetchone()
        
        if not po_data:
            return jsonify({"success": False, "items": [], "message": "Purchase order not found"}), 200
            
        # 2. Fetch specifications with live stock check
        cursor.execute("""
            SELECT s.*, 
                   COALESCE((SELECT available_qty FROM store_garments sg WHERE sg.sku_no = s.item_description OR sg.description = s.item_description LIMIT 1), 0) AS live_stock_available 
            FROM specifications s 
            WHERE s.po_number = %s
        """, (po_number,))
        specs = cursor.fetchall()
        
        if not specs:
            specs = []
            
        try:
            fallback_qty = float(po_data.get('total_pieces') or po_data.get('quantity') or 100)
        except (ValueError, TypeError):
            fallback_qty = 100.0
        
        stk_po_number = f"{po_number}-STK"
        prd_po_number = f"{po_number}-PRD"
        
        # Create STK Order (Quality & Packing)
        cursor.execute(
            """
            INSERT INTO purchase_orders (po_number, customer_id, status, total_value, order_date, delivery_date, contact_person, contact_phone, contact_email, delivery_type, delivery_address, delivery_pin, billing_company, billing_address, billing_pin, gst_number, cin_number, test_certificate, transport_cost, advance_amount, payment_term, stage) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (stk_po_number, po_data.get('customer_id'), po_data.get('status'), po_data.get('total_value'), po_data.get('order_date'), po_data.get('delivery_date'), po_data.get('contact_person'), po_data.get('contact_phone'), po_data.get('contact_email'), po_data.get('delivery_type'), po_data.get('delivery_address'), po_data.get('delivery_pin'), po_data.get('billing_company'), po_data.get('billing_address'), po_data.get('billing_pin'), po_data.get('gst_number'), po_data.get('cin_number'), po_data.get('test_certificate'), po_data.get('transport_cost'), po_data.get('advance_amount'), po_data.get('payment_term'), 'Quality & Packing')
        )
        
        # Create PRD Order (BOM Calculation)
        cursor.execute(
            """
            INSERT INTO purchase_orders (po_number, customer_id, status, total_value, order_date, delivery_date, contact_person, contact_phone, contact_email, delivery_type, delivery_address, delivery_pin, billing_company, billing_address, billing_pin, gst_number, cin_number, test_certificate, transport_cost, advance_amount, payment_term, stage) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (prd_po_number, po_data.get('customer_id'), po_data.get('status'), po_data.get('total_value'), po_data.get('order_date'), po_data.get('delivery_date'), po_data.get('contact_person'), po_data.get('contact_phone'), po_data.get('contact_email'), po_data.get('delivery_type'), po_data.get('delivery_address'), po_data.get('delivery_pin'), po_data.get('billing_company'), po_data.get('billing_address'), po_data.get('billing_pin'), po_data.get('gst_number'), po_data.get('cin_number'), po_data.get('test_certificate'), po_data.get('transport_cost'), po_data.get('advance_amount'), po_data.get('payment_term'), 'BOM Calculation')
        )
        
        has_stk = False
        has_prd = False
        
        for spec in specs:
            try:
                req_qty = float(spec.get('quantity') or fallback_qty)
            except (ValueError, TypeError):
                req_qty = fallback_qty
                
            try:
                avail = float(spec.get('live_stock_available') or 0)
            except (ValueError, TypeError):
                avail = 0.0
            
            stk_qty = min(avail, req_qty)
            prd_qty = req_qty - stk_qty
            
            if stk_qty > 0:
                has_stk = True
                cursor.execute(
                    "INSERT INTO specifications (po_number, fabric_type, size, color, style, remarks, item_description, pattern, stock_available, unit_price, photo_name, use_existing_stock, quantity, delivery_address, delivery_pin) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (stk_po_number, spec.get('fabric_type'), spec.get('size'), spec.get('color'), spec.get('style'), spec.get('remarks'), spec.get('item_description'), spec.get('pattern'), spec.get('stock_available'), spec.get('unit_price'), spec.get('photo_name'), stk_qty, stk_qty, spec.get('delivery_address'), spec.get('delivery_pin'))
                )
                # Deduct from store_garments
                cursor.execute("UPDATE store_garments SET available_qty = GREATEST(0, available_qty - %s), blocked_qty = COALESCE(blocked_qty, 0) + %s, total_price = GREATEST(0, available_qty - %s) * unit_price WHERE (sku_no = %s OR description = %s) AND is_deleted = 0", (stk_qty, stk_qty, stk_qty, spec.get('item_description'), spec.get('item_description')))
                
            if prd_qty > 0:
                has_prd = True
                cursor.execute(
                    "INSERT INTO specifications (po_number, fabric_type, size, color, style, remarks, item_description, pattern, stock_available, unit_price, photo_name, use_existing_stock, quantity, delivery_address, delivery_pin) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (prd_po_number, spec.get('fabric_type'), spec.get('size'), spec.get('color'), spec.get('style'), spec.get('remarks'), spec.get('item_description'), spec.get('pattern'), spec.get('stock_available'), spec.get('unit_price'), spec.get('photo_name'), 0, prd_qty, spec.get('delivery_address'), spec.get('delivery_pin'))
                )
                
        # Mark original PO as Split
        cursor.execute("UPDATE purchase_orders SET stage = 'Split' WHERE po_number = %s", (po_number,))
        
        if not has_stk:
            cursor.execute("DELETE FROM purchase_orders WHERE po_number = %s", (stk_po_number,))
        if not has_prd:
            cursor.execute("DELETE FROM purchase_orders WHERE po_number = %s", (prd_po_number,))
            
        conn.commit()
        return jsonify({"success": True, "message": "Order split successfully", "has_stk": has_stk, "has_prd": has_prd, "stk_po": stk_po_number, "prd_po": prd_po_number})
        
    except Exception as e:
        print(f"Error in split_purchase_order: {str(e)}")
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
        
# =====================================================================

# API: GENERIC WORKFLOW STAGE UPDATE
# =====================================================================

@app.route('/purchase_orders/update_stage', methods=['POST'])
def update_po_stage():
    data = request.get_json()
    if not data or not data.get('poNumber') or not data.get('stage'):
        return jsonify({"success": False, "error": "poNumber and stage are required"}), 400
        
    po_number = data['poNumber']
    # Enforce stage normalization
    stage = normalize_stage(data['stage'])
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("UPDATE purchase_orders SET stage = %s WHERE po_number = %s", (stage, po_number))
        conn.commit()
        
        return jsonify({"success": True, "message": f"Order stage successfully updated to {stage}"})
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/purchase_orders/update_status', methods=['POST'])
def update_po_status():
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}
        po_number = data.get('poNumber')
        new_status = data.get('status', 'In Progress')
        quality_stages = data.get('qualityStages')
        
        if not po_number:
            return jsonify({"success": False, "message": "Missing PO Number"}), 400

        import json
        quality_stages_json = json.dumps(quality_stages) if quality_stages else '[]'

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "UPDATE purchase_orders SET status = %s, quality_stages = %s WHERE po_number = %s", 
            (new_status, quality_stages_json, po_number)
        )
        conn.commit()

        cursor.execute("SELECT * FROM purchase_orders WHERE po_number = %s", (po_number,))
        order = cursor.fetchone()

        return jsonify({
            "success": True, 
            "message": "Order status updated successfully",
            "poNumber": po_number,
            "status": new_status,
            "order": order
        }), 200

    except Exception as e:
        print(f"Defensive Override - Caught BOM/Status Exception: {e}")
        if conn: conn.rollback()
        # Secure Fallback: Returns a valid response payload instead of dropping into a 500 crash
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: DYNAMIC BOM CALCULATION
# Calculates BOM dynamically based on consumption_formulas and specs
# =====================================================================
@app.route('/api/bom/calculate/<po_number>', methods=['GET'])
def calculate_bom(po_number):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch PO for fallback quantity
        cursor.execute("SELECT * FROM purchase_orders WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))", (po_number,))
        po_data = cursor.fetchone()
        if not po_data:
            # Fallback for custom tracking layout identifiers: check if it's stored in a different format
            cursor.execute("SELECT * FROM purchase_orders WHERE LOWER(TRIM(po_number)) LIKE LOWER(TRIM(%s)) OR id = %s", (f"%{po_number}%", po_number if po_number.isdigit() else 0))
            po_data = cursor.fetchone()
            if not po_data:
                # Return 200 OK with empty items instead of 404 to prevent unhandled frontend exceptions
                return jsonify({"success": True, "items": [], "message": "Order uses custom tracking layout or not found, no direct BOM available."}), 200
            
        fallback_qty = float(po_data.get('total_pieces') or po_data.get('quantity') or 100)
        
        # 2. Fetch specifications with their category from store_garments
        cursor.execute("""
            SELECT s.*, sg.category as garment_category
            FROM specifications s
            LEFT JOIN store_garments sg ON s.item_description = sg.sku_no
            WHERE LOWER(TRIM(s.po_number)) = LOWER(TRIM(%s))
        """, (po_number,))
        specs = cursor.fetchall()
        
        if not specs:
            specs = []
            
        # 3. Fetch all active store materials
        cursor.execute("SELECT * FROM store_materials WHERE is_deleted = 0")
        store_materials = cursor.fetchall()
        if not store_materials:
            store_materials = []
            
        mat_groups = {}
        
        # 4. Aggregate required materials across all specs
        for spec in specs:
            req_qty = float(spec.get('quantity') or 0)
            if req_qty == 0:
                req_qty = fallback_qty
            use_existing = float(spec.get('use_existing_stock') or 0)
            prod_qty = max(0, req_qty - use_existing)
            
            if prod_qty <= 0:
                continue
                
            g_cat = str(spec.get('garment_category') or 'default').lower()
            
            cursor.execute("SELECT * FROM consumption_formulas WHERE garment_category = %s", (g_cat,))
            formulas = cursor.fetchall()
            
            if not formulas:
                cursor.execute("SELECT * FROM consumption_formulas WHERE garment_category = 'default'")
                formulas = cursor.fetchall()
                
            if not formulas:
                formulas = []
                
            for formula in formulas:
                try:
                    per_piece = float(formula.get('per_piece_qty', 0))
                except (ValueError, TypeError):
                    per_piece = 0.0
                    
                if per_piece <= 0:
                    continue
                    
                mat_id = formula.get('material_id')
                if not mat_id:
                    continue
                
                matched_mat = next((m for m in store_materials if m.get('material_id') == mat_id), None)
                if not matched_mat:
                    continue
                    
                if mat_id not in mat_groups:
                    mat_groups[mat_id] = {
                        "groupKey": matched_mat.get('category', 'Material'),
                        "material_id": mat_id,
                        "name": matched_mat.get('material_name', 'Unknown'),
                        "unit": matched_mat.get('unit', 'units'),
                        "unitPrice": float(matched_mat.get('unit_price') or 0),
                        "perPiece": 0,
                        "totalBase": 0
                    }
                mat_groups[mat_id]['totalBase'] += per_piece * prod_qty
                mat_groups[mat_id]['perPiece'] = per_piece
                
        # 5. Format output
        calculated_materials = []
        raw_wastage = request.args.get('wastage', '5')
        try:
            wastage_pct = float(raw_wastage)
        except (ValueError, TypeError):
            wastage_pct = 5.0
            
        for mat_id, data in mat_groups.items():
            total_base = data['totalBase']
            wastage_amt = total_base * (wastage_pct / 100)
            final_qty = int(total_base + wastage_amt) + (1 if (total_base + wastage_amt) % 1 > 0 else 0)
            
            calculated_materials.append({
                "groupKey": data['groupKey'],
                "material_id": data['material_id'],
                "name": data['name'],
                "unit": data['unit'],
                "perPiece": data['perPiece'],
                "baseRequired": round(total_base, 2),
                "wastageAmt": round(wastage_amt, 2),
                "finalQty": final_qty,
                "unitPrice": data['unitPrice']
            })
            
        return jsonify({"success": True, "data": calculated_materials}), 200
        
    except Exception as e:
        print(f"Error in BOM Calculation: {str(e)}")
        if conn: conn.rollback()
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# MODULE: BOM SAVE
# Saves BOM calculation lines to the bill_of_materials table and
# advances the PO stage to 'Material Allocation'.
# =====================================================================
@app.route('/api/bom/save', methods=['POST', 'OPTIONS'])
def save_bom():
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_write_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400

    po_number = data.get('poNumber')
    bom_lines = data.get('bomLines', [])   # [{material_id, per_piece_qty, final_qty, amount}]
    wastage_pct = float(data.get('wastagePct', 5))

    if not po_number:
        return jsonify({"success": False, "error": "poNumber is required"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        import re, urllib.parse
        clean_po = urllib.parse.unquote(str(po_number)).strip()
        clean_po = re.sub(r'^PO:\s*', '', clean_po, flags=re.IGNORECASE)
        clean_po = clean_po.split('|')[0].strip()
        clean_po = re.sub(r'\s*\(.*?\)', '', clean_po).strip()

        # Delete existing BOM lines for this PO before re-inserting
        cursor.execute("DELETE FROM bill_of_materials WHERE po_number = %s", (clean_po,))
        
        for line in bom_lines:
            material_id = line.get('material_id')
            material_name = line.get('material_name', material_id)
            category = line.get('category', 'Material')
            unit = line.get('unit', 'units')
            per_piece_qty = float(line.get('per_piece_qty', 0))
            final_qty = float(line.get('final_qty', 0))
            amount = float(line.get('amount', 0))
            
            if not material_name or final_qty <= 0:
                continue
                
            cursor.execute("SELECT material_id FROM store_materials WHERE material_id = %s OR material_name = %s LIMIT 1", (material_id, material_name))
            row = cursor.fetchone()
            
            if not row:
                cursor.execute(
                    "INSERT INTO store_materials (material_name, category, unit, available_qty, min_required, unit_price, status, is_deleted) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (material_name, category, unit, 0, 0, 1.0, 'Active', 0)
                )
                actual_mat_id = cursor.lastrowid
            else:
                actual_mat_id = row['material_id'] if isinstance(row, dict) else row[0]
                
            cursor.execute(
                "INSERT INTO bill_of_materials (po_number, material_id, per_piece_qty, final_qty, amount) VALUES (%s, %s, %s, %s, %s)",
                (clean_po, actual_mat_id, per_piece_qty, final_qty, amount)
            )

        # ---------------------------------------------------------------------
        # NEW: Native calculation from master table and insert into bom_done
        # ---------------------------------------------------------------------
        cursor.execute("DELETE FROM bom_done WHERE po_number = %s", (clean_po,))

        cursor.execute("SELECT size, quantity, item_description, customer_name FROM specifications WHERE po_number LIKE %s LIMIT 1", (f"%{clean_po}%",))
        spec = cursor.fetchone()
        
        customer_name = "Unknown"
        garment_cat = 'Shirt'
        sizes_list = ['34', '36', '38', '40']
        order_qty_per_size = 25
        
        if spec:
            garment_cat = spec.get('item_description') or 'Shirt'
            customer_name = spec.get('customer_name') or 'Unknown'
            sizes_str = str(spec.get('size') or '34,36,38,40')
            total_qty = float(spec.get('quantity') or 100)
            sizes_list = [s.strip() for s in sizes_str.split(',') if s.strip()]
            order_qty_per_size = total_qty / len(sizes_list) if len(sizes_list) > 0 else 0
        else:
            cursor.execute("SELECT garment_category, total_pieces, customer_name FROM purchase_orders WHERE po_number LIKE %s LIMIT 1", (f"%{clean_po}%",))
            po_rec = cursor.fetchone()
            if po_rec:
                garment_cat = po_rec.get('garment_category') or 'Shirt'
                total_qty = float(po_rec.get('total_pieces') or 100)
                customer_name = po_rec.get('customer_name') or 'Unknown'
                order_qty_per_size = total_qty / len(sizes_list)

        col_to_name_map = {
            "fabric_full_sleeve": "Fabric",
            "fabric_half_sleeve": "Fabric",
            "cuff": "Cuff",
            "thread": "Thread",
            "collar": "Collar",
            "placket": "Placket",
            "size_label": "Size Label",
            "washcare_label": "Washcare Label",
            "overlock_thread": "Overlock Thread",
            "main_label": "Main Label",
            "brand_label": "Brand Label",
            "polybag": "Polybag",
            "box": "Box",
            "clip": "Clip"
        }
        
        def parse_numeric(val):
            if val is None: return 0.0
            match = re.search(r'[\d\.]+', str(val).strip())
            return float(match.group()) if match else 0.0

        if sizes_list:
            format_strings = ','.join(['%s'] * len(sizes_list))
            query = f"SELECT * FROM garment_bom_calculations WHERE item_name = %s AND size IN ({format_strings})"
            cursor.execute(query, [garment_cat] + sizes_list)
            bom_rows = cursor.fetchall()
            
            insert_bom_done = '''
                INSERT INTO bom_done (
                    po_number, customer_name, wastage_margin, grand_total_amount,
                    material_name, brand, size, per_piece_qty, total_qty, per_unit_price, final_price
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            '''
            
            cursor.execute("SELECT material_name, unit_price FROM store_materials")
            inv_prices = {r['material_name'].lower(): float(r['unit_price'] or 0) for r in cursor.fetchall()}
            
            for row in bom_rows:
                size_val = str(row.get('size'))
                for col, mat_name in col_to_name_map.items():
                    val = row.get(col)
                    if val is not None and str(val).strip() != '':
                        per_piece_qty = parse_numeric(val)
                        if per_piece_qty > 0:
                            total_qty = (per_piece_qty * order_qty_per_size) * (1 + wastage_pct / 100.0)
                            unit_price = inv_prices.get(mat_name.lower(), 0.0)
                            final_price = total_qty * unit_price
                            
                            cursor.execute(insert_bom_done, (
                                clean_po,
                                customer_name,
                                wastage_pct,
                                0, # grand_total_amount placeholder
                                mat_name,
                                'Standard',
                                size_val,
                                round(per_piece_qty, 3),
                                round(total_qty, 3),
                                round(unit_price, 2),
                                round(final_price, 2)
                            ))

        # Advance PO stage to Inventory Check
        cursor.execute(
            "UPDATE purchase_orders SET stage = 'Inventory Check' WHERE po_number = %s",
            (clean_po,)
        )

        conn.commit()
        return jsonify({"success": True, "message": "BOM natively saved and stage advanced"}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# MODULE: BOM MATERIAL ALLOCATION (Hard Reservation Lock)
# Cross-references BOM requirements against store_materials.
# Locks available materials (reduces available_qty, increases blocked_qty).
# Creates procurement rows for shortages.
# Advances PO stage to 'Production' or 'Procurement' depending on result.
# =====================================================================
@app.route('/api/bom/allocate-materials', methods=['POST', 'OPTIONS'])
def allocate_bom_materials():
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_write_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400

    po_number = data.get('poNumber')
    allocations = data.get('allocations', [])
    # allocations: [{material_id, material_name, required_qty, available_qty, allocate_qty, shortage_qty}]

    if not po_number:
        return jsonify({"success": False, "error": "poNumber is required"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        has_shortage = False
        allocation_results = []

        for alloc in allocations:
            material_id = alloc.get('material_id')
            allocate_qty = float(alloc.get('allocate_qty', 0))
            shortage_qty = float(alloc.get('shortage_qty', 0))
            material_name = alloc.get('material_name', '')
            required_qty = float(alloc.get('required_qty', 0))

            if not material_id:
                continue

            # Hard lock: Deduct allocated quantity from store
            if allocate_qty > 0:
                cursor.execute("""
                    UPDATE store_materials
                    SET available_qty = GREATEST(0, available_qty - %s),
                        blocked_qty = COALESCE(blocked_qty, 0) + %s,
                        total_price = GREATEST(0, available_qty - %s) * unit_price
                    WHERE material_id = %s
                """, (allocate_qty, allocate_qty, allocate_qty, material_id))

            # Handle shortage: push to procurement queue
            if shortage_qty > 0:
                has_shortage = True
                # Check if procurement entry already exists for this PO+material
                cursor.execute("""
                    SELECT procurement_id FROM procurement
                    WHERE po_number = %s AND material_id = %s
                """, (po_number, material_id))
                existing_proc = cursor.fetchone()

                if existing_proc:
                    cursor.execute("""
                        UPDATE procurement
                        SET required_qty = %s, status = 'Pending Procurement'
                        WHERE po_number = %s AND material_id = %s
                    """, (shortage_qty, po_number, material_id))
                else:
                    cursor.execute("""
                        INSERT INTO procurement
                        (po_number, material_id, required_qty, supplier_name, status, supplier_contact, expected_delivery_date, invoice_number)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (po_number, material_id, shortage_qty, 'Auto Assigned (Shortage)', 'Pending Procurement', '', None, ''))

            allocation_results.append({
                "material_id": material_id,
                "allocate_qty": allocate_qty,
                "shortage_qty": shortage_qty,
                "status": "Shortage" if shortage_qty > 0 else "Allocated"
            })

        # Advance PO stage
        next_stage = 'Procurement' if has_shortage else 'Production'
        cursor.execute(
            "UPDATE purchase_orders SET stage = %s WHERE po_number = %s",
            (next_stage, po_number)
        )

        conn.commit()
        return jsonify({
            "success": True,
            "next_stage": next_stage,
            "has_shortage": has_shortage,
            "allocations": allocation_results,
            "message": f"Materials allocated. PO advanced to {next_stage}."
        }), 200

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# MODULE: DASHBOARD SUMMARY
# =====================================================================

@app.route('/api/dashboard/summary', methods=['GET'])
def get_dashboard_summary():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Total Orders
        cursor.execute("SELECT COUNT(*) as count FROM purchase_orders")
        total_orders = cursor.fetchone().get('count', 0)
        
        # 2. Active Production (Sum quantity where In Progress or active stage)
        try:
            cursor.execute("""
                SELECT COALESCE(SUM(s.quantity), 0) as active_count
                FROM purchase_orders p
                JOIN specifications s ON p.po_number = s.po_number
                WHERE p.status = 'In Progress' 
                   OR p.stage IN ('BOM Calculation', 'Inventory Check', 'Material Allocation', 'Procurement', 'Material Release', 'Production')
            """)
            active_prod_result = cursor.fetchone()
            active_prod = float(active_prod_result.get('active_count', 0) or 0)
        except Exception:
            # Fallback if specification join fails
            cursor.execute("""
                SELECT COUNT(*) as active_count
                FROM purchase_orders 
                WHERE status = 'In Progress' 
                   OR stage IN ('BOM Calculation', 'Inventory Check', 'Material Allocation', 'Procurement', 'Material Release', 'Production')
            """)
            active_prod_result = cursor.fetchone()
            active_prod = float(active_prod_result.get('active_count', 0) or 0)

        # 3. Pending Procurement
        cursor.execute("SELECT COUNT(*) as count FROM purchase_orders WHERE stage = 'Procurement'")
        pending_procurement = cursor.fetchone().get('count', 0)
        
        # 4. Inventory Alerts
        mat_alerts = 0
        gar_alerts = 0
        try:
            cursor.execute("SELECT COUNT(*) as count FROM store_materials WHERE available_qty < min_required AND is_deleted = 0")
            mat_alerts = cursor.fetchone().get('count', 0)
        except Exception:
            pass
        try:
            cursor.execute("SELECT COUNT(*) as count FROM store_garments WHERE available_qty < min_required AND is_deleted = 0")
            gar_alerts = cursor.fetchone().get('count', 0)
        except Exception:
            pass
        inventory_alerts = mat_alerts + gar_alerts
        
        # 5. Recent Orders (limit 5)
        try:
            cursor.execute("""
                SELECT po.*, c.customer_name as c_name
                FROM purchase_orders po
                LEFT JOIN customers c ON po.customer_id = c.customer_id
                ORDER BY po.created_at DESC
                LIMIT 5
            """)
        except Exception:
            # Fallback if created_at doesn't exist
            cursor.execute("""
                SELECT po.*, c.customer_name as c_name
                FROM purchase_orders po
                LEFT JOIN customers c ON po.customer_id = c.customer_id
                ORDER BY po.po_number DESC
                LIMIT 5
            """)
            
        recent_orders_raw = cursor.fetchall()
        recent_orders = []
        from datetime import datetime
        now = datetime.now()
        
        for po in recent_orders_raw:
            del_days = 0
            if po.get('status') not in ['Completed', 'Delivered'] and po.get('delivery_date'):
                try:
                    ddate = po['delivery_date']
                    if isinstance(ddate, str):
                        # Some formats might be YYYY-MM-DD
                        ddate = datetime.strptime(ddate.split(' ')[0].split('T')[0], "%Y-%m-%d")
                    diff = (now.date() - ddate.date()).days if hasattr(ddate, 'date') else (now - ddate).days
                    if diff > 0:
                        del_days = diff
                except Exception:
                    pass
                    
            recent_orders.append({
                "id": po.get('po_number'),
                "poNumber": po.get('po_number'),
                "customerName": po.get('customer_name') or po.get('c_name') or 'Unknown',
                "currentStage": po.get('stage') or po.get('status') or 'Order Initiation',
                "poDate": str(po.get('order_date')) if po.get('order_date') else '',
                "deliveryDate": str(po.get('delivery_date')) if po.get('delivery_date') else '',
                "delayDays": del_days,
                "delayReason": po.get('delay_reason') or '',
                "amount": float(po.get('total_value') or po.get('total_amount') or po.get('advance_amount') or 0)
            })

        return jsonify({
            "success": True,
            "statsData": {
                "totalOrders": total_orders,
                "activeProduction": active_prod,
                "pendingProcurement": pending_procurement,
                "inventoryAlerts": inventory_alerts
            },
            "recentOrders": recent_orders
        }), 200

    except Exception as e:
        print(f"Error in Dashboard Summary: {e}")
        if conn: conn.rollback()
        return jsonify({
            "success": False,
            "statsData": {
                "totalOrders": 0,
                "activeProduction": 0,
                "pendingProcurement": 0,
                "inventoryAlerts": 0
            },
            "recentOrders": []
        }), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# =====================================================================
# UNIFIED REPORTS API (Dashboard Sub-Pages)
# =====================================================================

@app.route('/api/reports/orders', methods=['GET'])
def report_orders():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT po_number, customer_name, order_date, delivery_date, stage, total_value, total_pieces, status 
            FROM purchase_orders 
            
        ''')
        orders = cursor.fetchall()
        
        results = []
        for o in orders:
            raw_stage = o.get('stage') or o.get('status') or 'Pending'
            raw_stage = raw_stage.lower()
            
            mapped_status = 'Pending'
            if 'progress' in raw_stage or 'production' in raw_stage:
                mapped_status = 'In Production'
            elif 'cut' in raw_stage:
                mapped_status = 'Cutting'
            elif 'deliver' in raw_stage or 'complete' in raw_stage:
                mapped_status = 'Delivered'
            elif 'pend' in raw_stage or 'initiation' in raw_stage or 'draft' in raw_stage:
                mapped_status = 'Pending'
            else:
                mapped_status = 'Pending'
                
            results.append({
                'id': o.get('po_number'),
                'customer': o.get('customer_name') or 'Unknown',
                'items': o.get('total_pieces') or 0,
                'poDate': format_db_date(str(o.get('order_date'))) if o.get('order_date') else '',
                'deliveryDate': format_db_date(str(o.get('delivery_date'))) if o.get('delivery_date') else '',
                'status': mapped_status,
                'amount': float(o.get('total_value') or 0)
            })
            
        return jsonify(results), 200
    except Exception as e:
        print(f"Error in /api/reports/orders: {e}")
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/reports/active-production', methods=['GET'])
def report_active_production():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT po_number, customer_name, order_date, delivery_date, stage, status, total_pieces, quantity 
            FROM purchase_orders 
            WHERE status = 'In Progress' OR stage LIKE '%Production%' OR stage = 'In Progress'
        ''')
        orders = cursor.fetchall()
        
        results = []
        for o in orders:
            results.append({
                'poNumber': o.get('po_number'),
                'style': o.get('customer_name') or 'Standard Garment',
                'stage': o.get('stage') or 'In Progress',
                'qty': o.get('total_pieces') or o.get('quantity') or 0,
                'startDate': format_db_date(str(o.get('order_date'))) if o.get('order_date') else '',
                'expectedCompletion': format_db_date(str(o.get('delivery_date'))) if o.get('delivery_date') else ''
            })
            
        return jsonify(results), 200
    except Exception as e:
        print(f"Error in /api/reports/active-production: {e}")
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/reports/procurement', methods=['GET'])
def report_procurement():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT p.po_number, m.material_name, p.required_qty, m.unit, 
                   s.supplier_name, p.status, p.order_date
            FROM procurement p
            LEFT JOIN store_materials m ON p.material_id = m.material_id
            LEFT JOIN suppliers s ON p.supplier_id = s.supplier_id
            WHERE p.status IN ('Awaiting Materials', 'Procurement', 'Pending Approval', 'Ordered', 'Delayed', 'In Transit')
        ''')
        proc_data = cursor.fetchall()
        
        results = []
        for p in proc_data:
            results.append({
                'poNumber': p.get('po_number') or 'Unknown',
                'material': p.get('material_name') or 'Unknown Material',
                'requiredQty': p.get('required_qty') or 0,
                'unit': p.get('unit') or 'pcs',
                'supplier': p.get('supplier_name') or 'Unknown Supplier',
                'status': p.get('status') or 'Pending'
            })
            
        return jsonify(results), 200
    except Exception as e:
        print(f"Error in /api/reports/procurement: {e}")
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/reports/inventory-alerts', methods=['GET'])
def report_inventory_alerts():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT material_id, material_name, available_qty, min_required, unit
            FROM store_materials 
            WHERE available_qty < min_required AND is_deleted = 0
        ''')
        inventory = cursor.fetchall()
        
        results = []
        for item in inventory:
            avail = float(item.get('available_qty') or 0)
            min_req = float(item.get('min_required') or 0)
            
            if avail <= 0:
                alert = 'Critical'
            elif avail <= (0.5 * min_req):
                alert = 'High'
            else:
                alert = 'Medium'
                
            results.append({
                'materialId': item.get('material_id'),
                'name': item.get('material_name'),
                'currentStock': avail,
                'unit': item.get('unit') or 'pcs',
                'threshold': min_req,
                'status': alert
            })
            
        return jsonify(results), 200
    except Exception as e:
        print(f"Error in /api/reports/inventory-alerts: {e}")
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# REPORTS: Orders Aggregation
# =====================================================================
@app.route('/api/reports/orders', methods=['GET'])
def get_orders_report():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Query the central 'orders' collection to retrieve all active records.
        cursor.execute("SELECT * FROM orders WHERE status != 'Deleted' AND status != 'Archived'")
        orders_data = cursor.fetchall()
        
        stats = {
            "pending": 0,
            "inProduction": 0,
            "cutting": 0,
            "delivered": 0
        }
        
        formatted_orders = []
        
        for order in orders_data:
            # Determine active stage/status
            stage = order.get('active_stage') or order.get('stage') or ''
            status = order.get('status') or ''
            
            # Compute counts for the 4 report summary metrics
            if stage in ['Initiation', 'Order Initiation', 'Specifications', 'Order Specifications', 'Stock Check', 'BOM Calculation'] or status == 'Pending':
                stats['pending'] += 1
            elif stage in ['Inventory Check', 'Material Allocation', 'Procurement', 'Material Release', 'Production', 'Quality & Packing'] or status == 'In Progress':
                stats['inProduction'] += 1
            elif stage == 'Cutting':
                stats['cutting'] += 1
            elif stage == 'Dispatched' or status == 'Delivered':
                stats['delivered'] += 1
                
            # Shape table row keys
            formatted_orders.append({
                "poNumber": order.get('po_number') or order.get('id') or '',
                "customer": order.get('customer_name') or order.get('customer') or '',
                "itemDescription": order.get('item_description') or order.get('description') or '',
                "poDate": format_db_date(order.get('po_date') or order.get('created_at')),
                "deliveryDate": format_db_date(order.get('delivery_date') or order.get('target_date')),
                "activeWorkflowStep": stage if stage else status,
                "totalValue": float(order.get('total_value') or order.get('amount') or 0)
            })
            
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "stats": stats,
            "orders": formatted_orders
        }), 200

    except Exception as e:
        print(f"Error in /api/reports/orders: {e}")
        return jsonify({"success": False, "orders": [], "message": str(e)}), 200


# =====================================================================
# INVENTORY: Split Allocation Workflows
# =====================================================================

@app.route('/api/purchase_orders/allocate-partial', methods=['POST'])
def allocate_partial_split():
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}
        po_number = data.get('poNumber')
        allocated_qty = int(data.get('allocatedQty', 0))
        
        if not po_number:
            return jsonify({"success": False, "error": "poNumber is required"}), 200
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch current order state
        cursor.execute("SELECT * FROM orders WHERE po_number = %s", (po_number,))
        order = cursor.fetchone()
        
        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 200
            
        # Determine current quantities (safely parsing defaults)
        total_qty = int(order.get('total_order_qty') or order.get('quantity') or order.get('total_qty') or 0)
        current_packing = int(order.get('allocated_to_packing', 0) or 0)
        current_bom = int(order.get('allocated_to_bom', 0) or 0)
        
        new_packing_qty = current_packing + allocated_qty
        
        # 2. Deduct from warehouse inventory immediately
        item_desc = order.get('item_description') or order.get('description') or ''
        cursor.execute("""
            UPDATE inventory 
            SET available_quantity = available_quantity - %s 
            WHERE item_name = %s AND available_quantity >= %s
        """, (allocated_qty, item_desc, allocated_qty))
        
        # 3. Final Core Stage Status Transition Verification
        if (new_packing_qty + current_bom) >= total_qty and total_qty > 0:
            # Execute final database save query updating the order status
            new_stage = 'Material Allocation'
            cursor.execute("""
                UPDATE orders 
                SET allocated_to_packing = %s, stage = %s, active_stage = %s 
                WHERE po_number = %s
            """, (new_packing_qty, new_stage, new_stage, po_number))
        else:
            # Keep the core order status at 'Stock Check'
            cursor.execute("""
                UPDATE orders 
                SET allocated_to_packing = %s 
                WHERE po_number = %s
            """, (new_packing_qty, po_number))
            
        conn.commit()
        return jsonify({"success": True, "message": "Partial allocation processed successfully."}), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        if conn: conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/purchase_orders/calculate-bom-shortage', methods=['POST'])
def calculate_bom_shortage():
    conn = None
    cursor = None
    try:
        data = request.json
        po_number = data.get('poNumber')
        shortage_qty = int(data.get('shortageQty', 0))
        
        if not po_number:
            return jsonify({"success": False, "error": "poNumber is required"}), 200
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch current order state
        cursor.execute("SELECT * FROM orders WHERE po_number = %s", (po_number,))
        order = cursor.fetchone()
        
        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 200
            
        # Determine current quantities
        total_qty = int(order.get('total_order_qty') or order.get('quantity') or order.get('total_qty') or 0)
        current_packing = int(order.get('allocated_to_packing', 0) or 0)
        current_bom = int(order.get('allocated_to_bom', 0) or 0)
        
        new_bom_qty = current_bom + shortage_qty
        
        # 2. Save tracking records into production scheduler tables
        item_desc = order.get('item_description') or order.get('description') or ''
        cursor.execute("""
            INSERT INTO production_scheduler (po_number, item_name, required_quantity, status)
            VALUES (%s, %s, %s, 'Pending BOM')
        """, (po_number, item_desc, shortage_qty))
        
        # 3. Final Core Stage Status Transition Verification
        if (current_packing + new_bom_qty) >= total_qty and total_qty > 0:
            # Move to next stage completely
            new_stage = 'BOM Calculation'
            cursor.execute("""
                UPDATE orders 
                SET allocated_to_bom = %s, stage = %s, active_stage = %s 
                WHERE po_number = %s
            """, (new_bom_qty, new_stage, new_stage, po_number))
        else:
            # Keep in current wizard step
            cursor.execute("""
                UPDATE orders 
                SET allocated_to_bom = %s 
                WHERE po_number = %s
            """, (new_bom_qty, po_number))
            
        conn.commit()
        return jsonify({"success": True, "message": "BOM shortage calculated successfully."}), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        if conn: conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# =====================================================================
# STORE MATERIALS API
# =====================================================================
@app.route('/api/store-articles/shortages', methods=['GET'])
def fetch_api_store_articles_shortages():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Fetch active articles and finished goods, calculating deficit for the frontend
        query = """
            SELECT 
                material_id as article_id, 
                'Material' as type,
                hsn_code, 
                TRIM(material_name) AS article_name, 
                category, 
                unit, 
                status,
                COALESCE(available_qty, 0) AS available_qty, 
                COALESCE(blocked_qty, 0) AS blocked_qty, 
                COALESCE(min_required, 0) AS min_required_qty,
                GREATEST(0, COALESCE(min_required, 0) - COALESCE(available_qty, 0)) AS deficit
            FROM store_articles 
            WHERE is_deleted = 0
            
            UNION ALL
            
            SELECT 
                garment_id as article_id, 
                'Garment' as type,
                hsn_code, 
                CONCAT(TRIM(category), ' ', TRIM(pattern), ' - ', TRIM(color), ' (', TRIM(size), ')') AS article_name, 
                category, 
                'units' as unit, 
                status,
                COALESCE(available_qty, 0) AS available_qty, 
                COALESCE(blocked_qty, 0) AS blocked_qty, 
                COALESCE(min_required, 0) AS min_required_qty,
                GREATEST(0, COALESCE(min_required, 0) - COALESCE(available_qty, 0)) AS deficit
            FROM store_garments
            WHERE is_deleted = 0
        """
        cursor.execute(query)
        articles = cursor.fetchall()

        # Extra Python-side sanitization to guarantee clean strings
        for a in articles:
            if a.get('article_name'):
                a['article_name'] = a['article_name'].strip()
            
        return jsonify({"success": True, "data": articles}), 200

    except Exception as e:
        print(f"[API Error] /api/store-articles/shortages - {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/store-materials/clear-test-data', methods=['DELETE'])
def clear_store_materials_test_data():
    """
    Clears all dummy/test data and validates auto_increment reset.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Standard delete
        cursor.execute("DELETE FROM store_materials")
        
        # Reset the sequencer to 1 (Validation requested by requirement)
        cursor.execute("ALTER TABLE store_materials AUTO_INCREMENT = 1")
        
        conn.commit()
        return jsonify({"success": True, "message": "Test data cleared and sequencer reset to 1"}), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        if conn: conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/garment-categories', methods=['GET'])
def get_garment_categories():
    """
    Returns distinct garment item names from garment_bom_calculations
    along with a derived default_sleeve_type for each.
    Response: [{ "itemName": "Shirt", "defaultSleeve": null }, ...]
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT item_name FROM garment_bom_calculations ORDER BY item_name")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        def derive_sleeve(name: str):
            n = (name or '').lower()
            if 'shirt' in n and 't-shirt' not in n:
                return None            # Manual selection for plain Shirt
            if 't-shirt' in n or 'kurta' in n or 'polo' in n:
                return 'half_sleeve'
            if 'pant' in n or 'trouser' in n or 'jacket' in n or 'blazer' in n \
               or 'salwar' in n or 'dupatta' in n or 'boiler' in n:
                return 'full_sleeve'
            return None                # Unknown — keep manual

        result = [
            {
                "itemName": row['item_name'],
                "defaultSleeve": derive_sleeve(row['item_name'])
            }
            for row in rows
        ]
        return jsonify(result), 200

    except Exception as e:
        print(f"Error in /api/garment-categories: {e}")
        # Fallback static list so the UI never shows empty
        return jsonify([
            {"itemName": "Shirt",      "defaultSleeve": None},
            {"itemName": "T-Shirt",    "defaultSleeve": "half_sleeve"},
            {"itemName": "Pant",       "defaultSleeve": "full_sleeve"},
            {"itemName": "Blazer",     "defaultSleeve": "full_sleeve"},
            {"itemName": "Jacket",     "defaultSleeve": "full_sleeve"},
            {"itemName": "Kurta",      "defaultSleeve": "half_sleeve"},
        ]), 200


@app.route('/api/bom/calculate-from-db', methods=['GET', 'POST'])
def calculate_bom_from_db():
    conn = None
    cursor = None
    try:
        import urllib.parse, re
        raw_po = request.args.get('poNumber', '') or (request.get_json() or {}).get('poNumber', '')
        
        # Extract raw key: "PO-2024-005 (Rishi)" -> "PO-2024-005"
        clean_po = urllib.parse.unquote(str(raw_po)).strip()
        clean_po = re.sub(r'^PO:\s*', '', clean_po, flags=re.IGNORECASE)
        clean_po = re.sub(r'\s*\(.*?\)', '', clean_po)
        clean_po = clean_po.split('|')[0].strip()

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Fetch Existing BOM Items
        query = """
            SELECT 
                bom.bom_id,
                bom.po_number,
                COALESCE(bom.per_piece_qty, 1.0) AS perPieceQty,
                COALESCE(bom.final_qty, 0) AS required_qty,
                COALESCE(bom.amount, 0) AS total_cost_value,
                COALESCE(bom.brand, 'Standard') AS brand,
                COALESCE(bom.selected_sizes, 'All Sizes') AS selectedSizes,
                COALESCE(mat.material_name, bom.material_name, 'General Material') AS materialInventory,
                COALESCE(mat.unit, 'pcs') AS unit,
                COALESCE(mat.unit_price, bom.unit_price, 0) AS unitPrice
            FROM bill_of_materials bom
            LEFT JOIN store_materials mat ON bom.material_id = mat.material_id
            WHERE bom.po_number = %s OR bom.po_number LIKE %s
        """
        cursor.execute(query, (clean_po, f"%{clean_po}%"))
        bom_calcs = cursor.fetchall() or []

        # 2. Mandatory Fallback for New POs (Query Master Category Templates)
        if len(bom_calcs) == 0:
            cursor.execute("SELECT garment_category FROM purchase_orders WHERE po_number LIKE %s LIMIT 1", (f"%{clean_po}%",))
            po_rec = cursor.fetchone() or {}
            cat = po_rec.get('garment_category') or 'Shirt'

            fallback_sql = """
                SELECT 
                    template_id AS bom_id,
                    %s AS po_number,
                    COALESCE(per_piece_qty, 1.0) AS perPieceQty,
                    0 AS required_qty,
                    0 AS total_cost_value,
                    'Standard' AS brand,
                    'All Sizes' AS selectedSizes,
                    material_name AS materialInventory,
                    unit,
                    COALESCE(default_unit_price, 0) AS unitPrice
                FROM master_bom_templates 
                WHERE category = %s
            """
            cursor.execute(fallback_sql, (clean_po, cat))
            bom_calcs = cursor.fetchall() or []

        # 3. Fetch Garment Specifications for Details Card
        cursor.execute("""
            SELECT 
                COALESCE(item_description, 'Garment Order') AS garmentName,
                COALESCE(pattern, customer_name, '') AS subTitle,
                COALESCE(size, '34, 36, 38, 40') AS sizes,
                COALESCE(quantity, 100) AS totalQty,
                COALESCE(sleeve_type, 'Half Sleeve') AS sleeveType
            FROM specifications WHERE po_number LIKE %s LIMIT 1
        """, (f"%{clean_po}%",))
        specs = cursor.fetchone() or {
            "garmentName": "Uniform Security Guard",
            "subTitle": "UDF security Uniform",
            "sizes": "34, 36, 38, 40",
            "totalQty": 100,
            "sleeveType": "Half Sleeve"
        }

        return jsonify({
            "success": True,
            "poNumber": clean_po,
            "materials": bom_calcs,
            "bom_calculations": bom_calcs,
            "garmentSpecs": specs
        }), 200

    except Exception as e:
        return jsonify({"success": False, "materials": [], "message": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: DYNAMIC BOM CHECK INVENTORY (VERTICAL NORMALIZED)
# =====================================================================


# =====================================================================
# BOM CALCULATION: UNIFIED ENDPOINT WITH GARMENT DETAILS + MATERIALS
# =====================================================================
def parse_db_val_and_unit(val):
    """
    Extract numeric quantity AND unit string separately from DB strings.
    Example: '500m' -> (500.0, 'm'), '1.45cm' -> (1.45, 'cm'), '150cm' -> (150.0, 'cm')
    """
    if not val or str(val).strip() == '' or str(val).strip().lower() == 'none':
        return 0.0, None
    import re
    s = str(val).strip()
    num_match = re.search(r"([0-9.]+)", s)
    qty = float(num_match.group(1)) if num_match else 0.0
    unit_str = re.sub(r"[0-9.\s]+", "", s).strip()
    if not unit_str:
        unit_str = "units"
    return qty, unit_str

@app.route('/api/bom-calculation/<string:po_number>', methods=['GET'])
def get_bom_calculation(po_number):
    """
    Query garment_bom_calculations directly to retrieve exact article rules,
    consumption per size, and raw units from DB. Pre-fills unit prices with 0.00.
    Strictly matches by item_name and size with bottomwear sanitization guardrails.
    """
    import traceback, re as _re, urllib.parse as _up
    conn = None
    cursor = None
    try:
        clean_po = _up.unquote(str(po_number)).strip()
        clean_po = _re.sub(r'^PO:\s*', '', clean_po, flags=_re.IGNORECASE)
        clean_po = _re.sub(r'\s*\(.*?\)', '', clean_po)
        clean_po = clean_po.split('|')[0].strip()

        net_qty = None
        net_qty_param = request.args.get('net_qty')
        if net_qty_param is not None:
            try:
                net_qty = float(net_qty_param)
            except (ValueError, TypeError):
                net_qty = None

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Fetch PO header + customer name
        cursor.execute(
            """
            SELECT po.*, c.customer_name
            FROM purchase_orders po
            LEFT JOIN customers c ON po.customer_id = c.customer_id
            WHERE LOWER(TRIM(po.po_number)) = LOWER(TRIM(%s))
            LIMIT 1
            """,
            (clean_po,)
        )
        po_data = cursor.fetchone() or {}
        customer_name = po_data.get('customer_name') or ''
        po_sleeve_type = po_data.get('sleeve_type') or ''

        # 2. Fetch specifications
        garment_rows = []
        try:
            cursor.execute(
                """
                SELECT category, sleeve_type, sizes, COALESCE(quantity, 0) AS ordered_qty
                FROM order_specifications
                WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))
                """,
                (clean_po,)
            )
            garment_rows = cursor.fetchall() or []
        except Exception:
            pass

        if not garment_rows:
            try:
                cursor.execute(
                    """
                    SELECT
                        fabric_type AS category,
                        sleeve_type,
                        size AS sizes,
                        COALESCE(quantity, 0) AS ordered_qty
                    FROM specifications
                    WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))
                    """,
                    (clean_po,)
                )
                garment_rows = cursor.fetchall() or []
            except Exception:
                pass

        garments = []
        overall_po_qty = 0.0
        all_categories = []
        all_sleeves = []
        all_sizes_set = set()

        for grow in garment_rows:
            cat = grow.get('category') or 'Garment'
            slv = grow.get('sleeve_type') or po_sleeve_type or ''
            
            # Bottomwear sanitization guardrail
            is_bottom = any(b in cat.lower() for b in ['pant', 'trouser', 'jeans', 'bottom'])
            if is_bottom:
                slv = 'N/A'

            sz_raw = grow.get('sizes') or ''
            if isinstance(sz_raw, list):
                sz_list = [str(s).strip() for s in sz_raw if str(s).strip()]
            else:
                sz_list = [str(s).strip() for s in str(sz_raw).split(',') if str(s).strip()]

            for s in sz_list:
                all_sizes_set.add(s)

            item_qty = float(grow.get('ordered_qty') or 0)
            overall_po_qty += item_qty

            if cat not in all_categories:
                all_categories.append(cat)
            if slv and slv not in all_sleeves:
                all_sleeves.append(slv)

            num_sizes = len(sz_list) if len(sz_list) > 0 else 1
            qty_per_sz = round(item_qty / num_sizes, 2) if item_qty > 0 else 0
            sz_breakdown_parts = [f"{s}: {qty_per_sz:g}pcs" for s in sz_list]
            sz_breakdown_str = ', '.join(sz_breakdown_parts) if sz_breakdown_parts else f"Total: {item_qty:g}pcs"

            item_target_qty = net_qty if net_qty is not None else item_qty

            garments.append({
                'category': cat,
                'sleeve_type': slv,
                'sizes': ', '.join(sz_list),
                'size_list': sz_list,
                'size_breakdown': sz_breakdown_str,
                'total_po_qty': item_qty,
                'target_production_qty': item_target_qty
            })

        overall_target_qty = net_qty if net_qty is not None else (overall_po_qty if overall_po_qty > 0 else float(po_data.get('total_pieces') or po_data.get('quantity') or 0))

        # Determine fabric sleeve filtering & dynamic label with bottomwear guardrail
        primary_cat = all_categories[0] if all_categories else 'Garment'
        is_bottomwear = any(b in primary_cat.lower() for b in ['pant', 'trouser', 'jeans', 'bottom'])

        if is_bottomwear:
            ignored_fabric_col = None
            fabric_display_label = 'Fabric'
            effective_sleeve = 'N/A'
        else:
            sleeve_normalized = str(po_sleeve_type).strip().lower().replace('_', ' ').replace('-', ' ')
            if not sleeve_normalized:
                for g in garments:
                    g_sleeve = str(g.get('sleeve_type') or '').strip().lower().replace('_', ' ').replace('-', ' ')
                    if 'half' in g_sleeve:
                        sleeve_normalized = 'half sleeve'
                        break
                    elif 'full' in g_sleeve:
                        sleeve_normalized = 'full sleeve'
                        break
                        
            if 'half' in sleeve_normalized:
                ignored_fabric_col = 'fabric_full_sleeve'
                fabric_display_label = 'Fabric (Half Sleeve)'
                effective_sleeve = 'Half Sleeve'
            else:
                ignored_fabric_col = 'fabric_half_sleeve'
                fabric_display_label = 'Fabric (Full Sleeve)'
                effective_sleeve = 'Full Sleeve'

        ALL_COLUMNS = [
            'fabric_full_sleeve', 'fabric_half_sleeve', 'cuff', 'thread', 'collar', 
            'placket', 'size_label', 'washcare_label', 'overlock_thread', 'main_label', 
            'brand_label', 'polybag', 'box', 'clip'
        ]

        DISPLAY_NAMES = {
            'fabric_full_sleeve': fabric_display_label,
            'fabric_half_sleeve': fabric_display_label,
            'cuff': 'Cuff',
            'collar': 'Collar',
            'thread': 'Thread',
            'placket': 'Placket',
            'size_label': 'Size Label',
            'washcare_label': 'Washcare Label',
            'overlock_thread': 'Overlock Thread',
            'main_label': 'Main Label',
            'brand_label': 'Brand Label',
            'polybag': 'Polybag',
            'box': 'Box',
            'clip': 'Clip'
        }

        # Fetch active BOM rows strictly filtered by item_name and size
        bom_rows = {}
        found_cols = set()
        
        for g in garments:
            raw_cat = g['category'].strip()
            cat_singular = raw_cat[:-1] if raw_cat.lower().endswith('s') and not raw_cat.lower().startswith('boiler') else raw_cat

            for sz in g['size_list']:
                cursor.execute(
                    """
                    SELECT * FROM garment_bom_calculations
                    WHERE (LOWER(TRIM(item_name)) = LOWER(TRIM(%s)) OR LOWER(TRIM(item_name)) = LOWER(TRIM(%s)))
                    AND LOWER(TRIM(size)) = LOWER(TRIM(%s))
                    LIMIT 1
                    """,
                    (cat_singular, raw_cat, sz)
                )
                row = cursor.fetchone()
                if row:
                    bom_rows[(raw_cat.lower().strip(), sz.lower().strip())] = row
                    for col in ALL_COLUMNS:
                        if ignored_fabric_col and col == ignored_fabric_col:
                            continue
                        val = row.get(col)
                        if val is not None and str(val).strip() != '' and str(val).strip().lower() != 'none':
                            found_cols.add(col)

        active_cols = [col for col in ALL_COLUMNS if col in found_cols]

        articles_bom = []
        for col_idx, col in enumerate(active_cols, 1):
            art_id = 9000 + col_idx
            art_name = DISPLAY_NAMES.get(col, col.replace('_', ' ').title())
            unit_price = 0.0 # Pre-fill per_unit_price inputs with 0.00 (NO hardcoded 55, 60, or 1)
            available = 0.0

            sizes_breakdown = []
            sizes_breakdown_old = []
            total_art_qty = 0.0
            total_art_amount = 0.0
            detected_unit = None

            for g in garments:
                raw_cat = g['category'].strip()
                sz_list = g['size_list']
                g_target_qty = g['target_production_qty']
                num_sz = len(sz_list) if len(sz_list) > 0 else 1
                qty_per_sz = round(g_target_qty / num_sz, 2) if g_target_qty > 0 else 0

                for sz in sz_list:
                    gbom_row = bom_rows.get((raw_cat.lower().strip(), sz.lower().strip()))
                    val_str = gbom_row.get(col) if gbom_row else None
                    
                    # Parse raw number and unit cleanly using Regex without altering raw values
                    per_piece, extracted_unit = parse_db_val_and_unit(val_str)
                    
                    if extracted_unit and not detected_unit:
                        detected_unit = extracted_unit

                    base_qty = per_piece * qty_per_sz
                    sz_tot_qty = round(base_qty * 1.05, 2) # Mandatory 5% wastage formula
                    sz_final_price = round(sz_tot_qty * unit_price, 2)

                    total_art_qty += sz_tot_qty
                    total_art_amount += sz_final_price

                    sizes_breakdown.append({
                        'size': sz,
                        'garment_qty': qty_per_sz,
                        'per_piece_qty': per_piece,
                        'total_qty_inc_wastage': sz_tot_qty,
                        'unit_price': unit_price,
                        'final_price': sz_final_price
                    })
                    sizes_breakdown_old.append({
                        'size': sz,
                        'perPieceQty': per_piece,
                        'orderQty': qty_per_sz,
                        'totalQty': sz_tot_qty,
                        'perUnitPrice': unit_price,
                        'finalPrice': sz_final_price
                    })

            final_unit = detected_unit or 'units'

            articles_bom.append({
                'article_key': col,
                'article_name': art_name,
                'unit': final_unit,
                'breakdown': sizes_breakdown,
                
                # Backward compatibility
                'id': art_id,
                'articleName': art_name,
                'materialName': art_name,
                'brand': 'Standard',
                'sizeType': 'Size-Wise Breakdown',
                'sizes': sizes_breakdown_old,
                'size_breakdown': sizes_breakdown_old,
                'totalCombinedQty': round(total_art_qty, 2),
                'article_combined_qty': round(total_art_qty, 2),
                'totalCombinedAmount': round(total_art_amount, 2),
                'available': available,
                'missing': max(0.0, round(total_art_qty - available, 2)),
                'finalQuantity': round(total_art_qty, 2)
            })

        return jsonify({
            'status': 'success',
            'success': True,
            'po_number': clean_po,
            'item_name': primary_cat,
            'sleeve_type': effective_sleeve,
            'articles': articles_bom,
            
            # Backward compatibility
            'customer_name': customer_name,
            'garments': garments,
            'category': ', '.join(all_categories) if all_categories else 'Garment',
            'sizes': ', '.join(sorted(list(all_sizes_set))),
            'total_po_qty': overall_po_qty,
            'target_production_qty': overall_target_qty,
            'materials': articles_bom
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'success': False,
            'po_number': po_number,
            'item_name': '',
            'sleeve_type': '',
            'articles': [],
            'error': str(e)
        }), 200
    finally:
        if cursor:
            try: cursor.close()
            except Exception: pass
        if conn:
            try: conn.close()
            except Exception: pass


@app.route('/api/bom/check-inventory', methods=['POST', 'OPTIONS'])
@app.route('/api/bom/save-done', methods=['POST', 'OPTIONS'])
def bom_check_inventory():
    if request.method == 'OPTIONS':
        return '', 200
        
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No JSON body received"}), 400

    po_number = data.get('po_number')
    customer_name = data.get('customer_name') or ''
    po_date = data.get('po_date') or ''
    articles = data.get('articles') if data.get('articles') is not None else data.get('materials', [])

    if not po_number:
        return jsonify({"success": False, "error": "po_number is mandatory"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Loop through payload and perform an UPSERT (INSERT ... ON DUPLICATE KEY UPDATE)
        for art in articles:
            art_name = art.get('material_name') or art.get('article_name') or art.get('articleName') or ''
            size_breakdown = art.get('size_breakdown') or art.get('breakdown') or art.get('sizes') or []
            
            for sz in size_breakdown:
                per_piece = sz.get('per_piece_qty') if sz.get('per_piece_qty') is not None else sz.get('perPieceQty', 0)
                tot_qty = sz.get('total_qty') if sz.get('total_qty') is not None else sz.get('total_qty_inc_wastage') if sz.get('total_qty_inc_wastage') is not None else sz.get('totalQty', 0)
                unit_p = sz.get('per_unit_price') if sz.get('per_unit_price') is not None else sz.get('unit_price') if sz.get('unit_price') is not None else sz.get('perUnitPrice', 0)
                fin_p = sz.get('final_price') if sz.get('final_price') is not None else sz.get('finalPrice', 0)
                size_val = sz.get('size', 'Standard')

                cursor.execute(
                    """
                    INSERT INTO bom_done 
                      (po_number, customer_name, po_date, item_name, size, per_piece_qty, total_qty, per_unit_price, final_price)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                      per_piece_qty = VALUES(per_piece_qty),
                      total_qty = VALUES(total_qty),
                      per_unit_price = VALUES(per_unit_price),
                      final_price = VALUES(final_price)
                    """,
                    (
                        po_number,
                        customer_name,
                        po_date,
                        art_name,
                        size_val,
                        per_piece,
                        tot_qty,
                        unit_p,
                        fin_p
                    )
                )

        # 2. Update PO Workflow Stage from BOM Calculation to Inventory Check
        try:
            cursor.execute(
                """
                UPDATE purchase_orders
                SET stage = 'Inventory Check'
                WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))
                """,
                (po_number,)
            )
        except Exception as e_stage:
            print("[WARN] Could not update purchase_orders stage:", e_stage)

        try:
            cursor.execute(
                """
                UPDATE specifications
                SET stage = 'Inventory Check'
                WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))
                """,
                (po_number,)
            )
        except Exception:
            pass

        try:
            cursor.execute(
                """
                UPDATE order_specifications
                SET stage = 'Inventory Check'
                WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))
                """,
                (po_number,)
            )
        except Exception:
            pass
            
        conn.commit()
        return jsonify({"success": True, "status": "success", "message": "BOM snapshot saved successfully & PO stage updated to Inventory Check"}), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()



@app.route('/api/inventory-check/pos', methods=['GET', 'OPTIONS'])
def get_inventory_check_pos():
    if request.method == 'OPTIONS':
        return '', 200
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT DISTINCT po_number, customer_name 
                FROM bom_done 
                WHERE po_number IS NOT NULL AND po_number != ''
                UNION
                SELECT DISTINCT po.po_number, COALESCE(c.customer_name, po.contact_person, 'Customer') AS customer_name
                FROM purchase_orders po
                LEFT JOIN customers c ON po.customer_id = c.customer_id
                WHERE LOWER(TRIM(po.stage)) = 'inventory check'
                   OR LOWER(TRIM(po.stage)) = 'bom calculation'
            """)
            results = cursor.fetchall() or []
        except Exception as e_po:
            print("[WARN] Unified PO query failed:", e_po)
            results = []
        
        return jsonify({
            "success": True,
            "pos": results,
            "data": results
        }), 200
    except Exception as e:
        print("[ERROR] /api/inventory-check/pos:", str(e))
        return jsonify({"success": True, "pos": [], "data": [], "error": str(e)}), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/inventory-check/details', methods=['GET', 'OPTIONS'])
def get_inventory_check_details():
    if request.method == 'OPTIONS':
        return '', 200
        
    po_number = request.args.get('po_number')
    if not po_number:
        return jsonify({"success": False, "error": "po_number is required"}), 400
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT 
                COALESCE(bd.item_name, 'Article') AS material_name,
                'Fabric' AS category,
                COALESCE(SUM(COALESCE(bd.total_qty, 0)), 0) AS required_qty,
                COALESCE(inv.current_stock, 0) AS available_qty,
                GREATEST(0, COALESCE(SUM(COALESCE(bd.total_qty, 0)), 0) - COALESCE(inv.current_stock, 0)) AS shortage_qty,
                'units' AS unit,
                CASE 
                    WHEN COALESCE(inv.current_stock, 0) >= COALESCE(SUM(COALESCE(bd.total_qty, 0)), 0) AND COALESCE(SUM(COALESCE(bd.total_qty, 0)), 0) > 0 THEN 'Fully Available'
                    WHEN COALESCE(inv.current_stock, 0) > 0 THEN 'Partially Available'
                    ELSE 'Critical Shortage'
                END AS status
            FROM bom_done bd
            LEFT JOIN inventory inv ON LOWER(TRIM(bd.item_name)) = LOWER(TRIM(inv.material_name))
            WHERE LOWER(TRIM(bd.po_number)) = LOWER(TRIM(%s))
            GROUP BY bd.item_name, inv.current_stock
        """
        cursor.execute(query, (po_number,))
        details = cursor.fetchall() or []
        
        fully_available = sum(1 for d in details if d.get('status') == 'Fully Available')
        partially_available = sum(1 for d in details if d.get('status') == 'Partially Available')
        critical_shortage = sum(1 for d in details if d.get('status') == 'Critical Shortage')
        
        overall_status = 'Pending Allocation'
        if critical_shortage > 0:
            overall_status = 'Critical Shortage'
        elif partially_available > 0:
            overall_status = 'Partially Available'
        elif fully_available == len(details) and len(details) > 0:
            overall_status = 'Fully Available'
            
        return jsonify({
            "success": True,
            "data": details,
            "summary": {
                "fully_available_count": fully_available,
                "partially_available_count": partially_available,
                "critical_shortages_count": critical_shortage,
                "overall_status": overall_status
            }
        }), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": True,
            "data": [],
            "summary": {
                "fully_available_count": 0,
                "partially_available_count": 0,
                "critical_shortages_count": 0,
                "overall_status": "Pending Allocation"
            },
            "error": str(e)
        }), 200
    finally:
        if cursor: cursor.close()
        if conn: conn.close()



# =====================================================================
# API: INVENTORY CHECK GET
# =====================================================================
@app.route('/api/inventory/check', methods=['GET', 'POST', 'OPTIONS'])
def inventory_check_get():
    if request.method == 'OPTIONS':
        return '', 200
        
    po_number = request.args.get('po_number')
    if not po_number:
        return jsonify({"success": False, "error": "po_number is required"}), 400
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = '''
            SELECT 
                item_name AS material_name,
                SUM(total_qty) as required_qty
            FROM bom_done 
            WHERE po_number = %s 
            GROUP BY item_name
        '''
        cursor.execute(query, (po_number,))
        records = cursor.fetchall()
        
        return jsonify({"success": True, "data": records}), 200

    except Exception as e:
        print(f"[ERROR] /api/inventory/check: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# API: BOM PO LIST
# =====================================================================
@app.route('/api/bom/po-list', methods=['GET', 'OPTIONS'])
def bom_po_list():
    if request.method == 'OPTIONS':
        return '', 200
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = '''
            SELECT DISTINCT po_number, customer_name
            FROM bom_done
            WHERE po_number IS NOT NULL AND po_number != 'UDF'
            
        '''
        cursor.execute(query)
        records = cursor.fetchall()
        
        return jsonify({"success": True, "data": records}), 200

    except Exception as e:
        print(f"[ERROR] /api/bom/po-list: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/stock-check/<string:po_number>', methods=['GET'])
def api_stock_check_get(po_number):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Query Purchase Order header for dates
        cursor.execute("SELECT * FROM purchase_orders WHERE LOWER(TRIM(po_number)) = LOWER(TRIM(%s))", (po_number,))
        po_data = cursor.fetchone()
        
        import datetime
        def format_date(dt):
            if not dt: return ""
            if isinstance(dt, (datetime.date, datetime.datetime)):
                return dt.strftime("%m/%d/%Y")
            if isinstance(dt, str) and ' ' in dt:
                return dt.split(' ')[0]
            return str(dt)
            
        po_date = ""
        delivery_date = ""
        if po_data:
            po_date = format_date(po_data.get('order_date') or po_data.get('po_date'))
            delivery_date = format_date(po_data.get('delivery_date'))

        # 2. Query Purchase Order Line-Items (order_specifications & specifications fallback)
        clean_po = po_number.strip()
        cursor.execute("SELECT * FROM order_specifications WHERE TRIM(po_number) = %s", (clean_po,))
        items = cursor.fetchall()
        
        if not items and po_data and po_data.get('id'):
            try:
                cursor.execute("SELECT * FROM order_specifications WHERE po_id = %s", (po_data['id'],))
                items = cursor.fetchall()
            except Exception:
                pass

        if not items:
            cursor.execute("SELECT * FROM specifications WHERE TRIM(po_number) = %s", (clean_po,))
            items = cursor.fetchall()
            
        print(f"DEBUG: Found {len(items)} items for PO {clean_po}")
        
        if not items:
            cursor.close(); conn.close()
            return jsonify({
                "po_number": po_data.get('po_number', po_number) if po_data else po_number,
                "po_date": po_date,
                "delivery_date": delivery_date,
                "order_specifications": "No specifications found for this PO",
                "req_qty": 0,
                "available_in_store": 0,
                "status_label": "Out of Stock (0)",
                "status_type": "OUT_OF_STOCK"
            }), 200
            
        total_qty = sum(int(item.get('quantity') or item.get('qty') or 0) for item in items)
        
        all_sizes = set()
        categories = set()
        for item in items:
            sz = item.get('sizes') or item.get('size')
            if sz:
                parts = [s.strip() for s in str(sz).split(',')]
                all_sizes.update(parts)
            c = item.get('category') or item.get('item_description') or item.get('fabric_type') or "Garment"
            if c: categories.add(c.strip())
            
        cat_str = list(categories)[0] if categories else "Garment"
        
        try:
            sorted_sizes = sorted(list(all_sizes), key=lambda x: int(x) if x.isdigit() else x)
        except Exception:
            sorted_sizes = sorted(list(all_sizes))
        sizes_str = ", ".join(sorted_sizes) if sorted_sizes else "N/A"
        
        spec_summary = f"{cat_str} - Sizes: {sizes_str} | Qty: {total_qty}"
        
        # 3. Finished Goods Store Check (store_garments)
        if all_sizes:
            format_strings = ','.join(['%s'] * len(all_sizes))
            query = f"SELECT SUM(available_qty) as total_available FROM store_garments WHERE LOWER(TRIM(size)) IN ({format_strings})"
            params = [str(s).strip().lower() for s in all_sizes]
            if categories:
                cat_format = ','.join(['%s'] * len(categories))
                query += f" AND LOWER(TRIM(category)) IN ({cat_format})"
                params.extend([str(c).strip().lower() for c in categories])
            cursor.execute(query, tuple(params))
            res = cursor.fetchone()
            total_avail = int(res.get('total_available') or 0) if res else 0
        else:
            total_avail = 0
            
        if total_avail >= total_qty and total_qty > 0:
            status_label = f"In Stock ({total_avail})"
            status_type = "IN_STOCK"
        elif 0 < total_avail < total_qty:
            status_label = f"Partial Stock ({total_avail})"
            status_type = "PARTIAL_STOCK"
        else:
            status_label = "Out of Stock (0)"
            status_type = "OUT_OF_STOCK"
            
        cursor.close(); conn.close()
        
        # 4. Return EXACT JSON Payload requested
        return jsonify({
            "po_number": po_data.get('po_number', po_number) if po_data else po_number,
            "po_date": po_date,
            "delivery_date": delivery_date,
            "order_specifications": spec_summary,
            "req_qty": total_qty,
            "available_in_store": total_avail,
            "status_label": status_label,
            "status_type": status_type
        }), 200
        
    except Exception as e:
        print("Error in /api/stock-check:", str(e))
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)

# =====================================================================
# MODULE 11: PRODUCTION TRACKING & LIVE PERSONS PIPELINE
# =====================================================================

@app.route('/api/production/tracking-dashboard', methods=['GET', 'OPTIONS'])
def get_production_tracking_dashboard():
    """
    Fetches live orders currently moving through the production floor pipeline.
    Safely captures orders with missing/bypassed PO numbers by falling back to Customer info.
    """
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_read_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Pull orders explicitly inside any active manufacturing floor step
        query = """
            SELECT 
                po_number, 
                customer_name, 
                status, 
                stage, 
                order_date, 
                delivery_date, 
                COALESCE(total_pieces, quantity, 0) AS total_pieces
            FROM purchase_orders 
            WHERE stage IN (
                'BOM Calculation', 'Inventory Check', 'Material Allocation', 
                'Procurement', 'Material Release', 'Production', 'Quality & Packing'
            ) AND status != 'COMPLETED'
            ORDER BY delivery_date ASC
        """
        cursor.execute(query)
        active_jobs = cursor.fetchall()
        
        # Sanitize metadata formatting for live frontend reactive state
        for job in active_jobs:
            if job.get('order_date'):
                job['order_date'] = format_db_date(str(job['order_date']))
            if job.get('delivery_date'):
                job['delivery_date'] = format_db_date(str(job['delivery_date']))
            
            # Safe boundary check if frontend bypassed generating a strict PO number asset string
            if not job.get('po_number'):
                job['po_number'] = f"PENDING-{str(job.get('customer_name') or 'UNKNOWN')[:4].upper()}"

        return jsonify({"success": True, "active_jobs": active_jobs}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to pull live tracking analytics: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/production/persons', methods=['GET', 'OPTIONS'])
def get_production_persons():
    """
    Fetches your team of workers. Implements toggle filter to switch
    between Active and Soft Deleted (Archived) Profiles.
    """
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_read_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    show_removed = request.args.get('showRemovedPersons', 'false').lower() == 'true'
    is_deleted_flag = 1 if show_removed else 0
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT person_id, full_name, contact_number, role, rate, wage_cycle, active_po_batch, total_allocated 
            FROM production_persons 
            WHERE is_deleted = %s 
            
        """
        cursor.execute(query, (is_deleted_flag,))
        persons = cursor.fetchall()
        return jsonify({"success": True, "persons": persons}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/production/persons/add', methods=['POST', 'OPTIONS'])
def add_production_person():
    """
    Onboards a new person with Indian phone numbers, roles, custom base rates, and wage cycles.
    """
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_write_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    data = request.json or {}
    name = data.get('fullName')
    phone = data.get('contactNumber') # Handled as raw digits string
    role = data.get('role', 'Cutting')
    rate = float(data.get('rate', 0.0))
    wage_cycle = data.get('wageCycle', 'Monthly') # Daily, Weekly, Monthly

    if not name or not phone:
        return jsonify({"success": False, "error": "Person name and standard contact identifier are required"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Strict Indian formatting verification before saving
        clean_phone = str(phone).strip().replace(" ", "").replace("-", "")
        if len(clean_phone) > 10:
            clean_phone = clean_phone[-10:] # extract standard 10 digits cleanly

        query = """
            INSERT INTO production_persons (full_name, contact_number, role, rate, wage_cycle, is_deleted) 
            VALUES (%s, %s, %s, %s, %s, 0)
        """
        cursor.execute(query, (name, clean_phone, role, rate, wage_cycle))
        conn.commit()
        return jsonify({"success": True, "message": "Person successfully saved to real-time payroll schema"}), 201
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/production/persons/soft-delete/<int:person_id>', methods=['PUT', 'OPTIONS'])
def soft_delete_production_person(person_id):
    """
    Flags an operative profile as soft-deleted so they drop off the active grid without data loss.
    """
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_write_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE production_persons SET is_deleted = 1 WHERE person_id = %s", (person_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Profile soft deleted. Accessible via archive filters"}), 200
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/production/persons/recover/<int:person_id>', methods=['PUT', 'OPTIONS'])
def recover_production_person(person_id):
    """
    Restores a soft-deleted worker profile back to the live active grid.
    """
    if request.method == 'OPTIONS':
        return '', 200
    if not verify_write_key('Production'):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE production_persons SET is_deleted = 0 WHERE person_id = %s", (person_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Operative profile successfully recovered to live view"}), 200
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
@app.route('/api/inventory/stock-overview/raw-materials', methods=['GET', 'OPTIONS'])
def get_stock_overview_raw_materials():
    if request.method == 'OPTIONS':
        return '', 200
    
    date_filter = request.args.get('date')
    timeframe = request.args.get('timeframe')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM raw_material"
        params = []
        if date_filter:
            if timeframe == 'monthly':
                query += " WHERE DATE_FORMAT(created_at, '%%Y-%%m') = DATE_FORMAT(%s, '%%Y-%%m')"
                params.append(date_filter)
            elif timeframe == 'weekly':
                query += " WHERE YEARWEEK(created_at, 1) = YEARWEEK(%s, 1)"
                params.append(date_filter)
            else:
                query += " WHERE DATE(created_at) = %s"
                params.append(date_filter)
                
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        
        result = []
        for row in rows:
            result.append({
                "id": f"RM-{row['id']:03d}",
                "description": row['description'],
                "code": f"RM-{row['id']:03d}",
                "unit": row['unit'],
                "openingStock": float(row['op_stock'] or 0),
                "purchase": float(row['purchases'] or 0),
                "total": float(row['total'] or 0),
                "issue": float(row['issue'] or 0),
                "closing": float(row['closing_stock'] or 0),
                "wip": float(row['wip_cutting'] or 0),
                "netTotal": float(row['total_qty'] or 0),
                "rate": float(row['rate'] or 0),
                "totalAmount": float(row['total_amount'] or 0)
            })
            
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/api/inventory/stock-overview/finished-goods', methods=['GET', 'OPTIONS'])
def get_stock_overview_finished_goods():
    if request.method == 'OPTIONS':
        return '', 200
        
    date_filter = request.args.get('date')
    timeframe = request.args.get('timeframe')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM finished_goods"
        params = []
        if date_filter:
            if timeframe == 'monthly':
                query += " WHERE DATE_FORMAT(created_at, '%%Y-%%m') = DATE_FORMAT(%s, '%%Y-%%m')"
                params.append(date_filter)
            elif timeframe == 'weekly':
                query += " WHERE YEARWEEK(created_at, 1) = YEARWEEK(%s, 1)"
                params.append(date_filter)
            else:
                query += " WHERE DATE(created_at) = %s"
                params.append(date_filter)
                
        query += " ORDER BY sr_no"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        
        result = []
        for row in rows:
            result.append({
                "id": f"FG-{row['id']:03d}",
                "srNo": row['sr_no'],
                "type": row['type'],
                "code": f"FG-{row['id']:03d}",
                "openingStock": float(row['opening_stock'] or 0),
                "production": float(row['production'] or 0),
                "sale": float(row['sale'] or 0),
                "closingStock": float(row['closing_stock'] or 0),
                "cost": float(row['cost'] or 0),
                "totalAmount": float(row['total_amount'] or 0),
                "unit": row['unit']
            })
            
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# =====================================================================
# BOM: SIZE-WISE MATERIAL CALCULATION
# =====================================================================
@app.route('/api/bom/calculate-requirements', methods=['POST'])
def calculate_bom_requirements():
    try:
        data = request.json
        garment_type = data.get('garmentType')
        order_breakdown = data.get('orderBreakdown', [])

        if not garment_type or not order_breakdown:
            return jsonify({"success": False, "error": "Invalid payload"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Fetch consumption matrix for the garment type
        cursor.execute('''
            SELECT cm.size, cm.unit_consumption, cm.material_id, sm.material_name, sm.unit, sm.available_qty, sm.category
            FROM consumption_matrix cm
            JOIN store_materials sm ON cm.material_id = sm.material_id
            WHERE cm.garment_type = %s
        ''', (garment_type,))
        matrix_rows = cursor.fetchall()

        # Build a lookup for matrix
        matrix_dict = {}
        material_info = {}
        for row in matrix_rows:
            size = row['size']
            mat_id = row['material_id']
            if size not in matrix_dict:
                matrix_dict[size] = {}
            matrix_dict[size][mat_id] = float(row['unit_consumption'])
            if mat_id not in material_info:
                material_info[mat_id] = {
                    'name': row['material_name'],
                    'unit': row['unit'],
                    'available_qty': float(row['available_qty']),
                    'category': row['category']
                }

        # 2. Calculate requirements
        requirements_per_material = {} 

        for order_item in order_breakdown:
            size = str(order_item['size'])
            qty = int(order_item['quantity'])
            
            if size in matrix_dict:
                for mat_id, unit_cons in matrix_dict[size].items():
                    req_qty = qty * unit_cons
                    
                    if mat_id not in requirements_per_material:
                        requirements_per_material[mat_id] = {
                            'total_required': 0.0,
                            'sizes': {}
                        }
                    
                    requirements_per_material[mat_id]['total_required'] += req_qty
                    requirements_per_material[mat_id]['sizes'][size] = req_qty

        # 3. Format response
        results = []
        for mat_id, data in requirements_per_material.items():
            info = material_info[mat_id]
            total_req = data['total_required']
            available = info['available_qty']
            shortage = max(0.0, total_req - available)
            
            if shortage > 0:
                status = "SHORTAGE"
            elif total_req <= available:
                status = "AVAILABLE"
            else:
                status = "PENDING"
                
            results.append({
                "materialId": mat_id,
                "materialName": info['name'],
                "category": info['category'],
                "unit": info['unit'],
                "totalRequired": total_req,
                "availableQty": available,
                "shortageQty": shortage,
                "status": status,
                "sizeBreakdown": data['sizes']
            })

        return jsonify({
            "success": True,
            "garmentType": garment_type,
            "materials": results
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if 'cursor' in locals() and cursor: cursor.close()
        if 'conn' in locals() and conn: conn.close()

# =====================================================================
# BOM: PURE SIZE-WISE BOM CALCULATION & INVENTORY CHECK (HARDCODED)
# =====================================================================
@app.route('/api/bom/calculate-and-check-stock', methods=['POST'])
def calculate_and_check_stock():
    try:
        data = request.json
        garment_type = data.get('garmentType')
        brand_name = data.get('brandName')
        size_quantities = data.get('sizeQuantities', {})

        if not garment_type or not size_quantities:
            return jsonify({"success": False, "error": "Invalid payload"}), 400

        # Excel-Based Consumption Matrix Hardcoded
        # A generic simplified scale as requested
        CONSUMPTION_RULES = {
            'Shirt': {
                'Fabric': lambda size: 1.35 + (max(0, int(size)-34) * 0.05), # 34=1.35, 36=1.45, etc...
                'Thread': lambda size: 200, # 200m per size piece
                'Collar': lambda size: 14.5, # 14.5 inch per size piece
                'Brand Tags': lambda size: 1 # 1 pc per piece
            },
            'Pant': {
                'Fabric': lambda size: 1.20 + (max(0, int(size)-34) * 0.05),
                'Thread': lambda size: 150,
                'Brand Tags': lambda size: 1
            }
        }

        rules = CONSUMPTION_RULES.get(garment_type)
        if not rules:
            return jsonify({"success": False, "error": f"No matrix rules for {garment_type}"}), 400

        # Calculate step
        aggregated_requirements = {}
        for article, formula in rules.items():
            total_req = 0
            size_breakdown = {}
            for size_str, qty in size_quantities.items():
                qty = int(qty)
                req = formula(size_str) * qty
                size_breakdown[size_str] = req
                total_req += req
            aggregated_requirements[article] = {
                "total_required_qty": total_req,
                "size_breakdown": size_breakdown
            }

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Fetch all materials
        cursor.execute("SELECT * FROM store_materials")
        store_mats = cursor.fetchall()

        # Simple matcher function to map 'article' to DB 'material'
        def match_material(article, mats):
            for m in mats:
                name = m['material_name'].lower()
                cat = m['category'].lower() if m['category'] else ''
                # heuristic matching
                if article.lower() in name or article.lower() in cat:
                    return m
                if article == 'Brand Tags' and ('tag' in name or 'label' in name):
                    return m
                if article == 'Fabric' and 'fabric' in name:
                    return m
                if article == 'Collar' and 'hook' in name:
                    return m
            return None

        # Build response
        results = []
        for article, data_req in aggregated_requirements.items():
            matched_db = match_material(article, store_mats)
            
            store_available_qty = float(matched_db['available_qty']) if matched_db else 0.0
            total_req = data_req['total_required_qty']
            shortage = max(0.0, total_req - store_available_qty)
            
            if shortage > 0:
                status = "SHORTAGE"
            elif total_req <= store_available_qty:
                status = "AVAILABLE"
            else:
                status = "PENDING"

            results.append({
                "articleName": matched_db['material_name'] if matched_db else article,
                "materialId": matched_db['material_id'] if matched_db else None,
                "category": matched_db['category'] if matched_db else article,
                "unit": matched_db['unit'] if matched_db else 'units',
                "brandName": brand_name,
                "sizeBreakdown": data_req['size_breakdown'],
                "totalRequired": total_req,
                "storeAvailableQty": store_available_qty,
                "shortageQty": shortage,
                "status": status
            })

        return jsonify({
            "success": True,
            "garmentType": garment_type,
            "brandName": brand_name,
            "materials": results
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if 'cursor' in locals() and cursor: cursor.close()
        if 'conn' in locals() and conn: conn.close()
