import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import os
import threading
import random
import datetime
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("WARNING: SUPABASE_URL or SUPABASE_KEY is missing in .env")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
# Enable CORS so the landing page can send requests to this server from any domain/port
CORS(app)

def check_password(input_password, db_password):
    if not db_password:
        return False
    if input_password == db_password:
        return True
    # Support SHA-256 hashed password comparison
    hashed = hashlib.sha256(input_password.encode()).hexdigest()
    if hashed == db_password:
        return True
    return False

def send_otp_email(to_email, otp_code):
    gmail_client_id = os.getenv("GMAIL_CLIENT_ID")
    gmail_client_secret = os.getenv("GMAIL_CLIENT_SECRET")
    gmail_refresh_token = os.getenv("GMAIL_REFRESH_TOKEN")
    gmail_sender = os.getenv("GMAIL_USER") or os.getenv("SMTP_USER")

    subject = f"Your ProSync OTP Code: {otp_code}"
    body = f"""Hello,

Your One-Time Password (OTP) for signing in to ProSync is:

{otp_code}

This code is valid for 10 minutes. If you did not request this code, please ignore this email.

Best regards,
ProSync Security Team"""

    # If Gmail API credentials are provided, use the Gmail REST API (HTTPS)
    if gmail_client_id and gmail_client_secret and gmail_refresh_token and gmail_sender:
        try:
            import requests
            import base64
            from email.message import EmailMessage

            print(f"Attempting to send OTP email to {to_email} via Gmail REST API...", flush=True)
            
            # 1. Get Access Token using Refresh Token
            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "client_id": gmail_client_id,
                "client_secret": gmail_client_secret,
                "refresh_token": gmail_refresh_token,
                "grant_type": "refresh_token"
            }
            token_resp = requests.post(token_url, data=token_data, timeout=5)
            token_resp.raise_for_status()
            access_token = token_resp.json().get("access_token")

            # 2. Build MIME message
            msg = EmailMessage()
            msg.set_content(body)
            msg["Subject"] = subject
            msg["From"] = gmail_sender
            msg["To"] = to_email

            # 3. Base64url-encode the email raw bytes
            raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

            # 4. Send email via Gmail REST API
            send_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
            send_headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            send_resp = requests.post(send_url, headers=send_headers, json={"raw": raw_message}, timeout=5)
            send_resp.raise_for_status()
            print(f"OTP email sent successfully to {to_email} via Gmail REST API.", flush=True)
            return True

        except Exception as api_err:
            print(f"Gmail REST API sending failed: {api_err}", flush=True)
            # Fall through to SMTP fallback or backup log

    # Otherwise, fall back to SMTP
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")

    # If SMTP is not configured, fall back to console logging
    if not (smtp_server and smtp_port and smtp_user and smtp_password):
        print("\n" + "="*60, flush=True)
        print(f"[MOCK EMAIL] OTP verification code for {to_email}: {otp_code}", flush=True)
        print("Configure SMTP or Gmail API env variables in .env to send real emails.", flush=True)
        print("="*60 + "\n", flush=True)
        return True

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        port = int(smtp_port)
        if port == 465:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=5)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=5)
            server.starttls()

        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, to_email, msg.as_string())
        server.quit()
        print(f"OTP email sent to {to_email} via SMTP fallback", flush=True)
        return True
    except Exception as e:
        print(f"Failed to send OTP email to {to_email} via SMTP: {e}", flush=True)
        # Even if email sending fails, we log the OTP to the console for testing convenience
        print(f"[BACKUP LOG] OTP verification code: {otp_code}", flush=True)
        return False

# Route to serve the landing page index.html
@app.route("/")
def index():
    return send_from_directory("landing-page", "index.html")

# Route to serve other static files in the landing-page directory if needed
@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("landing-page", path)

# Temporary in-memory storage for pending sign-ups (valid for 10 minutes)
temp_signups = {}

# 1. Login Endpoint (For existing users)
@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required"}), 400

    try:
        # Check if user exists in public.web_users
        res = supabase.table("web_users").select("*").eq("email", email).execute()
        if not res.data:
            return jsonify({"success": False, "error": "User not found. Please Sign Up first."}), 404

        user = res.data[0]

        # Password check (direct password or SHA-256 hash)
        db_password = user.get("password")
        if not check_password(password, db_password):
            return jsonify({"success": False, "error": "Invalid password"}), 401
        
        return jsonify({
            "success": True,
            "message": "Login successful!",
            "otp_required": False,
            "name": user.get("name")
        })

    except Exception as e:
        print("AUTH LOGIN ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500



def validate_password_strength(password):
    if len(password) < 6:
        return "Password must be at least 6 characters long."
    if not any(c.isalpha() for c in password):
        return "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    return None

# 2. Register Endpoint (For new users)
@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")

    if not email or not password or not name:
        return jsonify({"success": False, "error": "Name, email and password are required to register"}), 400

    pw_err = validate_password_strength(password)
    if pw_err:
        return jsonify({"success": False, "error": pw_err}), 400

    try:
        # Check if user already exists
        res = supabase.table("web_users").select("email").eq("email", email).execute()
        if res.data:
            return jsonify({"success": False, "error": "Email already registered. Please Sign In."}), 400

        # Generate OTP to verify the new registration
        otp_code = f"{random.randint(100000, 999999)}"
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)

        # Save to temporary in-memory dictionary
        temp_signups[email] = {
            "name": name,
            "password": password,
            "otp_code": otp_code,
            "expires_at": expires_at
        }

        # Send Email synchronously so Gunicorn sync worker doesn't suspend it
        send_otp_email(email, otp_code)

        return jsonify({
            "success": True,
            "message": "An OTP code has been sent to verify your email.",
            "otp_required": True
        })

    except Exception as e:
        print("AUTH REGISTER ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

# 3. OTP Verification Endpoint (Handles both Signup & Passwordless login)
@app.route("/api/auth/verify-otp", methods=["POST"])
def auth_verify_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    otp_code = data.get("otp")

    if not email or not otp_code:
        return jsonify({"success": False, "error": "Email and OTP are required"}), 400

    try:
        # Check Case 1: Pending Signup Verification
        if email in temp_signups:
            pending = temp_signups[email]
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            
            if now_dt > pending["expires_at"]:
                del temp_signups[email]
                return jsonify({"success": False, "error": "OTP has expired. Please register again."}), 400

            if str(pending["otp_code"]).strip() != str(otp_code).strip():
                return jsonify({"success": False, "error": "Invalid OTP code"}), 401

            # Verification successful -> Return success and the password hash so the client can save it after onboarding/consent
            password_hash = pending["password"]

            # Clean up memory
            del temp_signups[email]

            return jsonify({
                "success": True,
                "message": "OTP verified successfully.",
                "password_hash": password_hash
            })

        # Check Case 2: Existing User Passwordless Login Verification
        else:
            res = supabase.table("web_users").select("*").eq("email", email).execute()
            if not res.data:
                return jsonify({"success": False, "error": "User record not found"}), 404

            user = res.data[0]
            db_otp = user.get("otp_code")
            db_expiry = user.get("otp_expires_at")

            if not db_otp or not db_expiry:
                return jsonify({"success": False, "error": "No pending OTP request for this email"}), 400

            expiry_dt = datetime.datetime.fromisoformat(db_expiry.replace("Z", "+00:00"))
            now_dt = datetime.datetime.now(datetime.timezone.utc)

            if now_dt > expiry_dt:
                return jsonify({"success": False, "error": "OTP has expired. Please try again."}), 400

            if str(db_otp).strip() != str(otp_code).strip():
                return jsonify({"success": False, "error": "Invalid OTP code"}), 401

            # Clear OTP fields in DB
            supabase.table("web_users").update({
                "otp_code": None,
                "otp_expires_at": None
            }).eq("email", email).execute()

            return jsonify({
                "success": True,
                "message": "Authentication successful!"
            })

    except Exception as e:
        print("VERIFY OTP ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

# 4. Contact Form Endpoint
@app.route("/api/contact", methods=["POST"])
def contact_submit():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    email = data.get("email")
    message = data.get("message")

    if not name or not email or not message:
        return jsonify({"success": False, "error": "Name, email and message are required"}), 400

    try:
        # 1. Insert message into Supabase
        try:
            supabase.table("contact_messages").insert({
                "name": name,
                "email": email,
                "message": message
            }).execute()
            print(f"Saved contact message from {email} to database.")
        except Exception as db_err:
            print(f"Note: Could not save message to 'contact_messages' table: {db_err}")

        # 2. Output console log alert
        print("\n" + "="*60, flush=True)
        print(f"[CONTACT US ALERT] New Message Received!", flush=True)
        print(f"From: {name} ({email})", flush=True)
        print(f"Message: {message}", flush=True)
        print("="*60 + "\n", flush=True)

        return jsonify({
            "success": True,
            "message": "Thank you! Your message has been received. We will get back to you shortly."
        })

    except Exception as e:
        print("CONTACT FORM ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

# 5. Record Payment Checkout Event
@app.route("/api/payment/record", methods=["POST"])
def record_payment():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    plan = data.get("plan")
    users = data.get("users")
    months = data.get("months")
    company_name = data.get("company_name", "")
    company_address = data.get("company_address", "")

    if not email or not plan or not users or not months:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    try:
        # Calculate dates
        start_date = datetime.datetime.now(datetime.timezone.utc)
        
        # Add exact months and then add 1 day grace period
        m = start_date.month - 1 + int(months)
        year = start_date.year + m // 12
        month = m % 12 + 1
        
        import calendar
        _, last_day = calendar.monthrange(year, month)
        day = min(start_date.day, last_day)
        
        base_end_date = datetime.datetime(year, month, day, 23, 59, 59, tzinfo=datetime.timezone.utc)
        end_date = base_end_date + datetime.timedelta(days=1)

        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()

        # 1. Save to local log file (JSONL format)
        log_entry = {
            "timestamp": start_date_str,
            "email": email,
            "plan": plan,
            "users": users,
            "months": months,
            "company_name": company_name,
            "company_address": company_address,
            "start_date": start_date_str,
            "end_date": end_date_str
        }
        
        try:
            import json
            # Write to /tmp on serverless environments
            log_file_path = "/tmp/billing_transactions.jsonl"
            with open(log_file_path, "a", encoding="utf-8") as lf:
                lf.write(json.dumps(log_entry) + "\n")
            print(f"Recorded payment locally to /tmp for {email}")
        except Exception as log_err:
            print(f"Could not log transaction locally (read-only filesystem): {log_err}")

        # 2. Try saving to public.billing_transactions in Supabase
        db_success = False
        try:
            supabase.table("billing_transactions").insert({
                "user_email": email,
                "plan": plan,
                "users_count": int(users),
                "months": int(months),
                "company_name": company_name,
                "company_address": company_address,
                "start_date": start_date_str,
                "end_date": end_date_str,
                "Approved": "pending"
            }, returning="minimal").execute()
            print("Successfully recorded payment to billing_transactions table.")
            db_success = True
        except Exception as db_err:
            print(f"billing_transactions insert failed, using contact_messages fallback: {db_err}")
            
            # Fallback to contact_messages
            message_body = f"[PAYMENT_CHECKOUT] Plan: {plan}, Users: {users}, Months: {months}, Company: {company_name}, Address: {company_address}, Start: {start_date_str[:10]}, End: {end_date_str[:10]}"
            try:
                supabase.table("contact_messages").insert({
                    "name": "Payment Record",
                    "email": email,
                    "message": message_body
                }, returning="minimal").execute()
                print("Successfully recorded payment to contact_messages fallback.")
                db_success = True
            except Exception as fallback_err:
                print(f"Fallback database insert failed: {fallback_err}")



        return jsonify({
            "success": True,
            "message": "Payment event recorded successfully",
            "db_success": db_success,
            "start_date": start_date_str,
            "end_date": end_date_str
        })

    except Exception as e:
        print("RECORD PAYMENT ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

# 6. Get User Profile & Transaction Details
@app.route("/api/user/profile", methods=["POST"])
def get_user_profile():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    try:
        # 1. Fetch user name, type, and company_code from web_users
        user_res = supabase.table("web_users").select("name, type, company_code").eq("email", email).execute()
        name = "User"
        user_type = "company"
        company_code = None
        if user_res.data:
            name = user_res.data[0].get("name", "User")
            user_type = user_res.data[0].get("type", "company")
            company_code = user_res.data[0].get("company_code")

        # 2. Fetch all transactions for this user
        tx_res = supabase.table("billing_transactions").select("*").eq("user_email", email).order("created_at", desc=True).execute()
        transactions = tx_res.data or []

        # 3. Get company details from latest transaction
        company_name = ""
        company_address = ""
        if transactions:
            company_name = transactions[0].get("company_name", "")
            company_address = transactions[0].get("company_address", "")

        return jsonify({
            "success": True,
            "name": name,
            "email": email,
            "type": user_type,
            "company_code": company_code,
            "company_name": company_name,
            "company_address": company_address,
            "transactions": transactions
        })
    except Exception as e:
        print("GET PROFILE ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

# 7. Change Password Endpoint
@app.route("/api/user/change-password", methods=["POST"])
def change_password():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not email or not current_password or not new_password:
        return jsonify({"success": False, "error": "All fields are required"}), 400

    try:
        # Fetch user
        res = supabase.table("web_users").select("*").eq("email", email).execute()
        if not res.data:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        user = res.data[0]
        db_password = user.get("password")

        # Verify current password
        if not check_password(current_password, db_password):
            return jsonify({"success": False, "error": "Incorrect current password"}), 401

        # Validate strength of new password
        pw_err = validate_password_strength(new_password)
        if pw_err:
            return jsonify({"success": False, "error": pw_err}), 400

        # Update password in DB (using SHA-256 for enhanced security)
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        supabase.table("web_users").update({"password": new_password_hash}).eq("email", email).execute()
        
        return jsonify({"success": True, "message": "Password updated successfully!"})
    except Exception as e:
        print("CHANGE PASSWORD ERROR:", e, flush=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5601))
    print(f"Running Site Portal Backend on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=True)
