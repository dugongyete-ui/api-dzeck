"""Api Dzeck Ai Web API - A Web API for GPT-4.

Repo: github.com/aledipa/FreeGPT4-WEB-API
By: Alessandro Di Pasquale
GPT4Free Credits: github.com/xtekky/gpt4free
"""

import os
import argparse
import threading
import getpass
import json
import uuid
from pathlib import Path
from typing import Optional

from flask import Flask, request, render_template, redirect, jsonify, session, Response
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from g4f.api import run_api

from flask_cors import CORS

from config import config
from database import db_manager
from auth import auth_service, require_auth, require_token_auth
from ai_service import ai_service
from utils.logging import logger, setup_logging
from utils.exceptions import (
    FreeGPTException, 
    ValidationError, 
    AuthenticationError,
    AIProviderError,
    FileUploadError
)
from utils.validation import (
    validate_file_upload,
    validate_port,
    validate_proxy_format,
    sanitize_input
)
from utils.helpers import (
    generate_uuid,
    load_json_file,
    save_json_file,
    parse_proxy_url,
    safe_filename
)

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = config.security.secret_key
app.config['UPLOAD_FOLDER'] = config.files.upload_folder
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7
app.config['SESSION_COOKIE_PATH'] = '/'

PRODUCTION_URL = "https://project-p--keanun1.replit.app"

def _get_production_base_url():
    deploy_url = os.environ.get('REPLIT_DEPLOYMENT_URL', '')
    if deploy_url:
        return deploy_url.rstrip('/')
    return PRODUCTION_URL

def _get_allowed_origins():
    origins = [
        "https://api-dzeck.web.app",
        "https://api-dzeck.firebaseapp.com",
        PRODUCTION_URL,
        "http://localhost:5000",
    ]
    dev_domain = os.environ.get('REPLIT_DEV_DOMAIN', '')
    if dev_domain:
        origins.append(f"https://{dev_domain}")
    replit_domains = os.environ.get('REPLIT_DOMAINS', '')
    if replit_domains:
        for d in replit_domains.split(','):
            d = d.strip()
            if d:
                url = f"https://{d}"
                if url not in origins:
                    origins.append(url)
    replit_deployment = os.environ.get('REPLIT_DEPLOYMENT_URL', '')
    if replit_deployment:
        if replit_deployment not in origins:
            origins.append(replit_deployment)
    slug_domain = os.environ.get('REPL_SLUG', '')
    owner = os.environ.get('REPL_OWNER', '')
    if slug_domain and owner:
        deploy_url = f"https://{slug_domain}--{owner}.replit.app"
        if deploy_url not in origins:
            origins.append(deploy_url)
    return origins

CORS(app, supports_credentials=True, origins=_get_allowed_origins())

# Set up logging
if os.getenv('LOG_LEVEL'):
    setup_logging(level=os.getenv('LOG_LEVEL', 'INFO'))

@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Permissions-Policy'] = 'clipboard-write=(self)'
    origin = request.headers.get('Origin', '')
    if origin in _get_allowed_origins():
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

logger.info("Api Dzeck Ai Web API - Starting server...")
logger.info("Repo: github.com/aledipa/FreeGPT4-WEB-API")
logger.info("By: Alessandro Di Pasquale")
logger.info("GPT4Free Credits: github.com/xtekky/gpt4free")

class ServerArgumentParser:
    """Parse and manage server arguments."""
    
    def __init__(self):
        self.parser = self._create_parser()
        self.args = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(description="Api Dzeck Ai Web API Server")
        
        parser.add_argument(
            "--remove-sources",
            action='store_true',
            help="Remove the sources from the response",
        )
        parser.add_argument(
            "--enable-gui",
            action='store_true',
            help="Use a graphical interface for settings",
        )
        parser.add_argument(
            "--private-mode",
            action='store_true',
            help="Use a private token to access the API",
        )
        parser.add_argument(
            "--enable-proxies",
            action='store_true',
            help="Use one or more proxies to avoid being blocked or banned",
        )
        parser.add_argument(
            "--enable-history",
            action='store_true',
            help="Enable the history of the messages",
        )
        parser.add_argument(
            "--password",
            action='store',
            help="Set or change the password for the settings page [mandatory in docker environment]",
        )
        parser.add_argument(
            "--cookie-file",
            action='store',
            type=str,
            help="Use a cookie file",
        )
        parser.add_argument(
            "--file-input",
            action='store_true',
            help="Add the file as input support",
        )
        parser.add_argument(
            "--port",
            action='store',
            type=int,
            help="Change the port (default: 5500)",
        )
        parser.add_argument(
            "--model",
            action='store',
            type=str,
            help="Change the model (default: gpt-4)",
        )
        parser.add_argument(
            "--provider",
            action='store',
            type=str,
            help="Change the provider (default: Auto)",
        )
        parser.add_argument(
            "--keyword",
            action='store',
            type=str,
            help="Add the keyword support",
        )
        parser.add_argument(
            "--system-prompt",
            action='store',
            type=str,
            help="Use a system prompt to 'customize' the answers",
        )
        parser.add_argument(
            "--enable-fast-api",
            action='store_true',
            help="Use the fast API standard (PORT 1336 - compatible with OpenAI integrations)",
        )
        parser.add_argument(
            "--enable-virtual-users",
            action='store_true',
            help="Gives the chance to create and manage new users",
        )
        
        return parser
    
    def parse_args(self):
        """Parse command line arguments with environment variable fallbacks."""
        self.args, _ = self.parser.parse_known_args()
        
        if not self.args.enable_gui and os.getenv("ENABLE_GUI", "").lower() in ("true", "1", "yes"):
            self.args.enable_gui = True
        if not self.args.enable_virtual_users and os.getenv("ENABLE_VIRTUAL_USERS", "").lower() in ("true", "1", "yes"):
            self.args.enable_virtual_users = True
        if not self.args.enable_history and os.getenv("ENABLE_HISTORY", "").lower() in ("true", "1", "yes"):
            self.args.enable_history = True
        if not self.args.password and os.getenv("ADMIN_PASSWORD"):
            self.args.password = os.getenv("ADMIN_PASSWORD")
        if not self.args.port and os.getenv("PORT"):
            self.args.port = int(os.getenv("PORT"))
        
        return self.args

class ServerManager:
    """Manage server configuration and state."""
    
    def __init__(self, args):
        self.args = args
        self.fast_api_thread = None
        self._setup_working_directory()
        self._merge_settings_with_args()
    
    def _setup_working_directory(self):
        """Set up working directory."""
        script_path = Path(__file__).resolve()
        os.chdir(script_path.parent)
    
    def _merge_settings_with_args(self):
        """Merge database settings with command line arguments."""
        try:
            settings = db_manager.get_settings()
            
            # Update args with database settings if not specified
            if not self.args.keyword:
                self.args.keyword = settings.get("keyword", config.api.default_keyword)
            
            if not self.args.file_input:
                self.args.file_input = settings.get("file_input", True)
            
            if not self.args.port:
                self.args.port = int(settings.get("port", config.server.port))
            
            if not self.args.provider:
                self.args.provider = settings.get("provider", config.api.default_provider)
            
            if not self.args.model:
                self.args.model = settings.get("model", config.api.default_model)
            
            if not self.args.cookie_file:
                self.args.cookie_file = settings.get("cookie_file", config.files.cookies_file)
            
            if not self.args.remove_sources:
                self.args.remove_sources = settings.get("remove_sources", True)
            
            if not self.args.system_prompt:
                self.args.system_prompt = settings.get("system_prompt", "")
            
            if not self.args.enable_history:
                self.args.enable_history = settings.get("message_history", False)
            
            if not self.args.enable_proxies:
                self.args.enable_proxies = settings.get("proxies", False)
            
            # Handle private mode token
            token = settings.get("token", "")
            if self.args.private_mode and not token:
                token = generate_uuid()
                db_manager.update_settings({"token": token})
            elif token:
                self.args.private_mode = True
            
            self.args.token = token
            
            # Handle fast API
            if self.args.enable_fast_api or settings.get("fast_api", False):
                self.start_fast_api()
            
            # Handle virtual users
            if not hasattr(self.args, 'enable_virtual_users'):
                self.args.enable_virtual_users = settings.get("virtual_users", False)
            
        except Exception as e:
            logger.error(f"Failed to merge settings: {e}")
            # Use defaults
            self.args.keyword = self.args.keyword or config.api.default_keyword
            self.args.port = self.args.port or config.server.port
            self.args.provider = self.args.provider or config.api.default_provider
            self.args.model = self.args.model or config.api.default_model
    
    def start_fast_api(self):
        """Start Fast API in background thread."""
        if self.fast_api_thread and self.fast_api_thread.is_alive():
            return
        
        logger.info(f"Starting Fast API on port {config.api.fast_api_port}")
        self.fast_api_thread = threading.Thread(target=run_api, name="fastapi", daemon=True)
        self.fast_api_thread.start()
    
    def setup_password(self):
        """Set up admin password if GUI is enabled."""
        if not self.args.enable_gui:
            logger.info("GUI disabled - no password setup required")
            return
        
        try:
            settings = db_manager.get_settings()
            current_password = settings.get("password", "")
            
            if self.args.password:
                # Password provided via command line
                password = self.args.password
                confirm_password = password
                logger.info("Using password provided via command line argument")
            elif not current_password:
                # No password set, prompt for new one
                logger.info("No admin password configured. Setting up new password...")
                password = getpass.getpass("Settings page password:\n > ")
                confirm_password = getpass.getpass("Confirm password:\n > ")
            else:
                # Password already set
                logger.info("Admin password already configured")
                return
            
            # Validate passwords
            if not password or not confirm_password:
                logger.error("Password cannot be empty")
                exit(1)
            
            if password != confirm_password:
                logger.error("Passwords don't match")
                exit(1)
            
            # Additional password strength validation
            if len(password) < config.security.password_min_length:
                logger.error(f"Password must be at least {config.security.password_min_length} characters long")
                exit(1)
            
            # Save password (will be hashed automatically in update_settings)
            db_manager.update_settings({"password": password})
            logger.info("Admin password configured successfully")
            
            # Verify the password was saved correctly
            if not db_manager.verify_admin_password(password):
                logger.error("Password verification failed after setup")
                exit(1)
            
            logger.info("Password verification successful")
            
        except Exception as e:
            logger.error(f"Failed to setup password: {e}")
            exit(1)
    
    def setup_virtual_users(self):
        """Ensure default virtual users exist on startup."""
        if not self.args.enable_virtual_users:
            return
        
        try:
            db_manager.update_settings({"virtual_users": True})
            
            existing_user = db_manager.get_user_by_username("dzeckyete")
            if not existing_user:
                token = db_manager.create_user("dzeckyete", "dzeckaiv1")
                logger.info(f"Default virtual user 'dzeckyete' created")
            else:
                logger.info("Virtual user 'dzeckyete' already exists")
        except Exception as e:
            logger.warning(f"Failed to setup virtual users: {e}")

# Routes and handlers
@app.errorhandler(404)
def handle_not_found(e):
    """Handle 404 errors."""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(FreeGPTException)
def handle_freegpt_exception(e):
    """Handle FreeGPT exceptions."""
    logger.error(f"FreeGPT error: {e}")
    return jsonify({"error": str(e)}), 400

@app.errorhandler(Exception)
def handle_general_exception(e):
    """Handle general exceptions."""
    from werkzeug.exceptions import NotFound
    
    # Don't log 404 errors as unexpected errors
    if isinstance(e, NotFound):
        return jsonify({"error": "Not found"}), 404
    
    logger.error(f"Unexpected error: {e}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

@app.route("/", methods=["GET", "POST"])
def index():
    """Main API endpoint for chat completion."""
    import asyncio
    
    async def _async_index():
        is_api_request = (
            request.method == "POST" and (
                'application/json' in (request.content_type or '') or
                request.headers.get("Authorization", "").startswith("Bearer ")
            )
        )
        try:
            settings = db_manager.get_settings()
            
            question = None
            provider_override = None
            model_override = None
            token = None

            if request.method == "POST":
                content_type = request.content_type or ''
                if 'application/json' in content_type:
                    data = request.get_json(silent=True) or {}
                    question = data.get("text") or data.get(server_manager.args.keyword)
                    provider_override = data.get("provider")
                    model_override = data.get("model")
                    token = data.get("token")
                elif 'multipart/form-data' in content_type:
                    if 'file' in request.files:
                        file = request.files['file']
                        is_valid, error_msg = validate_file_upload(file, config.files.allowed_extensions)
                        if not is_valid:
                            raise FileUploadError(error_msg)
                        question = file.read().decode('utf-8')
                    else:
                        question = request.form.get("text") or request.form.get(server_manager.args.keyword)
                        provider_override = request.form.get("provider")
                        model_override = request.form.get("model")
                        token = request.form.get("token")
                else:
                    question = request.form.get("text") or request.form.get(server_manager.args.keyword)
                    provider_override = request.form.get("provider")
                    model_override = request.form.get("model")
                    token = request.form.get("token")
            else:
                question = request.args.get(server_manager.args.keyword)
                provider_override = request.args.get("provider")
                model_override = request.args.get("model")
                token = request.args.get("token")

            if not question:
                if is_api_request:
                    return jsonify({"status": "error", "message": "No text/message provided. Send POST with {\"text\": \"...\", \"provider\": \"...\", \"model\": \"...\"}"}), 400
                return render_template(
                    "index.html",
                    keyword=server_manager.args.keyword,
                    gui_enabled=server_manager.args.enable_gui,
                    username=session.get('logged_in_user', '')
                )
            
            question = sanitize_input(question, 0)
            
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]
                key_data = db_manager.get_api_key_by_key(api_key)
                if key_data:
                    db_manager.increment_api_key_usage(api_key)
                    username = key_data.get("created_by", "admin")
                    if not provider_override:
                        provider_override = key_data.get("provider", "Auto")
                    if not model_override:
                        model_override = key_data.get("model", "")
                else:
                    if is_api_request:
                        return jsonify({"status": "error", "message": "Invalid API key"}), 401
            
            if not locals().get('username'):
                username = auth_service.verify_token_access(
                    token, 
                    server_manager.args.private_mode
                )
            
            if server_manager.args.private_mode and not username:
                if is_api_request:
                    return jsonify({"status": "error", "message": "Invalid token"}), 401
                return "<p id='response'>Invalid token</p>"
            
            if not username:
                username = "admin"
            
            response_text = await ai_service.generate_response(
                message=question,
                username=username,
                provider=provider_override,
                model=model_override,
                use_history=server_manager.args.enable_history,
                remove_sources=server_manager.args.remove_sources,
                use_proxies=server_manager.args.enable_proxies,
                cookie_file=server_manager.args.cookie_file
            )
            
            logger.info(f"Generated response for user '{username}' ({len(response_text)} chars)")
            
            if is_api_request:
                return jsonify({"status": "success", "data": response_text})
            return response_text
            
        except FreeGPTException as e:
            logger.error(f"API error: {e}")
            if is_api_request:
                return jsonify({"status": "error", "message": str(e)}), 500
            return f"<p id='response'>Error: {e}</p>"
        except Exception as e:
            logger.error(f"Unexpected API error: {e}", exc_info=True)
            if is_api_request:
                return jsonify({"status": "error", "message": "Internal server error"}), 500
            return "<p id='response'>Internal server error</p>"
    
    loop = None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_async_index())
    except Exception as e:
        logger.error(f"Async execution error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"AI API call failed: {e}"}), 500
    finally:
        if loop:
            loop.close()

@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Pure JSON API endpoint for chat. Always returns JSON, never HTML.
    
    Request body: {"text": "...", "provider": "...", "model": "..."}
    Auth: Bearer token in Authorization header
    Response: {"status": "success", "data": "AI response text"}
    """
    import asyncio
    
    data = request.get_json(silent=True) or {}
    question = data.get("text", "").strip()
    provider = data.get("provider", "")
    model = data.get("model", "")
    
    if not question:
        return jsonify({"status": "error", "message": "Field 'text' is required"}), 400
    
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"status": "error", "message": "Missing Authorization header. Use: Bearer <your-api-key>"}), 401
    
    api_key = auth_header[7:]
    key_data = db_manager.get_api_key_by_key(api_key)
    if not key_data:
        return jsonify({"status": "error", "message": "Invalid or inactive API key"}), 401
    
    db_manager.increment_api_key_usage(api_key)
    username = key_data.get("created_by", "admin")
    
    if not provider:
        provider = key_data.get("provider", "Auto")
    if not model:
        model = key_data.get("model", "") or None
    
    question = sanitize_input(question, 0)
    
    loop = None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response_text = loop.run_until_complete(
            ai_service.generate_response(
                message=question,
                username=username,
                provider=provider,
                model=model,
                use_history=False,
                remove_sources=True,
                use_proxies=False
            )
        )
        return jsonify({"status": "success", "data": response_text})
    except Exception as e:
        logger.error(f"API chat error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if loop:
            loop.close()

@app.route("/stream", methods=["GET", "POST"])
def stream_response():
    """Streaming endpoint for chat - returns Server-Sent Events with real-time chunks."""
    import asyncio
    import queue
    
    image_data = None
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        question = data.get("text") or data.get(server_manager.args.keyword)
        provider_override = data.get("provider")
        model_override = data.get("model")
        token = data.get("token")
        image_data = data.get("image")
    else:
        question = request.args.get(server_manager.args.keyword)
        provider_override = request.args.get("provider")
        model_override = request.args.get("model")
        token = request.args.get("token")

    if not question:
        return jsonify({"error": "No message provided"}), 400
    
    question = sanitize_input(question, 0)
    username = auth_service.verify_token_access(
        token, server_manager.args.private_mode
    )
    if server_manager.args.private_mode and not username:
        return jsonify({"error": "Invalid token"}), 401
    if not username:
        username = "admin"
    
    chunk_queue = queue.Queue()
    SENTINEL = object()
    
    def async_worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            async def run_stream():
                async for chunk in ai_service.generate_response_stream(
                    message=question,
                    username=username,
                    provider=provider_override,
                    model=model_override,
                    use_history=server_manager.args.enable_history,
                    remove_sources=server_manager.args.remove_sources,
                    use_proxies=server_manager.args.enable_proxies,
                    cookie_file=server_manager.args.cookie_file,
                    image_data=image_data
                ):
                    chunk_queue.put(chunk)
                chunk_queue.put(SENTINEL)
            loop.run_until_complete(run_stream())
        except Exception as e:
            logger.error(f"Stream error: {e}")
            chunk_queue.put(f"[ERROR] {e}")
            chunk_queue.put(SENTINEL)
        finally:
            loop.close()
    
    worker_thread = threading.Thread(target=async_worker, daemon=True)
    worker_thread.start()
    
    def generate():
        while True:
            try:
                item = chunk_queue.get(timeout=600)
                if item is SENTINEL:
                    yield "data: [DONE]\n\n"
                    break
                escaped = json.dumps(item)
                yield f"data: {escaped}\n\n"
            except queue.Empty:
                yield "data: [DONE]\n\n"
                break
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

def _get_chat_username(device_id=None):
    """Get username for chat history storage.
    Returns logged-in username or a guest session ID, combined with device ID.
    """
    username = session.get('logged_in_user')
    if not username:
        if 'guest_id' not in session:
            session['guest_id'] = str(uuid.uuid4())
        username = session['guest_id']
    if device_id:
        return f"{username}_{device_id}"
    return username

def _ensure_guest_user(username):
    """Ensure a guest user row exists in the personal table."""
    if username == 'admin':
        return
    existing = db_manager.get_user_by_username(username)
    if not existing:
        try:
            db_manager.create_user(username, username)
        except Exception:
            pass

@app.route("/api/chat-history", methods=["GET"])
def get_chat_history():
    """Load chat history for the current user and device."""
    device_id = request.args.get('device_id')
    username = _get_chat_username(device_id)
    try:
        raw = db_manager.get_chat_history(username)
        if raw:
            history = json.loads(raw)
            if isinstance(history, list):
                return jsonify({"history": history})
        return jsonify({"history": []})
    except Exception:
        return jsonify({"history": []})

@app.route("/api/chat-history", methods=["POST"])
def save_chat_history():
    """Save chat history for the current user and device."""
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id")
    username = _get_chat_username(device_id)
    _ensure_guest_user(username)
    try:
        history = data.get("history", [])
        if not isinstance(history, list):
            history = []
        
        db_manager.save_chat_history(username, json.dumps(history))
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"status": "error"}), 500

@app.route("/api/chat-history", methods=["DELETE"])
def delete_chat_history():
    """Clear chat history for the current user and device."""
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id")
    username = _get_chat_username(device_id)
    _ensure_guest_user(username)
    try:
        db_manager.save_chat_history(username, "")
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"status": "error"}), 500

@app.route("/api/conversations", methods=["GET"])
def get_conversations():
    """Get list of conversations for current user."""
    username = _get_chat_username()
    try:
        convos = db_manager.get_conversations(username)
        return jsonify({"conversations": convos})
    except Exception:
        return jsonify({"conversations": []})

@app.route("/api/conversations", methods=["POST"])
def create_conversation():
    """Create a new conversation."""
    username = _get_chat_username()
    _ensure_guest_user(username)
    data = request.get_json(silent=True) or {}
    title = data.get("title", "New Chat")
    try:
        convo = db_manager.create_conversation(username, title)
        return jsonify(convo)
    except Exception:
        return jsonify({"error": "Failed to create conversation"}), 500

@app.route("/api/conversations/<convo_id>", methods=["GET"])
def get_conversation(convo_id):
    """Get a specific conversation with messages."""
    try:
        convo = db_manager.get_conversation(convo_id)
        if not convo:
            return jsonify({"error": "Not found"}), 404
        return jsonify(convo)
    except Exception:
        return jsonify({"error": "Failed to get conversation"}), 500

@app.route("/api/conversations/<convo_id>", methods=["PUT"])
def update_conversation(convo_id):
    """Update conversation messages and/or title."""
    data = request.get_json(silent=True) or {}
    messages = data.get("messages")
    title = data.get("title")
    try:
        if messages is not None:
            db_manager.update_conversation(convo_id, json.dumps(messages), title)
        elif title is not None:
            convo = db_manager.get_conversation(convo_id)
            if convo:
                db_manager.update_conversation(convo_id, convo.get("messages", "[]"), title)
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"error": "Failed to update conversation"}), 500

@app.route("/api/conversations/<convo_id>", methods=["DELETE"])
def delete_conversation_route(convo_id):
    """Delete a specific conversation."""
    try:
        db_manager.delete_conversation(convo_id)
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"error": "Failed to delete conversation"}), 500

@app.route("/api/conversations/all", methods=["DELETE"])
def delete_all_conversations():
    """Delete all conversations for current user."""
    username = _get_chat_username()
    try:
        db_manager.delete_all_conversations(username)
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"error": "Failed to delete conversations"}), 500

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """JSON-based login for external frontends (Firebase)."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"success": False, "error": "Masukkan username dan password"}), 400
    
    is_admin = False
    if username == "admin":
        is_admin = auth_service.authenticate_admin(username, password)
        if not is_admin:
            return jsonify({"success": False, "error": "Kredensial admin salah"}), 401
    else:
        if not auth_service.authenticate_user(username, password):
            return jsonify({"success": False, "error": "Kredensial salah"}), 401
    
    session.permanent = True
    session['logged_in_user'] = username
    session['is_admin'] = is_admin
    return jsonify({"success": True, "username": username, "is_admin": is_admin})

@app.route("/api/auth/logout", methods=["GET", "POST"])
def api_logout():
    """JSON-based logout for external frontends."""
    session.clear()
    return jsonify({"success": True})

@app.route("/api/auth/check", methods=["GET"])
def api_auth_check():
    """Check current session status."""
    username = session.get('logged_in_user')
    if username:
        return jsonify({"logged_in": True, "username": username, "is_admin": session.get('is_admin', False)})
    return jsonify({"logged_in": False})

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if not server_manager.args.enable_gui:
        return "The GUI is disabled. Use the --enable-gui argument to enable it."
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            return render_template(
                "login.html",
                virtual_users=server_manager.args.enable_virtual_users,
                error="Please enter username and password"
            )
        
        is_admin = False
        if username == "admin":
            is_admin = auth_service.authenticate_admin(username, password)
            if not is_admin:
                return render_template(
                    "login.html",
                    virtual_users=server_manager.args.enable_virtual_users,
                    error="Invalid admin credentials"
                )
        else:
            if not auth_service.authenticate_user(username, password):
                return render_template(
                    "login.html",
                    virtual_users=server_manager.args.enable_virtual_users,
                    error="Invalid credentials"
                )
        
        session.permanent = True
        session['logged_in_user'] = username
        session['is_admin'] = is_admin
        
        next_page = request.args.get('next', '/settings')
        return redirect(next_page, code=302)
    
    return render_template(
        "login.html",
        virtual_users=server_manager.args.enable_virtual_users
    )

@app.route("/logout")
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect("/login", code=302)

def _build_settings_template_data(username, is_admin, success_message=None):
    """Build template data for settings page."""
    template_data = {
        "username": username,
        "virtual_users": server_manager.args.enable_virtual_users,
        "providers": config.available_providers,
        "generic_models": config.generic_models
    }
    
    if success_message:
        template_data["success_message"] = success_message
    
    if is_admin:
        template_data["data"] = db_manager.get_settings()
        proxies_path = Path(config.files.proxies_file)
        template_data["proxies"] = load_json_file(proxies_path, [])
        if server_manager.args.enable_virtual_users:
            template_data["users_data"] = db_manager.get_all_users()
    else:
        user_data = db_manager.get_user_by_username(username)
        if not user_data:
            return None
        template_data["data"] = user_data
    
    return template_data

@app.route("/settings", methods=["GET", "POST"])
def settings():
    """Settings page."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            return render_template(
                "login.html",
                virtual_users=server_manager.args.enable_virtual_users,
                error="Please enter username and password"
            )
        
        is_admin = False
        if username == "admin":
            is_admin = auth_service.authenticate_admin(username, password)
            if not is_admin:
                return render_template(
                    "login.html",
                    virtual_users=server_manager.args.enable_virtual_users,
                    error="Invalid admin credentials"
                )
        else:
            if not auth_service.authenticate_user(username, password):
                return render_template(
                    "login.html",
                    virtual_users=server_manager.args.enable_virtual_users,
                    error="Invalid credentials"
                )
        
        session.permanent = True
        session['logged_in_user'] = username
        session['is_admin'] = is_admin
    
    username = session.get('logged_in_user')
    is_admin = session.get('is_admin', False)
    
    if not username:
        return redirect("/login?next=/settings", code=302)
    
    try:
        template_data = _build_settings_template_data(username, is_admin)
        if template_data is None:
            session.clear()
            return render_template(
                "login.html",
                virtual_users=server_manager.args.enable_virtual_users,
                error="User not found"
            )
        
        return render_template("settings.html", **template_data)
        
    except Exception as e:
        logger.error(f"Settings page error: {e}")
        return render_template(
            "login.html",
            virtual_users=server_manager.args.enable_virtual_users,
            error="An error occurred"
        )

@app.route("/save", methods=["POST"])
def save_settings():
    """Save admin settings."""
    try:
        username = session.get('logged_in_user')
        is_admin = session.get('is_admin', False)
        
        if not username or not is_admin:
            return redirect("/login", code=302)
        
        settings_update = {}
        
        bool_fields = [
            "file_input", "remove_sources", "message_history", 
            "proxies", "fast_api", "virtual_users"
        ]
        for field in bool_fields:
            settings_update[field] = request.form.get(field) == "true"
        
        string_fields = ["port", "model", "keyword", "provider", "system_prompt"]
        for field in string_fields:
            value = request.form.get(field, "")
            if field == "port":
                is_valid, error_msg = validate_port(value)
                if not is_valid:
                    raise ValidationError(f"Invalid port: {error_msg}")
            settings_update[field] = sanitize_input(value)
        
        new_password = request.form.get("new_password", "")
        if new_password:
            confirm_password = request.form.get("confirm_password", "")
            if new_password != confirm_password:
                raise ValidationError("Passwords do not match")
            if len(new_password) < 8:
                raise ValidationError("Password must be at least 8 characters long")
            settings_update["password"] = new_password
        
        if request.form.get("private_mode") == "true":
            token = request.form.get("token", "")
            if not token:
                token = generate_uuid()
            settings_update["token"] = token
        else:
            settings_update["token"] = ""
        
        if 'cookie_file' in request.files:
            file = request.files['cookie_file']
            if file.filename:
                is_valid, error_msg = validate_file_upload(file, config.files.allowed_extensions)
                if not is_valid:
                    raise FileUploadError(error_msg)
                
                filename = safe_filename(file.filename)
                file_path = Path(app.config['UPLOAD_FOLDER']) / filename
                file.save(str(file_path))
                settings_update["cookie_file"] = str(file_path)
        
        if request.form.get("proxies") == "true":
            proxies = []
            i = 1
            while f"proxy_{i}" in request.form:
                proxy_url = request.form.get(f"proxy_{i}", "").strip()
                if proxy_url:
                    if not validate_proxy_format(proxy_url):
                        raise ValidationError(f"Invalid proxy format: {proxy_url}")
                    
                    proxy_dict = parse_proxy_url(proxy_url)
                    if proxy_dict:
                        proxies.append(proxy_dict)
                i += 1
            
            proxies_path = Path(config.files.proxies_file)
            save_json_file(proxies_path, proxies)
        
        if request.form.get("virtual_users") == "true":
            current_users = {user["token"]: user["username"] for user in db_manager.get_all_users()}
            form_users = {}
            
            form_passwords = {}
            for key, value in request.form.items():
                if key.startswith("username_"):
                    token = key.split("_", 1)[1]
                    form_users[token] = sanitize_input(value, 50)
                elif key.startswith("password_"):
                    token = key.split("_", 1)[1]
                    form_passwords[token] = value
            
            new_user_password = request.form.get("new_user_password", "")
            
            for token, uname in form_users.items():
                if token not in current_users and uname:
                    try:
                        pwd = form_passwords.get(token, "") or new_user_password or None
                        db_manager.create_user(uname, pwd if pwd else None)
                    except ValidationError as e:
                        logger.warning(f"Could not create user '{uname}': {e}")
            
            for token, uname in form_users.items():
                if token in current_users and uname != current_users[token]:
                    try:
                        user = db_manager.get_user_by_token(token)
                        if user:
                            db_manager.update_user_settings(user["username"], {"username": uname})
                    except Exception as e:
                        logger.warning(f"Could not update user: {e}")
            
            for token in current_users:
                if token not in form_users:
                    try:
                        user = db_manager.get_user_by_token(token)
                        if user:
                            db_manager.delete_user(user["username"])
                    except Exception as e:
                        logger.warning(f"Could not delete user: {e}")
        
        db_manager.update_settings(settings_update)
        
        if settings_update.get("fast_api") and not server_manager.fast_api_thread:
            server_manager.start_fast_api()
        
        logger.info("Settings saved successfully")
        
        template_data = _build_settings_template_data("admin", True, "Settings saved and applied successfully!")
        return render_template("settings.html", **template_data)
        
    except FreeGPTException as e:
        logger.error(f"Settings save error: {e}")
        template_data = _build_settings_template_data("admin", True)
        if template_data:
            template_data["error_message"] = str(e)
            return render_template("settings.html", **template_data)
        return redirect("/settings", code=302)
    except Exception as e:
        logger.error(f"Unexpected settings save error: {e}")
        template_data = _build_settings_template_data("admin", True)
        if template_data:
            template_data["error_message"] = "Failed to save settings"
            return render_template("settings.html", **template_data)
        return redirect("/settings", code=302)

@app.route("/save/<username>", methods=["POST"])
def save_user_settings(username):
    """Save user-specific settings."""
    try:
        logged_in = session.get('logged_in_user')
        if not logged_in or logged_in != username:
            return redirect("/login", code=302)
        
        # Process user settings update
        settings_update = {}
        
        # String settings
        string_fields = ["provider", "model", "system_prompt"]
        for field in string_fields:
            value = request.form.get(field, "")
            settings_update[field] = sanitize_input(value)
        
        # Boolean settings
        settings_update["message_history"] = request.form.get("message_history") == "true"
        
        # Handle password update
        new_password = request.form.get("new_password", "")
        if new_password:
            confirm_password = request.form.get("confirm_password", "")
            if new_password != confirm_password:
                raise ValidationError("Passwords do not match")
            if len(new_password) < 8:
                raise ValidationError("Password must be at least 8 characters long")
            settings_update["password"] = new_password
        
        db_manager.update_user_settings(username, settings_update)
        
        logger.info(f"User settings saved for '{username}'")
        
        user_data = db_manager.get_user_by_username(username)
        template_data = {
            "username": username,
            "virtual_users": server_manager.args.enable_virtual_users,
            "providers": config.available_providers,
            "generic_models": config.generic_models,
            "data": user_data,
            "success_message": "Settings saved successfully!"
        }
        return render_template("settings.html", **template_data)
        
    except FreeGPTException as e:
        logger.error(f"User settings save error: {e}")
        template_data = _build_settings_template_data(username, False)
        if template_data:
            template_data["error_message"] = str(e)
            return render_template("settings.html", **template_data)
        return redirect("/settings", code=302)
    except Exception as e:
        logger.error(f"Unexpected user settings save error: {e}")
        template_data = _build_settings_template_data(username, False)
        if template_data:
            template_data["error_message"] = "Failed to save settings"
            return render_template("settings.html", **template_data)
        return redirect("/settings", code=302)

@app.route("/models", methods=["GET"])
def get_models():
    """Get available models for a provider."""
    provider = request.args.get("provider")
    if not provider:
        settings = db_manager.get_settings()
        provider = settings.get("provider", "Auto")
    
    if request.headers.get("Accept", "").startswith("application/json") or request.args.get("format") == "json":
        return jsonify(ai_service.get_all_providers_with_models())
    
    settings = db_manager.get_settings()
    current_model = settings.get("model", config.api.default_model)
    current_provider = settings.get("provider", config.api.default_provider)
    all_providers = list(config.available_providers.keys())
    models_by_provider = ai_service.get_all_providers_with_models()
    
    return render_template(
        "models.html",
        current_model=current_model,
        current_provider=current_provider,
        all_providers=all_providers,
        models_by_provider=models_by_provider,
        gui_enabled=server_manager.args.enable_gui,
        model_capabilities=config.model_capabilities,
        category_info=config.category_info
    )

@app.route("/api/chat-settings", methods=["GET"])
def get_chat_settings():
    """Get current chat settings for the frontend."""
    username = session.get('logged_in_user', 'admin')
    if username and username != 'admin':
        user_data = db_manager.get_user_by_username(username)
        if user_data:
            model = user_data.get("model", config.api.default_model)
            provider = user_data.get("provider", config.api.default_provider)
        else:
            settings = db_manager.get_settings()
            model = settings.get("model", config.api.default_model)
            provider = settings.get("provider", config.api.default_provider)
    else:
        settings = db_manager.get_settings()
        model = settings.get("model", config.api.default_model)
        provider = settings.get("provider", config.api.default_provider)
    
    model_info = config.get_model_info(model)
    cat_info = config.category_info.get(model_info.get("category", "general"), {})
    
    return jsonify({
        "model": model,
        "provider": provider,
        "model_name": model_info.get("name", model),
        "category": model_info.get("category", "general"),
        "category_label": cat_info.get("label", "General"),
        "category_color": cat_info.get("color", "#034953"),
        "description": model_info.get("desc", ""),
        "tags": model_info.get("tags", [])
    })

@app.route("/api/model-info", methods=["GET"])
def get_model_info_api():
    """Get info about a specific model."""
    model_name = request.args.get("model", "")
    if not model_name:
        return jsonify({"error": "Model name required"}), 400
    model_info = config.get_model_info(model_name)
    cat_info = config.category_info.get(model_info.get("category", "general"), {})
    return jsonify({
        "model": model_name,
        "name": model_info.get("name", model_name),
        "category": model_info.get("category", "general"),
        "category_label": cat_info.get("label", "General"),
        "category_color": cat_info.get("color", "#034953"),
        "description": model_info.get("desc", ""),
        "tags": model_info.get("tags", [])
    })

@app.route("/api/settings/data", methods=["GET"])
def api_settings_data():
    """Get settings data for external frontend (Firebase)."""
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    settings = db_manager.get_settings()
    is_admin = (username == "admin")
    
    user_token = ""
    if is_admin:
        user_token = settings.get("token", "")
    else:
        user_data = db_manager.get_user_by_username(username)
        if user_data:
            user_token = user_data.get("token", "")
    
    providers_list = list(config.available_providers.keys())
    providers_models = ai_service.get_all_providers_with_models()
    
    result = {
        "username": username,
        "is_admin": is_admin,
        "token": user_token,
        "providers": providers_list,
        "providers_models": providers_models,
        "settings": {
            "provider": settings.get("provider", config.api.default_provider),
            "model": settings.get("model", config.api.default_model),
            "system_prompt": settings.get("system_prompt", ""),
        }
    }
    
    if is_admin:
        result["settings"].update({
            "file_input": settings.get("file_input", False),
            "private_mode": bool(settings.get("token", "")),
            "token": settings.get("token", ""),
            "proxies": settings.get("proxies", False),
            "fast_api": settings.get("fast_api", False),
            "port": settings.get("port", 5000),
            "keyword": settings.get("keyword", "text"),
            "remove_sources": settings.get("remove_sources", False),
            "message_history": settings.get("message_history", False),
            "virtual_users": settings.get("virtual_users", False),
        })
        users = db_manager.get_all_users()
        result["users"] = [{"username": u["username"], "token": u["token"]} for u in users]
    else:
        result["settings"]["token"] = user_token
    
    result["data"] = result["settings"]
    
    return jsonify(result)

@app.route("/api/settings/save", methods=["POST"])
def api_settings_save():
    """Save settings via JSON API for external frontend."""
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json(silent=True) or {}
    
    try:
        if username == "admin":
            settings_update = {}
            for key in ["provider", "model", "system_prompt", "keyword", "port"]:
                if key in data:
                    settings_update[key] = data[key]
            for key in ["file_input", "proxies", "fast_api", "remove_sources", "message_history", "virtual_users"]:
                if key in data:
                    settings_update[key] = data[key]
            if settings_update:
                db_manager.update_settings(settings_update)
            
            if "private_mode" in data:
                if data["private_mode"]:
                    current_settings = db_manager.get_settings()
                    if not current_settings.get("token"):
                        settings_update["token"] = generate_uuid()
                else:
                    settings_update["token"] = ""
                if settings_update:
                    db_manager.update_settings(settings_update)
            
            user_errors = []
            if "new_users" in data and isinstance(data["new_users"], list):
                for user_entry in data["new_users"]:
                    uname = user_entry.get("username", "").strip()
                    pwd = user_entry.get("password", "").strip()
                    if uname and pwd:
                        try:
                            existing = db_manager.get_user_by_username(uname)
                            if not existing:
                                db_manager.create_user(uname, pwd)
                                logger.info(f"User '{uname}' created via API")
                            else:
                                user_errors.append(f"User '{uname}' already exists")
                        except Exception as e:
                            logger.warning(f"Could not create user '{uname}': {e}")
                            user_errors.append(f"Could not create user '{uname}': {e}")
            
            if "delete_users" in data and isinstance(data["delete_users"], list):
                for uname in data["delete_users"]:
                    if uname and uname != "admin":
                        try:
                            db_manager.delete_user(uname)
                            logger.info(f"User '{uname}' deleted via API")
                        except Exception as e:
                            logger.warning(f"Could not delete user '{uname}': {e}")
                            user_errors.append(f"Could not delete user '{uname}': {e}")
            
            if user_errors:
                return jsonify({"success": True, "message": "Settings saved with warnings: " + "; ".join(user_errors)})
        else:
            user_data = db_manager.get_user_by_username(username)
            if user_data:
                personal = {}
                for key in ["provider", "model", "system_prompt"]:
                    if key in data:
                        personal[key] = data[key]
                if personal:
                    db_manager.update_user_settings(username, personal)
        
        return jsonify({"success": True, "message": "Settings saved successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/providers-data", methods=["GET"])
def api_providers_data():
    """Get all providers with models for external frontend."""
    providers_list = list(config.available_providers.keys())
    providers_models = ai_service.get_all_providers_with_models()
    
    username = session.get('logged_in_user')
    user_token = ""
    if username:
        if username == "admin":
            settings = db_manager.get_settings()
            user_token = settings.get("token", "")
        else:
            user_data = db_manager.get_user_by_username(username)
            if user_data:
                user_token = user_data.get("token", "")
    
    return jsonify({
        "providers": providers_list,
        "providers_models": providers_models,
        "username": username or "guest",
        "user_token": user_token
    })

@app.route("/api/users/create", methods=["POST"])
def api_create_user():
    """Create a new user via API (admin only)."""
    username = session.get('logged_in_user')
    is_admin = session.get('is_admin', False)
    
    if not username or not is_admin:
        return jsonify({"error": "Not authorized"}), 403
    
    data = request.get_json(silent=True) or {}
    new_username = data.get("username", "").strip()
    new_password = data.get("password", "").strip()
    
    if not new_username:
        return jsonify({"error": "Username tidak boleh kosong"}), 400
    
    try:
        existing = db_manager.get_user_by_username(new_username)
        if existing:
            return jsonify({"error": f"Username '{new_username}' sudah ada"}), 400
        
        pwd = new_password if new_password else None
        token = db_manager.create_user(new_username, pwd)
        logger.info(f"User '{new_username}' created via API")
        
        actual_password = new_password if new_password else new_username
        return jsonify({
            "success": True,
            "message": f"User '{new_username}' berhasil dibuat",
            "token": token,
            "username": new_username,
            "password": actual_password
        })
    except Exception as e:
        logger.warning(f"Could not create user '{new_username}': {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/api/users/delete", methods=["POST"])
def api_delete_user():
    """Delete a user via API (admin only)."""
    username = session.get('logged_in_user')
    is_admin = session.get('is_admin', False)
    
    if not username or not is_admin:
        return jsonify({"error": "Not authorized"}), 403
    
    data = request.get_json(silent=True) or {}
    target_username = data.get("username", "").strip()
    
    if not target_username:
        return jsonify({"error": "Username tidak boleh kosong"}), 400
    
    if target_username == "admin":
        return jsonify({"error": "Tidak bisa menghapus admin"}), 400
    
    try:
        db_manager.delete_user(target_username)
        logger.info(f"User '{target_username}' deleted via API")
        return jsonify({"success": True, "message": f"User '{target_username}' berhasil dihapus"})
    except Exception as e:
        logger.warning(f"Could not delete user '{target_username}': {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/generatetoken", methods=["GET", "POST"])
def generate_token():
    """Generate a new token."""
    return generate_uuid()

@app.route("/test-api", methods=["GET"])
def test_api_page():
    """API test page."""
    username = session.get('logged_in_user')
    if not username:
        return redirect("/login?next=/test-api", code=302)
    
    providers_with_models = ai_service.get_all_providers_with_models()
    base_url = _get_production_base_url()
    
    user_token = ""
    if username == "admin":
        settings = db_manager.get_settings()
        user_token = settings.get("token", "")
    else:
        user_data = db_manager.get_user_by_username(username)
        if user_data:
            user_token = user_data.get("token", "")
    
    return render_template(
        "test_api.html",
        providers=list(config.available_providers.keys()),
        providers_models=providers_with_models,
        base_url=base_url,
        username=username,
        user_token=user_token
    )

@app.route("/test-api/run", methods=["POST"])
def test_api_run():
    """Run API test for a specific provider - tests directly without fallback."""
    import asyncio
    
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    provider_name = data.get("provider", "Auto")
    test_message = data.get("message", "Hello, respond with one short sentence.")
    custom_model = data.get("model")
    
    loop = None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            ai_service.test_provider_directly(provider_name, test_message, custom_model)
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"provider": provider_name, "status": "error", "response": str(e)})
    finally:
        if loop:
            loop.close()

@app.route("/provider-status", methods=["GET"])
def provider_status():
    """Get provider health status."""
    from utils.provider_monitor import provider_monitor
    
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    return jsonify(provider_monitor.get_status_summary())

@app.route("/favicon.ico")
def favicon():
    """Serve favicon."""
    try:
        from flask import send_from_directory
        static_folder = app.static_folder or str(Path(__file__).parent / "static")
        return send_from_directory(
            str(Path(static_folder) / "img"), 
            "favicon(Nicoladipa).png",
            mimetype='image/png'
        )
    except:
        # Return empty response if favicon not found
        return "", 204

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "timestamp": __import__('time').time()})

@app.route("/ping", methods=["GET"])
def ping():
    return "pong", 200

@app.route("/api/apikeys", methods=["GET"])
def list_api_keys():
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    is_admin = session.get('is_admin', False)
    if is_admin:
        keys = db_manager.get_api_keys()
    else:
        keys = db_manager.get_api_keys(created_by=username)
    default_base_url = _get_production_base_url()
    safe_keys = []
    firebase_url = "https://api-dzeck.web.app"
    for k in keys:
        key_base_url = k.get("base_url", "") or default_base_url
        if "kirk.replit.dev" in key_base_url or "replit.dev" in key_base_url:
            key_base_url = default_base_url
        if key_base_url and "replit.app" in key_base_url and key_base_url != default_base_url:
            key_base_url = default_base_url
        if key_base_url == firebase_url:
            pass
        elif key_base_url != default_base_url and key_base_url != firebase_url:
            key_base_url = default_base_url
        safe_keys.append({
            "id": k["id"],
            "api_key": k["api_key"],
            "provider": k["provider"],
            "model": k.get("model", ""),
            "label": k.get("label", ""),
            "created_by": k["created_by"],
            "created_at": k["created_at"],
            "last_used_at": k.get("last_used_at"),
            "usage_count": k.get("usage_count", 0),
            "is_active": k.get("is_active", True),
            "base_url": key_base_url,
            "endpoints": {
                "chat_simple": f"{key_base_url}/api/chat",
                "chat_openai": f"{key_base_url}/v1/chat/completions",
            }
        })
    return jsonify({
        "keys": safe_keys,
        "api_base_url": default_base_url,
        "firebase_url": "https://api-dzeck.web.app",
        "endpoints": {
            "chat_simple": f"{default_base_url}/api/chat",
            "chat_openai": f"{default_base_url}/v1/chat/completions",
        }
    })

@app.route("/api/apikeys/generate", methods=["POST"])
def generate_api_key():
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(silent=True) or {}
    provider = data.get("provider", "Auto")
    model = data.get("model", "")
    label = data.get("label", "")
    base_url_choice = data.get("base_url", "")
    if not provider:
        return jsonify({"error": "Provider is required"}), 400
    default_base_url = _get_production_base_url()
    firebase_url = "https://api-dzeck.web.app"
    if base_url_choice == "firebase":
        selected_base_url = firebase_url
    elif base_url_choice and base_url_choice.startswith("http"):
        selected_base_url = base_url_choice.rstrip('/')
    else:
        selected_base_url = default_base_url
    try:
        result = db_manager.create_api_key(provider, model, label, username, selected_base_url)
        result["api_base_url"] = selected_base_url
        result["endpoints"] = {
            "chat_simple": f"{selected_base_url}/api/chat",
            "chat_openai": f"{selected_base_url}/v1/chat/completions",
            "root": f"{selected_base_url}/"
        }
        return jsonify({"success": True, "key": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/apikeys/<key_id>", methods=["DELETE"])
def delete_api_key(key_id):
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        db_manager.delete_api_key(key_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/apikeys/<key_id>/toggle", methods=["POST"])
def toggle_api_key(key_id):
    username = session.get('logged_in_user')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(silent=True) or {}
    is_active = data.get("is_active", True)
    try:
        db_manager.toggle_api_key(key_id, is_active)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/v1/chat/completions", methods=["POST"])
def openai_compatible_endpoint():
    import asyncio
    import time as _t
    data = request.get_json(silent=True) or {}
    auth_header = request.headers.get("Authorization", "")
    api_key = None
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]
    if not api_key:
        return jsonify({
            "error": {
                "message": "You didn't provide an API key. You need to provide your API key in an Authorization header using Bearer auth (i.e. Authorization: Bearer YOUR_KEY).",
                "type": "invalid_request_error",
                "param": None,
                "code": "missing_api_key"
            }
        }), 401
    key_data = db_manager.get_api_key_by_key(api_key)
    if not key_data:
        return jsonify({
            "error": {
                "message": "Incorrect API key provided. You can find your API key in the settings page.",
                "type": "invalid_request_error",
                "param": None,
                "code": "invalid_api_key"
            }
        }), 401
    if not key_data.get("is_active", True):
        return jsonify({
            "error": {
                "message": "This API key has been disabled. Please enable it in the settings page or generate a new one.",
                "type": "invalid_request_error",
                "param": None,
                "code": "api_key_disabled"
            }
        }), 403
    db_manager.increment_api_key_usage(api_key)
    messages = data.get("messages", [])
    model_requested = data.get("model") or key_data.get("model") or "auto"
    provider = key_data.get("provider", "Auto")
    if not messages:
        return jsonify({
            "error": {
                "message": "Messages are required. Please provide at least one message in the 'messages' array.",
                "type": "invalid_request_error",
                "param": "messages",
                "code": "missing_messages"
            }
        }), 400
    last_msg = messages[-1].get("content", "") if messages else ""
    prompt_tokens = sum(len(m.get("content", "").split()) for m in messages) * 2
    created_ts = int(_t.time())
    completion_id = f"chatcmpl-{generate_uuid().replace('-', '')[:29]}"
    loop = None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response_text = loop.run_until_complete(
            ai_service.generate_response(
                message=last_msg,
                username=key_data.get("created_by", "admin"),
                provider=provider,
                model=model_requested,
                use_history=False,
                remove_sources=True,
                use_proxies=False
            )
        )
        completion_tokens = len(response_text.split()) * 2
        total_tokens = prompt_tokens + completion_tokens
        return jsonify({
            "id": completion_id,
            "object": "chat.completion",
            "created": created_ts,
            "model": model_requested,
            "system_fingerprint": f"fp_{generate_uuid()[:12].replace('-', '')}",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_text
                },
                "logprobs": None,
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            },
            "service_tier": "default"
        })
    except Exception as e:
        return jsonify({
            "error": {
                "message": str(e),
                "type": "server_error",
                "param": None,
                "code": "internal_error"
            }
        }), 500
    finally:
        if loop:
            loop.close()

def _start_keep_alive():
    import time as _time
    import urllib.request
    def keep_alive_worker():
        deploy_url = os.environ.get('REPLIT_DEPLOYMENT_URL', '')
        if deploy_url:
            url = f"{deploy_url.rstrip('/')}/ping"
        else:
            replit_domain = os.environ.get('REPLIT_DEV_DOMAIN', '') or os.environ.get('REPLIT_DOMAINS', '').split(',')[0].strip()
            if replit_domain:
                url = f"https://{replit_domain}/ping"
            else:
                url = f"{PRODUCTION_URL}/ping"
        logger.info(f"Keep-alive started, pinging {url} every 4 minutes")
        while True:
            try:
                req = urllib.request.Request(url, method='GET')
                urllib.request.urlopen(req, timeout=10)
            except Exception:
                pass
            _time.sleep(240)
    t = threading.Thread(target=keep_alive_worker, daemon=True)
    t.start()

server_manager = None

def _initialize_server():
    global server_manager
    if server_manager is not None:
        return
    
    arg_parser = ServerArgumentParser()
    args = arg_parser.parse_args()
    
    server_manager = ServerManager(args)
    server_manager.setup_password()
    server_manager.setup_virtual_users()
    
    logger.info(f"Server configuration:")
    logger.info(f"  Port: {args.port}")
    logger.info(f"  Provider: {args.provider}")
    logger.info(f"  Model: {args.model}")
    logger.info(f"  Private mode: {args.private_mode}")
    logger.info(f"  GUI enabled: {args.enable_gui}")
    logger.info(f"  History enabled: {args.enable_history}")
    logger.info(f"  Proxies enabled: {args.enable_proxies}")
    logger.info(f"  Virtual users: {args.enable_virtual_users}")

_initialize_server()
_start_keep_alive()

def main():
    try:
        _initialize_server()
        
        app.run(
            host=config.server.host,
            port=server_manager.args.port,
            debug=config.server.debug
        )
        
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
    except Exception as e:
        logger.error(f"Server startup failed: {e}", exc_info=True)
        exit(1)

if __name__ == "__main__":
    main()