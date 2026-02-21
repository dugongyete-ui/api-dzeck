# Api Dzeck Ai Web API

## Overview
Api Dzeck Ai Web API provides a self-hosted, free HTTP interface to various Large Language Model (LLM) providers like GPT-4, Claude, and Gemini, leveraging the g4f (GPT4Free) library without requiring API keys. The project aims to offer an accessible and versatile AI interaction platform with features like interactive chat, user-specific chat history, and administrative controls for settings and user management. It integrates a static frontend hosted on Firebase with a Python Flask backend.

## User Preferences
- Language: Bahasa Indonesia
- Design: Dark theme (#212121 bg, #00a896 teal accent) with ChatGPT-like interface using Space Grotesk + Inter fonts
- No chat limits: removed input truncation, history limits, and context windows
- No image generation features (removed - were blocked/non-functional)

## Recent Changes (2026-02-21)
- **Migrated to new Replit project (3rd time)**: All URLs updated from `project-p--cz8ihvdx.replit.app` to `https://project-p--keanun1.replit.app`.
- **Fixed Firebase redirect paths**: All redirects now preserve full path prefixes (e.g., `/api/chat` -> `/api/chat`, `/v1/chat/completions` -> `/v1/chat/completions`). Wildcard redirects include proper path prefixes (`/api/apikeys/:splat` instead of `/:splat`).
- **Provider name normalization**: "g4f", "gpt4free", "auto" now auto-mapped to "Auto" in validation, API key usage, and all chat endpoints. Prevents "provider not available" errors.
- **Base URL sync**: API keys with old Replit domains auto-corrected to current production URL. Firebase URL (`https://api-dzeck.web.app`) preserved when selected.
- **Firebase deployed**: Successfully deployed to https://api-dzeck.web.app with correct redirects.
- **AI tested**: GPT-4 via PollinationsAI working. Test key: `sk-dzeck-4dc878c22330aaf876ac6c37b26f81f9393124cedd71b184`
- **Virtual user**: dzeckyete / dzeckaiv1 (auto-created on startup)

## Changes (2026-02-20)
- **Fixed Firebase API redirect**: firebase.json now has `redirects` for `/api/chat`, `/v1/chat/completions`, `/stream`, `/health`, `/ping` that 307-redirect to Replit backend. Previously, all paths were caught by the `**` rewrite to index.html, causing API calls to Firebase URL to return HTML instead of JSON.
- **Updated deploy.sh**: Now automatically updates both `api-config.js` AND `firebase.json` redirects with the current Replit backend URL before deploying to Firebase.
- **Updated CORS**: Server CORS origins updated to include current Replit domain.
- **Per-key Base URL & Endpoint info**: Each API key now stores its own base_url (Replit or Firebase). When generating a key, user selects Base URL, Provider, and Model. Each key card displays its specific Base URL, Chat API endpoint, and OpenAI endpoint with copy buttons. Database `api_keys` table has `base_url` column.
- **JSON API responses**: POST requests with JSON content-type or Bearer auth now always return JSON (never HTML). Root `/` endpoint is hybrid: HTML for browsers, JSON for API clients.
- **Dedicated /api/chat endpoint**: Simple POST endpoint with Bearer token auth that always returns JSON.
- **API endpoints display**: Settings page shows base URL, Simple Chat and OpenAI Format endpoint URLs with copy buttons.
- **Copy buttons**: All API keys and endpoint URLs have explicit Copy buttons with clipboard API + fallback.
- **API key generation response**: Now includes `api_base_url` and `endpoints` object with full URLs.
- **Keep-alive mechanism**: Self-ping every 4 minutes to REPLIT_DEV_DOMAIN/ping to prevent server sleep during idle periods (1-5 hours).
- **API Key Generation**: Per-provider API key system with unified `sk-dzeck-` prefix. Unlimited keys stored in PostgreSQL api_keys table. Full CRUD via /api/apikeys endpoints.
- **OpenAI-compatible endpoint**: /v1/chat/completions endpoint supporting Bearer token auth with generated API keys. Compatible with any OpenAI SDK client.
- **Health check endpoints**: /health (JSON status) and /ping (pong text) for monitoring.
- **Fixed model selection**: Settings page now correctly populates models when changing providers. Initial load preserves saved model, provider change shows first available model.
- **API Keys UI**: Added API key management section to both Replit and Firebase settings pages with generate, copy, enable/disable, and delete functionality.

## Previous Changes (2026-02-18)
- **Removed ALL image generation features**: Deleted detectImageCommand(), handleImageGeneration() functions, /api/generate-image endpoint, /api/image-models endpoint, Image Generation tabs from test_api.html, image model catalog from models.html, generate_image() and get_image_models() from ai_service.py. Zero remaining references.
- **Fixed code block rendering consistency**: Both Replit and Firebase versions now use marked.js with highlight.js (github-dark theme), JetBrains Mono font, SVG copy button icons, and identical addCodeCopyButtons() implementation.
- **Migrated database to PostgreSQL**: Replaced SQLite with Replit PostgreSQL (Neon-backed). All tables now use PostgreSQL via psycopg2. DATABASE_URL env var for connection.
- **Removed all chat limits**: No input character limit, no message history truncation, no conversation context window cap.
- **Increased timeouts**: Default timeout raised to 300s. Stream queue timeout set to 600s. Content size limit raised to 100MB.

## System Architecture

### UI/UX Decisions
- **Dark Theme (ChatGPT-like)**: Modern dark UI with sidebar (#171717), main area (#212121), and AI messages (#2b2b2b). Teal accent (#00a896) for branding.
- **Interactive Chat Interface**: Features streaming responses, chat history, per-message copy button, and per-code-block copy buttons with SVG icons. Full-width message layout with avatars.
- **Login/Settings Pages**: Dedicated UI for user authentication and administrative/user-specific settings management.
- **Models Catalog**: HTML page displaying available AI providers and models.
- **Responsive Design**: Mobile-responsive across breakpoints (768px, 400px, 320px). Properly handles mobile keyboard with visualViewport API and safe-area-inset-bottom.
- **Branding**: Uses 'Space Grotesk' for branding, 'Inter' for body text, 'JetBrains Mono' for code.
- **Markdown Rendering**: AI responses include markdown rendering with highlight.js syntax highlighting for code blocks (with individual copy buttons), bold, italic, headers, lists, and links.
- **Image Upload**: Supports image/photo upload in chat with base64 encoding and preview.

### Technical Implementations
- **Core Framework**: Flask for the web server, handling all routes and endpoints.
- **AI Integration**: Uses `g4f` library for accessing diverse LLM providers.
- **Streaming Responses**: Implemented using Server-Sent Events (SSE) with a Queue-based real-time streaming mechanism. Queue timeout: 600s.
- **Authentication & Authorization**: Session-based authentication with permanent 7-day sessions (SameSite=None, Secure, HTTPOnly=True). Supports virtual users and admin credentials.
- **Database**: Replit PostgreSQL (Neon-backed) via psycopg2. Tables: `settings`, `personal`, `conversations`, `api_keys`. Connection via DATABASE_URL env var.
- **Configuration Management**: `config.py` handles provider and model configurations, including dynamic filtering of broken models.
- **CORS**: Enabled for Firebase domains to facilitate frontend-backend communication.
- **Chat History**: Persistent chat history per user, stored in PostgreSQL. NO truncation or limits on history size.
- **Keep-Alive**: Background thread pings /ping endpoint every 4 minutes to prevent Replit server sleep.
- **API Keys**: Provider-specific API keys with prefixes, stored in PostgreSQL. Supports generate, list, toggle, delete operations.
- **Deployment**: VM deployment for 24/7 operation. Environment variables control features like GUI, virtual users, and admin password.

### Feature Specifications
- **Free LLM Access**: Access to various LLM providers without API keys.
- **Interactive Chat**: Real-time streaming AI responses with no message limits.
- **User Management**: Admin and virtual user accounts with distinct access levels.
- **Settings Management**: Admin and user-specific settings for default providers and models.
- **API Key System**: Generate unlimited API keys per provider. Keys use provider-specific prefixes. OpenAI-compatible /v1/chat/completions endpoint.
- **API Testing**: Dedicated page for testing API endpoints with user tokens.
- **Provider Status**: Dynamic calculation and display of active AI models from configured providers, filtering out broken models.
- **Firebase Hosting Integration**: Static frontend hosted on Firebase, communicating with the Flask backend.
- **Dynamic API Configuration**: `api-config.js` on the frontend dynamically updates the backend API URL.
- **24/7 Uptime**: Keep-alive self-ping mechanism prevents server sleep during idle periods.

### API Endpoints
- `GET/POST /` - Hybrid: HTML for browsers, JSON for API POST requests
- `POST /api/chat` - Simple chat endpoint (Bearer token auth, always JSON)
- `POST /v1/chat/completions` - OpenAI-compatible chat endpoint (Bearer token auth)
- `POST /stream` - Stream AI chat responses (SSE)
- `GET /api/chat-settings` - Get current chat settings
- `GET/POST/PUT/DELETE /api/conversations` - Conversation CRUD
- `POST /api/auth/login` - User login
- `GET /api/auth/check` - Check session
- `POST /api/auth/logout` - Logout
- `GET /models` - List available models by provider
- `GET /health` - Health check (JSON status + timestamp)
- `GET /ping` - Simple ping (returns "pong")
- `GET /api/apikeys` - List API keys (includes api_base_url and endpoints)
- `POST /api/apikeys/generate` - Generate new API key (returns key + endpoints)
- `DELETE /api/apikeys/<id>` - Delete API key
- `POST /api/apikeys/<id>/toggle` - Enable/disable API key

## Important Files
- **TWO frontend versions that must be kept in sync**: `src/templates/` (Replit) and `public/` (Firebase)
- `src/FreeGPT4_Server.py` - Main Flask server
- `src/ai_service.py` - AI service layer (g4f integration)
- `src/database.py` - PostgreSQL database manager (settings, personal, conversations, api_keys tables)
- `src/config.py` - Provider/model configuration
- `src/auth.py` - Authentication utilities
- `src/templates/index.html` - Replit chat UI
- `public/index.html` - Firebase chat UI
- `public/settings.html` - Firebase settings UI (includes API key management)
- `public/api-config.js` - API URL configuration for Firebase frontend
- `src/templates/test_api.html` / `public/test-api.html` - API testing pages
- `src/templates/models.html` / `public/models.html` - Model catalog pages
- `test_models.py` - Script to test all AI providers/models

## External Dependencies
- **LLM Providers**: GPT-4, Claude, Gemini (accessed via g4f/GPT4Free). Providers include Auto, PollinationsAI, TeachAnything, Yqcloud, Perplexity.
- **Firebase Hosting**: For hosting the static frontend (api-dzeck.web.app).
- **Python Libraries**: Flask, flask-cors, g4f, Werkzeug, aiohttp, psycopg2-binary, gunicorn
- **Frontend Libraries**: marked.js (Markdown), highlight.js (syntax highlighting, github-dark theme)

## Key Technical Notes
- **Database**: Replit PostgreSQL (Neon-backed). Connected via DATABASE_URL env var. Contains 4 tables: `settings`, `personal`, `conversations`, `api_keys`.
- **message_history setting**: Controls whether AI uses conversation context in responses, NOT whether conversations are saved.
- **Server startup**: Uses `--enable-history` flag plus database setting `message_history=1` for full history support.
- **Markdown rendering**: Both versions use marked.js + highlight.js with JetBrains Mono font, github-dark theme, and per-code-block copy buttons with SVG icons.
- **Frontend consistency**: Both Replit (src/templates/) and Firebase (public/) versions must be kept in sync for features and styling.
- **API Key prefix**: All API keys use unified prefix `sk-dzeck-` followed by random hex.
- **Keep-alive**: Background thread in FreeGPT4_Server.py pings REPLIT_DEV_DOMAIN/ping every 240 seconds.
- **Deploy target**: VM (always-on) for 24/7 operation.
