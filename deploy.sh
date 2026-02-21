#!/bin/bash
DEPLOY_URL="https://project-p--keanun1.replit.app"

echo "Using deployment URL: $DEPLOY_URL"

echo "Updating API_BASE to: $DEPLOY_URL"
sed -i "s|API_BASE = '.*'|API_BASE = '${DEPLOY_URL}'|g" public/api-config.js

echo "Updating firebase.json redirects to: $DEPLOY_URL"
sed -i "s|\"destination\": \"https://[^\"]*/|\"destination\": \"${DEPLOY_URL}/|g" firebase.json

echo "Updating PRODUCTION_URL in server..."
sed -i "s|PRODUCTION_URL = \"https://[^\"]*\"|PRODUCTION_URL = \"${DEPLOY_URL}\"|g" src/FreeGPT4_Server.py

echo "Deploying to Firebase..."
firebase deploy --only hosting --project api-dzeck

echo ""
echo "Done! Firebase frontend: https://api-dzeck.web.app"
echo "Backend API: $DEPLOY_URL"
echo ""
echo "API Endpoints:"
echo "  Chat API: $DEPLOY_URL/api/chat"
echo "  OpenAI Format: $DEPLOY_URL/v1/chat/completions"
echo "  API Keys: $DEPLOY_URL/api/apikeys"
echo "  Health: $DEPLOY_URL/health"
echo ""
echo "Firebase redirects (also work):"
echo "  https://api-dzeck.web.app/api/chat -> $DEPLOY_URL/api/chat"
echo "  https://api-dzeck.web.app/v1/chat/completions -> $DEPLOY_URL/v1/chat/completions"
echo "  https://api-dzeck.web.app/api/apikeys -> $DEPLOY_URL/api/apikeys"
