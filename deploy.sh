#!/bin/bash
DEPLOY_URL="https://api-dzeck--mio7wxa.replit.app"

echo "Using deployment URL: $DEPLOY_URL"

echo "Updating API_BASE to: $DEPLOY_URL"
sed -i "s|API_BASE = '.*'|API_BASE = '${DEPLOY_URL}'|g" public/api-config.js

echo "Updating firebase.json redirects to: $DEPLOY_URL"
sed -i "s|\"destination\": \"https://[^\"]*\(/api/chat\)\"|\"destination\": \"${DEPLOY_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/v1/chat/completions\)\"|\"destination\": \"${DEPLOY_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/stream\)\"|\"destination\": \"${DEPLOY_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/health\)\"|\"destination\": \"${DEPLOY_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/ping\)\"|\"destination\": \"${DEPLOY_URL}\1\"|g" firebase.json

echo "Deploying to Firebase..."
firebase deploy --only hosting --project api-dzeck

echo ""
echo "Done! Firebase frontend: https://api-dzeck.web.app"
echo "Backend API: $DEPLOY_URL"
echo ""
echo "API Endpoints:"
echo "  Chat API: $DEPLOY_URL/api/chat"
echo "  OpenAI Format: $DEPLOY_URL/v1/chat/completions"
echo "  Health: $DEPLOY_URL/health"
echo ""
echo "Firebase redirects (also work):"
echo "  https://api-dzeck.web.app/api/chat -> $DEPLOY_URL/api/chat"
echo "  https://api-dzeck.web.app/v1/chat/completions -> $DEPLOY_URL/v1/chat/completions"
