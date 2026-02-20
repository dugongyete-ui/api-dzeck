#!/bin/bash
REPLIT_URL="https://${REPLIT_DEV_DOMAIN}"

if [ -z "$REPLIT_DEV_DOMAIN" ]; then
    echo "Error: REPLIT_DEV_DOMAIN not set. Run this inside Replit."
    exit 1
fi

echo "Updating API_BASE to: $REPLIT_URL"

sed -i "s|API_BASE = '.*'|API_BASE = '${REPLIT_URL}'|g" public/api-config.js

echo "Updating firebase.json redirects to: $REPLIT_URL"
sed -i "s|\"destination\": \"https://[^\"]*\(/api/chat\)\"|\"destination\": \"${REPLIT_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/v1/chat/completions\)\"|\"destination\": \"${REPLIT_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/stream\)\"|\"destination\": \"${REPLIT_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/health\)\"|\"destination\": \"${REPLIT_URL}\1\"|g" firebase.json
sed -i "s|\"destination\": \"https://[^\"]*\(/ping\)\"|\"destination\": \"${REPLIT_URL}\1\"|g" firebase.json

echo "Deploying to Firebase..."
firebase deploy --only hosting --project api-dzeck

echo ""
echo "Done! Firebase frontend: https://api-dzeck.web.app"
echo "Backend API: $REPLIT_URL"
echo ""
echo "API Endpoints:"
echo "  Chat API: $REPLIT_URL/api/chat"
echo "  OpenAI Format: $REPLIT_URL/v1/chat/completions"
echo "  Health: $REPLIT_URL/health"
echo ""
echo "Firebase redirects (also work):"
echo "  https://api-dzeck.web.app/api/chat -> $REPLIT_URL/api/chat"
echo "  https://api-dzeck.web.app/v1/chat/completions -> $REPLIT_URL/v1/chat/completions"
