var API_BASE = 'https://api-dzeck--mio7wxa.replit.app';
var PUBLIC_URL = 'https://api-dzeck.web.app';

(function() {
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
        if (scripts[i].src && scripts[i].src.indexOf('api-config.js') !== -1) {
            var configUrl = scripts[i].getAttribute('data-api-base');
            if (configUrl) {
                API_BASE = configUrl;
                return;
            }
        }
    }

    var saved = localStorage.getItem('api_dzeck_backend_url');
    if (saved) {
        API_BASE = saved;
        return;
    }

    API_BASE = 'https://api-dzeck--mio7wxa.replit.app';
})();

function setBackendUrl(url) {
    url = url.replace(/\/+$/, '');
    API_BASE = url;
    localStorage.setItem('api_dzeck_backend_url', url);
}

function getBackendUrl() {
    return API_BASE;
}

function apiFetch(path, options) {
    options = options || {};
    options.credentials = 'include';
    options.mode = 'cors';
    if (!options.headers) options.headers = {};
    if (!options.headers['Content-Type'] && options.method && options.method !== 'GET') {
        options.headers['Content-Type'] = 'application/json';
    }
    return fetch(API_BASE + path, options)
        .then(function(response) {
            return response;
        })
        .catch(function(error) {
            console.error('API request failed:', path, error);
            throw error;
        });
}
