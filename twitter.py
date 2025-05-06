import os
import random
import string
import secrets
from flask import Flask, request, jsonify, redirect, render_template, session
from dotenv import load_dotenv
import requests
import base64
import hashlib
from flask_session import Session

load_dotenv()

app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret_key")

# Configure session
app.config['SESSION_COOKIE_SAMESITE'] = None
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# LinkedIn credentials
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:5000/auth/linkedin/callback")

# Twitter credentials
TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
TWITTER_REDIRECT_URI = os.getenv("TWITTER_REDIRECT_URI", "http://127.0.0.1:5000/auth/twitter/callback")

# Helper function for PKCE
def generate_code_verifier():
    # Generate a random code verifier for PKCE
    token = secrets.token_urlsafe(100)
    return token[:128]

def generate_code_challenge(code_verifier):
    # Generate code challenge for PKCE
    code_challenge = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('ascii')
    return code_challenge.replace('=', '')

@app.route('/')
def home():
    return render_template('index.html')

# LinkedIn routes (existing code)
@app.route('/api/linkedin/auth', methods=['POST'])
def linkedin_auth():
    content = request.json.get('content')
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    session['linkedin_post_content'] = content
    scopes = "openid profile w_member_social email"
    auth_url = f"https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id={LINKEDIN_CLIENT_ID}&redirect_uri={LINKEDIN_REDIRECT_URI}&scope={scopes}&state={state}"
    return jsonify({'authUrl': auth_url})

# Twitter routes
@app.route('/api/twitter/auth', methods=['POST'])
def twitter_auth():
    content = request.form.get('content') or request.json.get('content')
    if not content:
        return jsonify({'error': 'Content is required'}), 400
    
    # Generate PKCE code verifier and challenge
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store in session
    session['twitter_post_content'] = content
    session['twitter_code_verifier'] = code_verifier
    
    # Generate state
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    session['twitter_state'] = state
    
    # Twitter OAuth 2.0 URL with PKCE
    scopes = ["tweet.read", "tweet.write", "users.read", "offline.access"]
    auth_url = (
        f"https://twitter.com/i/oauth2/authorize?"
        f"response_type=code&"
        f"client_id={TWITTER_CLIENT_ID}&"
        f"redirect_uri={TWITTER_REDIRECT_URI}&"
        f"scope={'%20'.join(scopes)}&"
        f"state={state}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )
    
    print('Setting twitter_state:', state)
    print('Session after setting:', dict(session))
    
    return redirect(auth_url)

@app.route('/auth/twitter/callback')
def twitter_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')

    # Debug: Print session and callback state
    print('Session twitter_state:', session.get('twitter_state'))
    print('Callback state:', state)
    print('Session keys:', list(session.keys()))

    # Verify state
    if state != session.get('twitter_state'):
        print('State mismatch!')
        return f"""
            <script>
                if (window.opener) {{
                    window.opener.postMessage({{ error: 'invalid_state', errorDescription: 'Invalid state parameter' }}, '*');
                    window.close();
                }} else {{
                    document.body.innerHTML = '<h2 style="color:red;">Error: Invalid state parameter</h2><p>Session may have expired or cookies are blocked.</p>';
                }}
            </script>
        """

    if error:
        return f"""
            <script>
                window.opener.postMessage({{ error: '{error}', errorDescription: '{error_description}' }}, '*');
                window.close();
            </script>
        """

    if not code:
        return """
            <script>
                window.opener.postMessage({ error: 'missing_code', errorDescription: 'Missing authorization code' }, '*');
                window.close();
            </script>
        """

    try:
        # Exchange code for access token
        token_url = "https://api.twitter.com/2/oauth2/token"
        data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': TWITTER_CLIENT_ID,
            'redirect_uri': TWITTER_REDIRECT_URI,
            'code_verifier': session['twitter_code_verifier']
        }

        # Basic Auth header
        auth_string = f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}"
        auth_bytes = auth_string.encode('ascii')
        base64_auth = base64.b64encode(auth_bytes).decode('ascii')

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {base64_auth}'
        }

        response = requests.post(token_url, data=data, headers=headers)
        response.raise_for_status()
        token_data = response.json()

        access_token = token_data.get('access_token')
        if not access_token:
            raise Exception("No access token received from Twitter")

        # Get the stored post content
        content = session.get('twitter_post_content')
        if not content:
            raise Exception("No post content found in session")

        # Post the tweet
        tweet_url = "https://api.twitter.com/2/tweets"
        tweet_data = {
            "text": content
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        tweet_response = requests.post(tweet_url, json=tweet_data, headers=headers)
        tweet_response.raise_for_status()
        tweet_data = tweet_response.json()

        return f"""
            <script>
                if (window.opener) {{
                    window.opener.postMessage({{ success: true, tweetId: '{tweet_data['data']['id']}' }}, '*');
                    window.close();
                }} else {{
                    document.body.innerHTML = '<h2>Tweet posted successfully! (ID: {tweet_data['data']['id']})</h2><p>You can close this window.</p>';
                }}
            </script>
        """

    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        if hasattr(e, 'response') and e.response:
            try:
                error_details = e.response.json()
                error_msg = error_details.get('detail', str(e))
            except:
                error_msg = e.response.text
        return f"""
            <script>
                window.opener.postMessage({{ error: 'twitter_error', errorDescription: '{error_msg}' }}, '*');
                window.close();
            </script>
        """

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')