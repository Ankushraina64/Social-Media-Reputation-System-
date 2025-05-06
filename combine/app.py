from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import subprocess
import os
from dotenv import load_dotenv
import requests
import random
import string
import secrets
import base64
import hashlib
from flask_session import Session

load_dotenv()

app = Flask(__name__)
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

# Store user credentials (in a real app, use a secure database)
user_credentials = {}

# Helper function for PKCE
def generate_code_verifier():
    token = secrets.token_urlsafe(100)
    return token[:128]

def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('ascii')
    return code_challenge.replace('=', '')

@app.route('/')
def index():
    linkedin_linked = 'linkedin' in user_credentials
    twitter_linked = 'twitter' in user_credentials
    return render_template('index.html', linkedin_linked=linkedin_linked, twitter_linked=twitter_linked)

@app.route('/link_accounts', methods=['GET', 'POST'])
def link_accounts():
    linkedin_linked = 'linkedin' in user_credentials
    twitter_linked = 'twitter' in user_credentials
    linkedin_error = None
    twitter_error = None

    if request.method == 'POST':
        if 'linkedin_link' in request.form:
            # Generate state and store in session
            state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            session['linkedin_state'] = state
            
            # LinkedIn OAuth URL
            scopes = "openid profile w_member_social email"
            auth_url = (
                f"https://www.linkedin.com/oauth/v2/authorization"
                f"?response_type=code"
                f"&client_id={LINKEDIN_CLIENT_ID}"
                f"&redirect_uri={LINKEDIN_REDIRECT_URI}"
                f"&scope={scopes}"
                f"&state={state}"
            )
            return redirect(auth_url)
            
        elif 'twitter_link' in request.form:
            # Generate PKCE code verifier and challenge
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier)
            
            # Store in session
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
            return redirect(auth_url)

    return render_template('link_accounts.html', 
                         linkedin_linked=linkedin_linked, 
                         twitter_linked=twitter_linked,
                         linkedin_error=linkedin_error,
                         twitter_error=twitter_error)

@app.route('/auth/linkedin/callback')
def linkedin_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')

    if error:
        return redirect(url_for('link_accounts', error=f"LinkedIn error: {error_description}"))

    if not code or not state or state != session.get('linkedin_state'):
        return redirect(url_for('link_accounts', error="Invalid state or missing code"))

    try:
        # Exchange code for access token
        token_response = requests.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': LINKEDIN_REDIRECT_URI,
                'client_id': LINKEDIN_CLIENT_ID,
                'client_secret': LINKEDIN_CLIENT_SECRET
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ).json()

        access_token = token_response.get('access_token')
        if not access_token:
            raise Exception("No access token received")

        # Store the access token
        user_credentials['linkedin'] = {'access_token': access_token}
        return redirect(url_for('link_accounts', success="LinkedIn account linked successfully!"))

    except Exception as e:
        return redirect(url_for('link_accounts', error=f"LinkedIn error: {str(e)}"))

@app.route('/auth/twitter/callback')
def twitter_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')

    if error:
        return redirect(url_for('link_accounts', error=f"Twitter error: {error_description}"))

    if not code or not state or state != session.get('twitter_state'):
        return redirect(url_for('link_accounts', error="Invalid state or missing code"))

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

        # Store the access token
        user_credentials['twitter'] = {'access_token': access_token}
        return redirect(url_for('link_accounts', success="Twitter account linked successfully!"))

    except Exception as e:
        return redirect(url_for('link_accounts', error=f"Twitter error: {str(e)}"))

@app.route('/post', methods=['GET', 'POST'])
def post():
    if request.method == 'POST':
        post_content = request.form['post_content']
        linkedin = 'linkedin' in request.form
        twitter = 'twitter' in request.form
        posting_errors = {}

        if linkedin:
            if 'linkedin' in user_credentials:
                try:
                    # Get user profile
                    profile_response = requests.get(
                        "https://api.linkedin.com/v2/userinfo",
                        headers={
                            'Authorization': f'Bearer {user_credentials["linkedin"]["access_token"]}',
                            'X-Restli-Protocol-Version': '2.0.0'
                        }
                    ).json()

                    user_urn = f"urn:li:person:{profile_response['sub']}"

                    # Post to LinkedIn
                    post_data = {
                        "author": user_urn,
                        "lifecycleState": "PUBLISHED",
                        "specificContent": {
                            "com.linkedin.ugc.ShareContent": {
                                "shareCommentary": {"text": post_content},
                                "shareMediaCategory": "NONE"
                            }
                        },
                        "visibility": {
                            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                        }
                    }

                    post_response = requests.post(
                        "https://api.linkedin.com/v2/ugcPosts",
                        headers={
                            'Authorization': f'Bearer {user_credentials["linkedin"]["access_token"]}',
                            'X-Restli-Protocol-Version': '2.0.0',
                            'Content-Type': 'application/json'
                        },
                        json=post_data
                    )
                    post_response.raise_for_status()
                except Exception as e:
                    posting_errors['linkedin'] = f"Error posting to LinkedIn: {str(e)}"
            else:
                posting_errors['linkedin'] = "LinkedIn account not linked"

        if twitter:
            if 'twitter' in user_credentials:
                try:
                    # Post to Twitter
                    tweet_url = "https://api.twitter.com/2/tweets"
                    tweet_data = {
                        "text": post_content
                    }

                    headers = {
                        'Authorization': f'Bearer {user_credentials["twitter"]["access_token"]}',
                        'Content-Type': 'application/json'
                    }

                    tweet_response = requests.post(tweet_url, json=tweet_data, headers=headers)
                    tweet_response.raise_for_status()
                except Exception as e:
                    posting_errors['twitter'] = f"Error posting to Twitter: {str(e)}"
            else:
                posting_errors['twitter'] = "Twitter account not linked"

        return render_template('post_status.html', 
                             post_content=post_content, 
                             posting_errors=posting_errors,
                             linkedin_success=linkedin and 'linkedin' not in posting_errors,
                             twitter_success=twitter and 'twitter' not in posting_errors)

    return render_template('post.html', 
                         linkedin_linked='linkedin' in user_credentials,
                         twitter_linked='twitter' in user_credentials)

if __name__ == '__main__':
    app.run(debug=True)