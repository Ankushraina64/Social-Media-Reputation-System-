import os
import random
import string
from flask import Flask, request, jsonify, redirect, render_template, send_from_directory
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__, static_folder='static')
pending_posts = {}

# LinkedIn credentials
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/auth/linkedin/callback")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/linkedin/auth', methods=['POST'])
def linkedin_auth():
    content = request.json.get('content')
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    pending_posts[state] = content

    scopes = "openid profile w_member_social email"
    auth_url = (
        f"https://www.linkedin.com/oauth/v2/authorization"
        f"?response_type=code"
        f"&client_id={LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={scopes}"
        f"&state={state}"
    )

    return jsonify({'authUrl': auth_url})

@app.route('/auth/linkedin/callback')
def linkedin_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')

    if error:
        return f"""
            <script>
                window.opener.postMessage({{ error: '{error}', errorDescription: '{error_description}' }}, '*');
                window.close();
            </script>
        """

    if not code or not state:
        return "Missing code or state", 400

    content = pending_posts.pop(state, None)
    if not content:
        return "Invalid state or expired session", 400

    try:
        token_response = requests.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT_URI,
                'client_id': LINKEDIN_CLIENT_ID,
                'client_secret': LINKEDIN_CLIENT_SECRET
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ).json()

        access_token = token_response.get('access_token')
        if not access_token:
            raise Exception("No access token received")

        profile_response = requests.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={
                'Authorization': f'Bearer {access_token}',
                'X-Restli-Protocol-Version': '2.0.0'
            }
        ).json()

        user_urn = f"urn:li:person:{profile_response['sub']}"

        post_data = {
            "author": user_urn,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": content},
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
                'Authorization': f'Bearer {access_token}',
                'X-Restli-Protocol-Version': '2.0.0',
                'Content-Type': 'application/json'
            },
            json=post_data
        ).json()

        return f"""
            <script>
                window.opener.postMessage({{ success: true, postId: '{post_response.get('id', '')}' }}, '*');
                window.close();
            </script>
        """

    except Exception as e:
        return f"""
            <script>
                window.opener.postMessage({{ error: 'server_error', errorDescription: '{str(e)}' }}, '*');
                window.close();
            </script>
        """

if __name__ == '__main__':
    app.run(debug=True)
