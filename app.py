import os
from flask import Flask, url_for, session
from authlib.common.security import generate_token
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)   
app.secret_key = os.urandom(12)

oauth = OAuth(app)

GOOGLE_CLIENT_ID = os.environ.get('CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# If user is not logged in, shows login button
# else shows the user email
@app.route('/')
def index():
  if not session.get('user'):
    return '<a href="/google">Login</a>'

  return f"Hello, {session.get('user')}"

# This constructs a redirect URI to the Google oauth server 
# and redirects the user there
@app.route('/google/')
def google():

  # Redirect to google_auth function
  redirect_uri = url_for('google_auth', _external=True)
  print(redirect_uri)
  session['nonce'] = generate_token()
  return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

# The Google auth server redirects the user back to this route
# This route parses out the response to try and auth the user
@app.route('/google/auth')  
def google_auth():
  token = oauth.google.authorize_access_token()
  user = oauth.google.parse_id_token(token, nonce=session['nonce'])
  if user.get('nonce') != session.get('nonce'):
    return 'Invalid nonce', 400
  session['user'] = user['email']
  return 'Google auth'

if __name__ == '__main__':
    app.run(port=3000, debug=True)