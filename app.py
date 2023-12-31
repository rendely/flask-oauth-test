import os
import requests
from flask import Flask, url_for, session, redirect
from authlib.common.security import generate_token
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)   
app.secret_key = os.environ.get('SECRET_KEY')

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
        'scope': 'openid profile email'
    }
)


# If user is not logged in, shows login button
# else shows the user email
@app.route('/')
def index():
  if not session.get('user'):
    return '<a href="/google">Login</a>'
  response  = f"Hello there, {session.get('user')}. <a href='/clear'>Logout</a> or  <a href='/revoke'>Revoke</a>"
  response += f"<br></br><img src='{session.get('picture')}' />"
  return response, 200


# This constructs a redirect URI to the Google oauth server 
# and redirects the user there
@app.route('/google/')
def google():
  redirect_uri = url_for('google_auth', _external=True)
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
  # session['picture'] = user['picture']
  session['token'] = token['access_token']
  return redirect(url_for('index'))


# Log out
@app.route('/clear')
def clear():
  session['user'] = None
  session['nonce'] = None
  return redirect(url_for('index'))

# Revoke the Oauth access
# Useful for resetting the state
@app.route('/revoke')
def revoke():
  token = session['token']

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return redirect(url_for('clear'))
  else:
    return('An error occurred.')

if __name__ == '__main__':
    app.run(port=3000, debug=True)