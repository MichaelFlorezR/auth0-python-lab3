"""Python Flask WebApp Auth0 integration example"""
import json
import logging
from os import environ as env
from urllib.parse import quote_plus, urlencode
import requests
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, flash

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

def get_management_api_token():
    """Obtiene el token de acceso para la API de gestión de Auth0"""
    try:
        response = requests.post(
            f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
            json={
                "client_id": env.get("AUTH0_CLIENT_ID"),
                "client_secret": env.get("AUTH0_CLIENT_SECRET"),
                "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
                "grant_type": "client_credentials"
            }
        )
        return response.json().get('access_token')
    except Exception as e:
        logger.error(f"Error obteniendo token de gestión: {str(e)}")
        return None

def get_user_metadata(user_id):
    """Obtiene los metadatos del usuario desde Auth0"""
    token = get_management_api_token()
    if not token:
        return {}
    
    try:
        response = requests.get(
            f"https://{env.get('AUTH0_DOMAIN')}/api/v2/users/{user_id}",
            headers={'Authorization': f'Bearer {token}'}
        )
        return response.json().get('user_metadata', {})
    except Exception as e:
        logger.error(f"Error obteniendo metadatos: {str(e)}")
        return {}

def update_user_metadata(user_id, metadata):
    """Actualiza los metadatos del usuario en Auth0"""
    token = get_management_api_token()
    if not token:
        return False
    
    try:
        response = requests.patch(
            f"https://{env.get('AUTH0_DOMAIN')}/api/v2/users/{user_id}",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            json={'user_metadata': metadata}
        )
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error actualizando metadatos: {str(e)}")
        return False

@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("user"):
        return redirect("/login")
    
    user_id = session["user"]["userinfo"]["sub"]
    
    if request.method == "POST":
        metadata = {
            "doc_type": request.form.get("doc_type"),
            "doc_number": request.form.get("doc_number"),
            "address": request.form.get("address"),
            "phone": request.form.get("phone")
        }
        
        if update_user_metadata(user_id, metadata):
            flash("Datos actualizados correctamente", "success")
        else:
            flash("Error al actualizar los datos", "danger")
        return redirect("/profile")
    
    user_metadata = get_user_metadata(user_id)
    return render_template(
        "profile.html",
        session=session.get("user"),
        metadata=user_metadata
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))