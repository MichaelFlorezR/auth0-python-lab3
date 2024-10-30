"""Python Flask WebApp Auth0 integration example with improved error handling"""
import json
import logging
from os import environ as env
from urllib.parse import quote_plus, urlencode
import requests
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, flash
from functools import wraps

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Auth0 OAuth configuration
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

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def get_management_api_token():
    """Obtiene el token de acceso para la API de gestión de Auth0"""
    try:
        payload = {
            "client_id": env.get("AUTH0_CLIENT_ID"),
            "client_secret": env.get("AUTH0_CLIENT_SECRET"),
            "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
            "grant_type": "client_credentials",
            "scope": "read:users update:users"  # Explicitly request required scopes
        }
        
        response = requests.post(
            f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
            json=payload
        )
        
        if response.status_code != 200:
            logger.error(f"Error getting management token: {response.status_code} - {response.text}")
            return None
            
        token_data = response.json()
        logger.debug(f"Management API Token Response: {json.dumps(token_data, indent=2)}")
        return token_data.get('access_token')
        
    except Exception as e:
        logger.error(f"Error obteniendo token de gestión: {str(e)}")
        return None

def get_user_metadata(user_id):
    """Obtiene los metadatos del usuario desde Auth0"""
    token = get_management_api_token()
    if not token:
        logger.error("No se pudo obtener el token de gestión")
        return {}
    
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # URL encode the user_id properly
        encoded_user_id = quote_plus(user_id)
        url = f"https://{env.get('AUTH0_DOMAIN')}/api/v2/users/{encoded_user_id}"
        
        logger.debug(f"Making request to: {url}")
        logger.debug(f"Headers: {headers}")
        
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"Error getting user metadata: {response.status_code} - {response.text}")
            return {}
            
        user_data = response.json()
        logger.debug(f"User Data Response: {json.dumps(user_data, indent=2)}")
        return user_data.get('user_metadata', {})
        
    except Exception as e:
        logger.error(f"Error obteniendo metadatos: {str(e)}")
        return {}

def update_user_metadata(user_id, metadata):
    """Actualiza los metadatos del usuario en Auth0"""
    token = get_management_api_token()
    if not token:
        logger.error("No se pudo obtener el token de gestión")
        return False
    
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # URL encode the user_id properly
        encoded_user_id = quote_plus(user_id)
        url = f"https://{env.get('AUTH0_DOMAIN')}/api/v2/users/{encoded_user_id}"
        
        payload = {
            'user_metadata': metadata
        }
        
        logger.debug(f"Making request to: {url}")
        logger.debug(f"Headers: {headers}")
        logger.debug(f"Payload: {payload}")
        
        response = requests.patch(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"Error updating user metadata: {response.status_code} - {response.text}")
            return False
            
        return True
        
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
@requires_auth
def profile():
    user_id = session["user"]["userinfo"]["sub"]
    
    if request.method == "POST":
        try:
            metadata = {
                "doc_type": request.form.get("doc_type"),
                "doc_number": request.form.get("doc_number"),
                "address": request.form.get("address"),
                "phone": request.form.get("phone")
            }
            
            if not all(metadata.values()):
                flash("Todos los campos son obligatorios", "danger")
                return redirect("/profile")
            
            if update_user_metadata(user_id, metadata):
                flash("Datos actualizados correctamente", "success")
            else:
                flash("Error al actualizar los datos. Por favor, intente nuevamente.", "danger")
        except Exception as e:
            logger.error(f"Error en el procesamiento del perfil: {str(e)}")
            flash("Error inesperado. Por favor, intente nuevamente.", "danger")
        
        return redirect("/profile")
    
    try:
        user_metadata = get_user_metadata(user_id)
        return render_template(
            "profile.html",
            session=session.get("user"),
            metadata=user_metadata
        )
    except Exception as e:
        logger.error(f"Error al cargar el perfil: {str(e)}")
        flash("Error al cargar los datos del perfil", "danger")
        return redirect("/")

@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        token = oauth.auth0.authorize_access_token()
        session["user"] = token
        flash("Inicio de sesión exitoso", "success")
        return redirect("/")
    except Exception as e:
        logger.error(f"Error en el callback: {str(e)}")
        flash("Error durante el inicio de sesión", "danger")
        return redirect("/login")

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