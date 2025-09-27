from __future__ import print_function
import base64
from email.mime.text import MIMEText
import os
import pickle
from flask import Flask, request, jsonify
from flask_cors import CORS

from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Configuración Flask
app = Flask(__name__)
CORS(app)  # Permite requests desde otros microservicios

# Alcance de la API (permite enviar correos)
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def authenticate_gmail():
    creds = None
    # Cargar credenciales si ya existen
    if os.path.exists('confidential/token.pickle'):
        with open('confidential/token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # Si no hay credenciales válidas, iniciar flujo OAuth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('confidential/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('confidential/token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return creds

def create_message(sender, to, subject, html_content):
    message = MIMEText(html_content, "html")
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': raw_message.decode()}

def send_message(service, user_id, message):
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        return {"success": True, "message_id": sent_message['id']}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Endpoint para enviar notificaciones de login
@app.route('/notifications/login', methods=['POST'])
def send_login_notification():
    try:
        # Obtener datos del request
        data = request.get_json()
        
        if not data or 'email' not in data:
            return jsonify({"error": "Email es requerido"}), 400
        
        email = data['email']
        user_name = data.get('user_name', 'Usuario')
        login_time = data.get('login_time', 'Ahora')

        # Autenticar Gmail
        creds = authenticate_gmail()
        service = build('gmail', 'v1', credentials=creds)
        
        # Crear contenido HTML personalizado
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 20px;">
            <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                <div style="background-color: #4CAF50; color: white; padding: 20px; text-align: center;">
                    <h1 style="margin: 0;">🔐 Notificación de Acceso</h1>
                </div>
                <div style="padding: 20px;">
                    <h2 style="color: #333;">Hola {user_name},</h2>
                    <p style="color: #666; line-height: 1.6;">
                        Te notificamos que se ha realizado un <strong>inicio de sesión exitoso</strong> en tu cuenta.
                    </p>
                    <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>📧 Email:</strong> {email}</p>
                        <p style="margin: 5px 0;"><strong>🕐 Hora:</strong> {login_time}</p>
                    </div>
                    <p style="color: #666; line-height: 1.6;">
                        Si no fuiste tú quien inició sesión, por favor contacta al administrador del sistema inmediatamente.
                    </p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #999; font-size: 12px; text-align: center;">
                        Este es un mensaje automático del sistema de notificaciones.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Crear y enviar mensaje
        mensaje = create_message(
            sender="juan.clavijo50057@ucaldas.edu.co",
            to=email,
            subject="🔐 Notificación de Inicio de Sesión",
            html_content=html_body
        )
        
        result = send_message(service, 'me', mensaje)
        
        if result["success"]:
            return jsonify({
                "success": True,
                "message": "Notificación enviada correctamente",
                "message_id": result["message_id"],
                "email_sent_to": email
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": result["error"]
            }), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error interno del servidor: {str(e)}"
        }), 500

# Endpoint genérico para enviar cualquier tipo de notificación
@app.route('/notifications/send', methods=['POST'])
def send_custom_notification():
    try:
        data = request.get_json()
        
        required_fields = ['email', 'subject', 'message']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"{field} es requerido"}), 400
        
        # Autenticar Gmail
        creds = authenticate_gmail()
        service = build('gmail', 'v1', credentials=creds)

        html_body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
            <div style="max-width: 600px; margin: 30px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px #eee;">
              <div style="background: #1976d2; color: #fff; padding: 20px; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 24px;">📢 Notificación Importante</h1>
              </div>
              <div style="padding: 24px;">
                <h2 style="color: #333; margin-top: 0;">¡Hola!</h2>
                <p style="color: #555; font-size: 16px;">
                  Este es un mensaje automático enviado desde el sistema de notificaciones.
                </p>
                <div style="background: #f9f9f9; border-radius: 6px; padding: 16px; margin: 20px 0;">
                  <p style="margin: 0; color: #1976d2; font-weight: bold;">{data['message']}</p>
                </div>
                <p style="color: #888; font-size: 13px;">
                  Si tienes dudas, contacta al soporte.
                </p>
              </div>
              <div style="background: #eee; color: #999; text-align: center; padding: 12px; border-radius: 0 0 8px 8px; font-size: 12px;">
                Sistema de Notificaciones &copy; 2025
              </div>
            </div>
          </body>
        </html>
        """
        # Crear mensaje personalizado
        html_content = data.get('html_content', f"<p>{data['message']}</p>")
        
        mensaje = create_message(
            sender="juan.clavijo50057@ucaldas.edu.co",
            to=data['email'],
            subject=data['subject'],
            html_content=html_body
        )
        
        result = send_message(service, 'me', mensaje)
        
        if result["success"]:
            return jsonify({
                "success": True,
                "message": "Notificación enviada correctamente",
                "message_id": result["message_id"]
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": result["error"]
            }), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error interno del servidor: {str(e)}"
        }), 500

# Endpoint de health check
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "ms-notifications",
        "timestamp": "2025-09-23"
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)  # Ejecutar en el puerto 5001