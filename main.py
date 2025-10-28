from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from datetime import timedelta

app = Flask(__name__)

# =============================
# CONFIGURACIÓN DE LA APP
# =============================
app.config["JWT_SECRET_KEY"] = "clave_super_secreta"  # 🔒 cámbiala en producción
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)

# =============================
# RATE LIMITER
# =============================

# El limitador usará el nombre de usuario (JWT) como clave
def user_identifier():
    # Si hay un token válido, usa su identidad; si no, usa la IP
    try:
        user = get_jwt_identity()
        return user if user else get_remote_address()
    except Exception:
        return get_remote_address()

limiter = Limiter(
    key_func=user_identifier,
    app=app,
    default_limits=[]
)

# =============================
# BASE DE DATOS SIMPLIFICADA
# =============================
USERS = {
    "ana": "1234",
    "bob": "abcd"
}

# =============================
# RUTAS DE AUTENTICACIÓN
# =============================

@app.post("/login")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in USERS and USERS[username] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Credenciales inválidas"}), 401


# =============================
# RUTAS PROTEGIDAS
# =============================

@app.get("/datos")
@jwt_required()  # solo usuarios autenticados
@limiter.limit("5 per minute")  # 🔥 límite de 5 peticiones por minuto por usuario
def datos():
    user = get_jwt_identity()
    return jsonify({
        "usuario": user,
        "datos": ["dato1", "dato2", "dato3"]
    })


@app.get("/perfil")
@jwt_required()
@limiter.limit("3 per minute")
def perfil():
    user = get_jwt_identity()
    return jsonify({
        "perfil": f"Información del usuario {user}"
    })


# =============================
# MANEJO DE ERRORES
# =============================
@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({
        "error": "Demasiadas peticiones, intenta más tarde.",
        "detalle": str(e.description)
    }), 429


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({
        "error": "Token inválido o no proporcionado."
    }), 401


if __name__ == "__main__":
    app.run(debug=True)
