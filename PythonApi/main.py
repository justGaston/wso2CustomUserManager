from fastapi import FastAPI
from pydantic import BaseModel

# Crear una instancia de FastAPI
app = FastAPI()

# Definir el modelo de datos para el login
class LoginRequest(BaseModel):
    user: str
    password: str

# Endpoint de login
@app.post("/login")
async def login(request: LoginRequest):
    # Aquí puedes implementar la lógica de autenticación
    # Por simplicidad, se verifica si el usuario y la contraseña son correctos
    if request.user == "usuario_correcto" and request.password == "contrasena_correcta":
        return {"success": True}
    return {"success": False}
