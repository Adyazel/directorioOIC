# add_user.py
from dotenv import load_dotenv
load_dotenv()  # Carga las variables de entorno del archivo .env

from app import app, db  # Importa la instancia de la aplicación y la base de datos
from app import User  # Asegúrate de que esta importación coincida con la ubicación de tu modelo User

# Crea un contexto de aplicación para que las variables de configuración se carguen correctamente
with app.app_context():
    # Crea una instancia del modelo User
    new_user = User(username='admin', email='admin@example.com')
    new_user.set_password('RssjT7AQ,bBy];%x') 
     # Esto guardará el hash, no la contraseña en texto plano

    # Agrega el nuevo usuario a la sesión de la base de datos y confirma los cambios
    db.session.add(new_user)
    db.session.commit()

print('Usuario agregado exitosamente.')
