import os
from flask import Flask, render_template, request, redirect, url_for, flash, session,send_from_directory,jsonify 
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField,BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError , Optional # Asegúrate de importar ValidationError
from flask_login import current_user, login_required,LoginManager,login_user,logout_user,UserMixin,login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import DevelopmentConfig
from flask_wtf.file import FileField, FileAllowed, FileRequired
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
load_dotenv()


# Configuración del logging
logging.basicConfig(level=logging.DEBUG)  # Puedes cambiar DEBUG por INFO si deseas menos detalle

# Crea un FileHandler
file_handler = RotatingFileHandler('static/logs/log.log', maxBytes=1024*1024*100, backupCount=20)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s '
    '[in %(pathname)s:%(lineno)d]'
))

# Añade el FileHandler al logger de Flask y al logger de SQLAlchemy
logging.getLogger('werkzeug').addHandler(file_handler)
logging.getLogger('sqlalchemy.engine').addHandler(file_handler)

# Establece el nivel de log de SQLAlchemy a INFO (puedes usar DEBUG para más detalle)
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
db = SQLAlchemy(app)
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# Modelo de usuario
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    rol = db.Column(db.Integer, nullable=False, default=0)

    # Nuevos campos añadidos
    full_name = db.Column(db.String(200), nullable=False)  # Nombre Completo
    administrative_unit = db.Column(db.String(200), nullable=False)  # Unidad Administrativa
    phone_ext = db.Column(db.String(50), nullable=False)  # Teléfono: Ext
    is_enabled = db.Column(db.Boolean, default=True)  # Campo para habilitar o inhabilitar el usuario

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



# Modelo de Dependencia
class Dependencia(db.Model):
    __tablename__ = 'dependencia'  # Asegúrate de definir el nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    foto = db.Column(db.String(255), nullable=True)  # Almacena el nombre del archivo de la imagen
    oic_id = db.Column(db.Integer, db.ForeignKey('oic.id'), nullable=True)  # Permite que dependencias estén inicialmente sin asignar
    habilitada = db.Column(db.Boolean, default=True, nullable=False)


# Modelo de OIC ajustado 
class OIC(db.Model):
    __tablename__ = 'oic'  # Asegúrate de definir el nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(150), nullable=False)
    telefono = db.Column(db.String(50), nullable=False)
    extension = db.Column(db.String(50), nullable=True)
    correo_electronico = db.Column(db.String(120), nullable=False)
    direccion = db.Column(db.String(150), nullable=False)
    colonia = db.Column(db.String(150), nullable=False)
    codigo_postal = db.Column(db.String(10), nullable=False)
    ciudad = db.Column(db.String(50), nullable=False) 
    sector = db.Column(db.String(50), nullable=True)
    dependencias = db.relationship('Dependencia', backref='oic', lazy=True)
     # Nuevo campo booleano para la habilitación del registro
    esta_habilitado = db.Column(db.Boolean, default=True)



# Formulario de inicio de sesión
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(message="El campo de usuario es obligatorio")])
    password = PasswordField('Contraseña', validators=[DataRequired(message="El campo de contraseña es obligatorio")])
    submit = SubmitField('Iniciar sesión')

# Formulario de OIC
class OICForm(FlaskForm):
    nombre_completo = StringField('Nombre completo', validators=[DataRequired()])
    telefono = StringField('Teléfono', validators=[DataRequired()])
    extension = StringField('Extensión')
    correo_electronico = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    direccion = StringField('Dirección', validators=[DataRequired()])
    colonia = StringField('Colonia', validators=[DataRequired()])
    codigo_postal = StringField('Código postal', validators=[DataRequired()])
    ciudad = StringField('Ciudad', validators=[DataRequired()])
    dependencia = StringField('Dependencias')
    sector = StringField('Sector')
    esta_habilitado = BooleanField('Habilitado')
    submit = SubmitField('Enviar')

# Formulario de registro de usuario
class UserRegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[
        DataRequired(),
        EqualTo('confirm_password', message='Las contraseñas deben coincidir.')
    ])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired()])
    
    # Nuevos campos añadidos
    full_name = StringField('Nombre Completo', validators=[DataRequired()])
    administrative_unit = SelectField(
        'Unidad Administrativa',
        choices=[ ('REPRESENTACION EN CD. JUAREZ', 'REPRESENTACION EN CD. JUAREZ'),
    ('OFICINA DEL C. DIRECTOR GENERAL DE LA COMISION ESTATAL DE MEJORA REGULATORIA', 'OFICINA DEL C. DIRECTOR GENERAL DE LA COMISION ESTATAL DE MEJORA REGULATORIA'),
    ('OFICINA DEL C. DIRECTOR DE ESTRATEGIAS DE MEJORA REGULATORIA', 'OFICINA DEL C. DIRECTOR DE ESTRATEGIAS DE MEJORA REGULATORIA'),
    ('DEPARTAMENTO DE TRAMITES Y SERVICIOS', 'DEPARTAMENTO DE TRAMITES Y SERVICIOS'),
    ('COORDINACION ADMINISTRATIVA', 'COORDINACION ADMINISTRATIVA'),
    ('DEPARTAMENTO DE RECURSOS MATERIALES', 'DEPARTAMENTO DE RECURSOS MATERIALES'),
    ('COORDINACION DE TECNOLOGIAS DE LA INFORMACION', 'COORDINACION DE TECNOLOGIAS DE LA INFORMACION'),
    ('DEPARTAMENTO DE ANALISIS Y DESARROLLO', 'DEPARTAMENTO DE ANALISIS Y DESARROLLO'),
    ('OFICINA DEL C. DIRECTOR GENERAL DE TRANSPARENCIA Y GESTION DE LA INFORMACION GUBERNAMENTAL', 'OFICINA DEL C. DIRECTOR GENERAL DE TRANSPARENCIA Y GESTION DE LA INFORMACION GUBERNAMENTAL'),
    ('DEPARTAMENTO DE VIGILANCIA Y SEGUIMIENTO EN MATERIA DE TRANSPARENCIA Y ACCESO A LA INFORMACION PUBLICA', 'DEPARTAMENTO DE VIGILANCIA Y SEGUIMIENTO EN MATERIA DE TRANSPARENCIA Y ACCESO A LA INFORMACION PUBLICA'),
    ('DEPARTAMENTO DE GESTION DE INFORMACION GUBERNAMENTAL Y RENDICION DE CUENTAS', 'DEPARTAMENTO DE GESTION DE INFORMACION GUBERNAMENTAL Y RENDICION DE CUENTAS'),
    ('DEPARTAMENTO DE VINCULACION', 'DEPARTAMENTO DE VINCULACION'),
    ('DEPARTAMENTO DE UNIDAD DE TRANSPARENCIA', 'DEPARTAMENTO DE UNIDAD DE TRANSPARENCIA'),
    ('OFICINA DEL C. SUBSECRETARIO DE ASUNTOS JURIDICOS, CONTRATACIONES PUBLICAS Y DE RESPONSABILIDADES', 'OFICINA DEL C. SUBSECRETARIO DE ASUNTOS JURIDICOS, CONTRATACIONES PUBLICAS Y DE RESPONSABILIDADES'),
    ('OFICINA DEL C. DIRECTOR DE CONTRATACIONES PUBLICAS', 'OFICINA DEL C. DIRECTOR DE CONTRATACIONES PUBLICAS'),
    ('DEPARTAMENTO DE CONTROVERSIAS EN CONTRATACIONES PUBLICAS', 'DEPARTAMENTO DE CONTROVERSIAS EN CONTRATACIONES PUBLICAS'),
    ('DEPARTAMENTO DE NORMATIVIDAD EN CONTRATACIONES PUBLICAS', 'DEPARTAMENTO DE NORMATIVIDAD EN CONTRATACIONES PUBLICAS'),
    ('OFICINA DEL C. DIRECTOR GENERAL JURIDICA Y DE RESPONSABILIDADES', 'OFICINA DEL C. DIRECTOR GENERAL JURIDICA Y DE RESPONSABILIDADES'),
    ('DEPARTAMENTO DE SUBSTANCIACION', 'DEPARTAMENTO DE SUBSTANCIACION'),
    ('DEPARTAMENTO DE RESOLUCIONES', 'DEPARTAMENTO DE RESOLUCIONES'),
    ('DEPARTAMENTO DE ASUNTOS JURIDICOS', 'DEPARTAMENTO DE ASUNTOS JURIDICOS'),
    ('OFICINA DEL C. SUBSECRETARIO DE INVESTIGACION Y EVOLUCION PATRIMONIAL', 'OFICINA DEL C. SUBSECRETARIO DE INVESTIGACION Y EVOLUCION PATRIMONIAL'),
    ('OFICINA DE C. DIRECTOR DE EVOLUCION PATRIMONIAL', 'OFICINA DE C. DIRECTOR DE EVOLUCION PATRIMONIAL'),
    ('DEPARTAMENTO DE EVOLUCION PATRIMONIAL', 'DEPARTAMENTO DE EVOLUCION PATRIMONIAL'),
    ('OFICINA DEL C. DIRECTOR GENERAL DE DENUNCIAS E INVESTIGACIONES', 'OFICINA DEL C. DIRECTOR GENERAL DE DENUNCIAS E INVESTIGACIONES'),
    ('DEPARTAMENTO DE DENUNCIAS E INVESTIGACIONES',
  'DEPARTAMENTO DE DENUNCIAS E INVESTIGACIONES'),
 ('OFICINA DEL C SUBSECRETARIO DE BUEN GOBIERNO',
  'OFICINA DEL C. SUBSECRETARIO DE BUEN GOBIERNO'),
 ('OFICINA DEL C DIRECTOR DE DESARROLLO INSTITUCIONAL Y FORTALECIMIENTO DE LA GESTION PUBLICA',
  'OFICINA DEL C. DIRECTOR DE DESARROLLO INSTITUCIONAL Y FORTALECIMIENTO DE LA GESTION PUBLICA'),
 ('DEPARTAMENTO DE ORGANIZACION Y PROCESOS',
  'DEPARTAMENTO DE ORGANIZACION Y PROCESOS'),
 ('DEPARTAMENTO DE CONTROL INTERNO', 'DEPARTAMENTO DE CONTROL INTERNO'),
 ('DEPARTAMENTO DE CULTURA INSTITUCIONAL Y ETICA PUBLICA',
  'DEPARTAMENTO DE CULTURA INSTITUCIONAL Y ETICA PUBLICA'),
 ('OFICINA DEL C DIRECTOR GENERAL DE SERVICIOS INNOVACION JURIDICA PARTICIPACION CIUDADANA Y DE EQUIDAD DE GENERO',
  'OFICINA DEL C. DIRECTOR GENERAL DE SERVICIOS, INNOVACION JURIDICA, PARTICIPACION CIUDADANA Y DE EQUIDAD DE GENERO'),
 ('DEPARTAMENTO DE SERVICIOS E INNOVACION JURIDICA',
  'DEPARTAMENTO DE SERVICIOS E INNOVACION JURIDICA'),
 ('DEPARTAMENTO DE PARTICIPACION CIUDADANA Y EQUIDAD DE GENERO',
  'DEPARTAMENTO DE PARTICIPACION CIUDADANA Y EQUIDAD DE GENERO'),
 ('OFICINA DEL C SUBSECRETARIO DE FISCALIZACION',
  'OFICINA DEL C. SUBSECRETARIO DE FISCALIZACION'),
 ('DEPARTAMENTO DE AUDITORIAS DE CUMPLIMIENTO Y APOYO NORMATIVO',
  'DEPARTAMENTO DE AUDITORIAS DE CUMPLIMIENTO Y APOYO NORMATIVO'),
 ('OFICINA DEL C DIRECTOR DE AUDITORIA GUBERNAMENTAL',
  'OFICINA DEL C. DIRECTOR DE AUDITORIA GUBERNAMENTAL'),
 ('DEPARTAMENTO DE AUDITORIAS ESTATALES A',
  'DEPARTAMENTO DE AUDITORIAS ESTATALES "A"'),
 ('DEPARTAMENTO DE AUDITORIAS EXTERNAS',
  'DEPARTAMENTO DE AUDITORIAS EXTERNAS'),
 ('DEPARTAMENTO DE AUDITORIAS ESTATALES B',
  'DEPARTAMENTO DE AUDITORIAS ESTATALES "B"'),
 ('OFICINA DEL C DIRECTOR DE AUDITORIA DE PROGRAMAS DE INVERSION',
  'OFICINA DEL C. DIRECTOR DE AUDITORIA DE PROGRAMAS DE INVERSION'),
 ('DEPARTAMENTO DE AUDITORIA AL EJERCICIO DEL RECURSO FEDERAL',
  'DEPARTAMENTO DE AUDITORIA AL EJERCICIO DEL RECURSO FEDERAL'),
 ('DEPARTAMENTO DE AUDITORIA DE OBRA PUBLICA',
  'DEPARTAMENTO DE AUDITORIA DE OBRA PUBLICA')])
    phone_ext = StringField('Teléfono: Ext', validators=[DataRequired()])

    submit = SubmitField('Registrar')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Por favor usa un nombre de usuario diferente.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Por favor usa un correo electrónico diferente.')
        

class UserUpdateForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    email = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Nueva Contraseña', validators=[Optional()])  # Contraseña opcional

    # Nuevos campos añadidos
    full_name = StringField('Nombre Completo')  # No es obligatorio en la actualización
    administrative_unit = SelectField(
        'Unidad Administrativa',
        choices=[ ('REPRESENTACION EN CD. JUAREZ', 'REPRESENTACION EN CD. JUAREZ'),
    ('OFICINA DEL C. DIRECTOR GENERAL DE LA COMISION ESTATAL DE MEJORA REGULATORIA', 'OFICINA DEL C. DIRECTOR GENERAL DE LA COMISION ESTATAL DE MEJORA REGULATORIA'),
    ('OFICINA DEL C. DIRECTOR DE ESTRATEGIAS DE MEJORA REGULATORIA', 'OFICINA DEL C. DIRECTOR DE ESTRATEGIAS DE MEJORA REGULATORIA'),
    ('DEPARTAMENTO DE TRAMITES Y SERVICIOS', 'DEPARTAMENTO DE TRAMITES Y SERVICIOS'),
    ('COORDINACION ADMINISTRATIVA', 'COORDINACION ADMINISTRATIVA'),
    ('DEPARTAMENTO DE RECURSOS MATERIALES', 'DEPARTAMENTO DE RECURSOS MATERIALES'),
    ('COORDINACION DE TECNOLOGIAS DE LA INFORMACION', 'COORDINACION DE TECNOLOGIAS DE LA INFORMACION'),
    ('DEPARTAMENTO DE ANALISIS Y DESARROLLO', 'DEPARTAMENTO DE ANALISIS Y DESARROLLO'),
    ('OFICINA DEL C. DIRECTOR GENERAL DE TRANSPARENCIA Y GESTION DE LA INFORMACION GUBERNAMENTAL', 'OFICINA DEL C. DIRECTOR GENERAL DE TRANSPARENCIA Y GESTION DE LA INFORMACION GUBERNAMENTAL'),
    ('DEPARTAMENTO DE VIGILANCIA Y SEGUIMIENTO EN MATERIA DE TRANSPARENCIA Y ACCESO A LA INFORMACION PUBLICA', 'DEPARTAMENTO DE VIGILANCIA Y SEGUIMIENTO EN MATERIA DE TRANSPARENCIA Y ACCESO A LA INFORMACION PUBLICA'),
    ('DEPARTAMENTO DE GESTION DE INFORMACION GUBERNAMENTAL Y RENDICION DE CUENTAS', 'DEPARTAMENTO DE GESTION DE INFORMACION GUBERNAMENTAL Y RENDICION DE CUENTAS'),
    ('DEPARTAMENTO DE VINCULACION', 'DEPARTAMENTO DE VINCULACION'),
    ('DEPARTAMENTO DE UNIDAD DE TRANSPARENCIA', 'DEPARTAMENTO DE UNIDAD DE TRANSPARENCIA'),
    ('OFICINA DEL C. SUBSECRETARIO DE ASUNTOS JURIDICOS, CONTRATACIONES PUBLICAS Y DE RESPONSABILIDADES', 'OFICINA DEL C. SUBSECRETARIO DE ASUNTOS JURIDICOS, CONTRATACIONES PUBLICAS Y DE RESPONSABILIDADES'),
    ('OFICINA DEL C. DIRECTOR DE CONTRATACIONES PUBLICAS', 'OFICINA DEL C. DIRECTOR DE CONTRATACIONES PUBLICAS'),
    ('DEPARTAMENTO DE CONTROVERSIAS EN CONTRATACIONES PUBLICAS', 'DEPARTAMENTO DE CONTROVERSIAS EN CONTRATACIONES PUBLICAS'),
    ('DEPARTAMENTO DE NORMATIVIDAD EN CONTRATACIONES PUBLICAS', 'DEPARTAMENTO DE NORMATIVIDAD EN CONTRATACIONES PUBLICAS'),
    ('OFICINA DEL C. DIRECTOR GENERAL JURIDICA Y DE RESPONSABILIDADES', 'OFICINA DEL C. DIRECTOR GENERAL JURIDICA Y DE RESPONSABILIDADES'),
    ('DEPARTAMENTO DE SUBSTANCIACION', 'DEPARTAMENTO DE SUBSTANCIACION'),
    ('DEPARTAMENTO DE RESOLUCIONES', 'DEPARTAMENTO DE RESOLUCIONES'),
    ('DEPARTAMENTO DE ASUNTOS JURIDICOS', 'DEPARTAMENTO DE ASUNTOS JURIDICOS'),
    ('OFICINA DEL C. SUBSECRETARIO DE INVESTIGACION Y EVOLUCION PATRIMONIAL', 'OFICINA DEL C. SUBSECRETARIO DE INVESTIGACION Y EVOLUCION PATRIMONIAL'),
    ('OFICINA DE C. DIRECTOR DE EVOLUCION PATRIMONIAL', 'OFICINA DE C. DIRECTOR DE EVOLUCION PATRIMONIAL'),
    ('DEPARTAMENTO DE EVOLUCION PATRIMONIAL', 'DEPARTAMENTO DE EVOLUCION PATRIMONIAL'),
    ('OFICINA DEL C. DIRECTOR GENERAL DE DENUNCIAS E INVESTIGACIONES', 'OFICINA DEL C. DIRECTOR GENERAL DE DENUNCIAS E INVESTIGACIONES'),
    ('DEPARTAMENTO DE DENUNCIAS E INVESTIGACIONES',
  'DEPARTAMENTO DE DENUNCIAS E INVESTIGACIONES'),
 ('OFICINA DEL C SUBSECRETARIO DE BUEN GOBIERNO',
  'OFICINA DEL C. SUBSECRETARIO DE BUEN GOBIERNO'),
 ('OFICINA DEL C DIRECTOR DE DESARROLLO INSTITUCIONAL Y FORTALECIMIENTO DE LA GESTION PUBLICA',
  'OFICINA DEL C. DIRECTOR DE DESARROLLO INSTITUCIONAL Y FORTALECIMIENTO DE LA GESTION PUBLICA'),
 ('DEPARTAMENTO DE ORGANIZACION Y PROCESOS',
  'DEPARTAMENTO DE ORGANIZACION Y PROCESOS'),
 ('DEPARTAMENTO DE CONTROL INTERNO', 'DEPARTAMENTO DE CONTROL INTERNO'),
 ('DEPARTAMENTO DE CULTURA INSTITUCIONAL Y ETICA PUBLICA',
  'DEPARTAMENTO DE CULTURA INSTITUCIONAL Y ETICA PUBLICA'),
 ('OFICINA DEL C DIRECTOR GENERAL DE SERVICIOS INNOVACION JURIDICA PARTICIPACION CIUDADANA Y DE EQUIDAD DE GENERO',
  'OFICINA DEL C. DIRECTOR GENERAL DE SERVICIOS, INNOVACION JURIDICA, PARTICIPACION CIUDADANA Y DE EQUIDAD DE GENERO'),
 ('DEPARTAMENTO DE SERVICIOS E INNOVACION JURIDICA',
  'DEPARTAMENTO DE SERVICIOS E INNOVACION JURIDICA'),
 ('DEPARTAMENTO DE PARTICIPACION CIUDADANA Y EQUIDAD DE GENERO',
  'DEPARTAMENTO DE PARTICIPACION CIUDADANA Y EQUIDAD DE GENERO'),
 ('OFICINA DEL C SUBSECRETARIO DE FISCALIZACION',
  'OFICINA DEL C. SUBSECRETARIO DE FISCALIZACION'),
 ('DEPARTAMENTO DE AUDITORIAS DE CUMPLIMIENTO Y APOYO NORMATIVO',
  'DEPARTAMENTO DE AUDITORIAS DE CUMPLIMIENTO Y APOYO NORMATIVO'),
 ('OFICINA DEL C DIRECTOR DE AUDITORIA GUBERNAMENTAL',
  'OFICINA DEL C. DIRECTOR DE AUDITORIA GUBERNAMENTAL'),
 ('DEPARTAMENTO DE AUDITORIAS ESTATALES A',
  'DEPARTAMENTO DE AUDITORIAS ESTATALES "A"'),
 ('DEPARTAMENTO DE AUDITORIAS EXTERNAS',
  'DEPARTAMENTO DE AUDITORIAS EXTERNAS'),
 ('DEPARTAMENTO DE AUDITORIAS ESTATALES B',
  'DEPARTAMENTO DE AUDITORIAS ESTATALES "B"'),
 ('OFICINA DEL C DIRECTOR DE AUDITORIA DE PROGRAMAS DE INVERSION',
  'OFICINA DEL C. DIRECTOR DE AUDITORIA DE PROGRAMAS DE INVERSION'),
 ('DEPARTAMENTO DE AUDITORIA AL EJERCICIO DEL RECURSO FEDERAL',
  'DEPARTAMENTO DE AUDITORIA AL EJERCICIO DEL RECURSO FEDERAL'),
 ('DEPARTAMENTO DE AUDITORIA DE OBRA PUBLICA',
  'DEPARTAMENTO DE AUDITORIA DE OBRA PUBLICA')])  # No es obligatorio en la actualización
    phone_ext = StringField('Teléfono: Ext')  # No es obligatorio en la actualización
    is_enabled = BooleanField('Habilitado')
    submit = SubmitField('Actualizar')

    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(UserUpdateForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Por favor usa un nombre de usuario diferente.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Por favor usa un correo electrónico diferente.')

class OICUpdateForm(FlaskForm):
    nombre_completo = StringField('Nombre Completo', validators=[Optional()])
    telefono = StringField('Teléfono', validators=[Optional()])
    extension = StringField('Extensión', validators=[Optional()])
    correo_electronico = StringField('Correo Electrónico', validators=[Optional(), Email()])
    direccion = StringField('Dirección', validators=[Optional()])
    colonia = StringField('Colonia', validators=[Optional()])
    codigo_postal = StringField('Código postal', validators=[Optional()])
    ciudad = StringField('Ciudad', validators=[Optional()])
    sector = StringField('Sector', validators=[Optional()])
    esta_habilitado = BooleanField('Habilitado', validators=[Optional()])
    submit = SubmitField('Actualizar')

class AsignarDependenciaForm(FlaskForm):
    oic_id = SelectField('Titular del Órgano Interno de Control', coerce=int, validators=[DataRequired()])
    dependencia_id = SelectField('Nombre de la Dependencia', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Asignar Dependencia')

class DependenciaForm(FlaskForm):
    nombre = StringField('Nombre de la Dependencia', validators=[DataRequired()])
    foto = FileField('Logo de la Dependencia', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png'], 'Solo imá  genes en formato JPG o PNG.')
    ])
    submit = SubmitField('Registrar Dependencia') 
      

class DependenciaUpdateForm(FlaskForm):
    nombre = StringField('Nombre de la Dependencia', validators=[Optional()])
    foto = FileField('Logo de la Dependencia', validators=[
        FileAllowed(['jpg', 'png'], 'Solo imágenes en formato JPG o PNG.'),
        Optional()
    ])
    habilitada = BooleanField('Habilitada')
    submit = SubmitField('Actualizar Dependencia')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.is_enabled:
                login_user(user)  # Inicia sesión con el usuario
                flash('Inicio de sesión exitoso.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Esta cuenta está inhabilitada.', 'danger')
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'danger')
    
    return render_template('login.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
def logout():
    logout_user()  # Cierra la sesión del usuario actual
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
         print("--------------------Rol del usuario autenticado:", current_user.rol)
         user_role = current_user.rol
    else:
         print("-----------------Usuario no autenticado")
         user_role = None
    regreso = ''
    oic_list = OIC.query.all()  # Obtener todos los registros de la tabla OIC
    regreso = render_template('index.html', oic_list=oic_list, user_role=user_role)
    return regreso
 

@app.route('/asignar_dependencia', methods=['GET', 'POST'])
@login_required  # Asegura que solo los usuarios autenticados puedan acceder
def asignar_dependencia():
    form = AsignarDependenciaForm()
    form.oic_id.choices = [(oic.id, oic.nombre_completo) for oic in OIC.query.all()]
    form.dependencia_id.choices = [(dep.id, dep.nombre) for dep in Dependencia.query.filter_by(oic_id=None, habilitada=True).all()]
    dependencias = Dependencia.query.all()

    if form.validate_on_submit():
        dependencia = Dependencia.query.get(form.dependencia_id.data)
        oic = OIC.query.get(form.oic_id.data)
        dependencia.oic = oic
        db.session.commit()
        flash('Dependencia asignada correctamente.', 'success')
        return redirect(url_for('asignar_dependencia'))
    return render_template('asignar_dependencia.html', form=form, dependencias=dependencias)

@app.route('/desasignar_dependencia/<int:dependencia_id>', methods=['POST'])
@login_required
def desasignar_dependencia(dependencia_id):
    dependencia = Dependencia.query.get_or_404(dependencia_id)
    dependencia.oic_id = None
    db.session.commit()
    flash('Dependencia desasignada correctamente.', 'success')
    return redirect(url_for('asignar_dependencia'))


@app.route('/manage_users', methods=['GET', 'POST'])
@login_required  # Asegura que solo usuarios autenticados accedan a esta ruta
def manage_users():
    # Si deseas restringir aún más, puedes agregar comprobaciones de roles aquí.
    # Por ejemplo, si solo los administradores pueden gestionar usuarios:
    # if not current_user.es_administrador:
    #     flash('No tienes permiso para acceder a esta página.', 'danger')
    #     return redirect(url_for('index'))

    user_form = UserRegistrationForm()
    user_update_form = UserUpdateForm(obj=current_user)  # Precargar formulario con datos del usuario

    if user_form.validate_on_submit():
        new_user = User(
            username=user_form.username.data, 
            email=user_form.email.data,
            full_name=user_form.full_name.data,  # Nuevo campo
            administrative_unit=user_form.administrative_unit.data,  # Nuevo campo
            phone_ext=user_form.phone_ext.data  # Nuevo campo
        )
        new_user.set_password(user_form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuario registrado exitosamente', 'success')
        return redirect(url_for('manage_users'))

    if user_update_form.validate_on_submit():
        # Asegúrate de que el usuario actual es el que se está actualizando
        # o que el usuario actual tiene permiso para actualizar otros usuarios.
        current_user.username = user_update_form.username.data
        current_user.email = user_update_form.email.data
        if user_update_form.password.data:
            current_user.set_password(user_update_form.password.data)

        # Actualiza los campos nuevos si son proporcionados
        if user_update_form.full_name.data:
            current_user.full_name = user_update_form.full_name.data
        if user_update_form.administrative_unit.data:
            current_user.administrative_unit = user_update_form.administrative_unit.data
        if user_update_form.phone_ext.data:
            current_user.phone_ext = user_update_form.phone_ext.data

        db.session.commit()
        flash('Datos del usuario actualizados exitosamente', 'success')
        return redirect(url_for('manage_users'))

    users = User.query.all()
    return render_template('manage_users.html', user_form=user_form, user_update_form=user_update_form, users=users)


@app.route('/add_data', methods=['GET', 'POST'])
@login_required  # Asegura que solo usuarios autenticados puedan acceder
def add_data():
    form = OICForm()
    oics = OIC.query.all()
    oic_update_form = OICUpdateForm()

    if form.validate_on_submit():
        nuevo_oic = OIC(
            nombre_completo=form.nombre_completo.data,
            telefono=form.telefono.data,
            extension=form.extension.data,
            correo_electronico=form.correo_electronico.data,
            direccion=form.direccion.data,
            colonia=form.colonia.data,
            codigo_postal=form.codigo_postal.data,
            ciudad=form.ciudad.data,
            sector=form.sector.data,
            esta_habilitado=form.esta_habilitado.data
        )
        db.session.add(nuevo_oic)
        db.session.commit()
        flash('Registro añadido exitosamente!', 'success')
        return redirect(url_for('add_data'))

    return render_template('add_data.html', form=form, oics=oics, oic_update_form=oic_update_form, current_user=current_user)


from flask_login import login_required, current_user

@app.route('/agregar_dependencia', methods=['GET', 'POST'])
@login_required  # Asegura que solo los usuarios autenticados puedan acceder a esta ruta
def agregar_dependencia():
    form = DependenciaForm()
    dependencia_update_form = DependenciaUpdateForm()  # Instancia para el modal de edición
    dependencias = Dependencia.query.all()

    if form.validate_on_submit():
        archivo = form.foto.data
        nombre_archivo_seguro = secure_filename(archivo.filename)

        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        ruta_completa = os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_seguro)
        archivo.save(ruta_completa)

        nueva_dependencia = Dependencia(nombre=form.nombre.data, foto=nombre_archivo_seguro)

        try:
            db.session.add(nueva_dependencia)
            db.session.commit()
            flash('Dependencia agregada con éxito!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Ocurrió un error al agregar la dependencia: {}'.format(e), 'danger')
            app.logger.error('Error al agregar dependencia: {}'.format(e))

        return redirect(url_for('agregar_dependencia'))

    return render_template('agregar_dependencia.html', form=form, dependencia_update_form=dependencia_update_form, dependencias=dependencias)




@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form['user_id']
    user = User.query.get(user_id)

    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('manage_users'))

    user_update_form = UserUpdateForm(request.form)
    user_update_form.original_username = user.username
    user_update_form.original_email = user.email

    if user_update_form.validate_on_submit():
        user.username = user_update_form.username.data
        user.email = user_update_form.email.data
        user.full_name = user_update_form.full_name.data
        user.administrative_unit = user_update_form.administrative_unit.data
        user.phone_ext = user_update_form.phone_ext.data

        # Aquí manejamos el checkbox 'is_enabled'
        # Si el checkbox está marcado, se recibirá 'True', de lo contrario, se recibirá 'False' del campo oculto
        user.is_enabled = user_update_form.is_enabled.data

        if user_update_form.password.data:
            user.set_password(user_update_form.password.data)

        db.session.commit()
        flash('Usuario actualizado con éxito', 'success')
    else:
        for error in user_update_form.errors.values():
            flash(f'Error en el formulario: {error[0]}', 'danger')

    return redirect(url_for('manage_users'))


@app.route('/update_oic', methods=['POST'])
def update_oic():
    oic_id = request.form['oic_id']
    oic = OIC.query.get(oic_id)

    if not oic:
        flash('Registro OIC no encontrado', 'danger')
        return redirect(url_for('add_data'))

    oic_update_form = OICUpdateForm(request.form)

    if oic_update_form.validate_on_submit():
        # Actualiza los campos del registro OIC
        oic.nombre_completo = oic_update_form.nombre_completo.data
        oic.telefono = oic_update_form.telefono.data
        oic.extension = oic_update_form.extension.data  # Nuevo campo
        oic.correo_electronico = oic_update_form.correo_electronico.data
        oic.direccion = oic_update_form.direccion.data  # Nuevo campo
        oic.colonia = oic_update_form.colonia.data  # Nuevo campo
        oic.codigo_postal = oic_update_form.codigo_postal.data  # Nuevo campo
        oic.ciudad = oic_update_form.ciudad.data
        oic.sector = oic_update_form.sector.data
        oic.esta_habilitado = oic_update_form.esta_habilitado.data# Nuevo campo

        db.session.commit()
        flash('Registro OIC actualizado con éxito', 'success')
    else:
        for error in oic_update_form.errors.values():
            flash(f'Error en el formulario: {error[0]}', 'danger')

    return redirect(url_for('add_data'))



@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete_dependencia/<int:dependencia_id>', methods=['GET', 'POST'])
def delete_dependencia(dependencia_id):
    dependencia = Dependencia.query.get_or_404(dependencia_id)

    try:
        # Eliminar la imagen asociada si existe
        if dependencia.foto:
            ruta_imagen = os.path.join(app.config['UPLOAD_FOLDER'], dependencia.foto)
            if os.path.exists(ruta_imagen):
                os.remove(ruta_imagen)

        db.session.delete(dependencia)
        db.session.commit()
        flash('Dependencia eliminada con éxito!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar la dependencia: {}'.format(e), 'danger')

    return redirect(url_for('agregar_dependencia'))

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Usuario eliminado con éxito.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/update_dependencia', methods=['POST'])
def update_dependencia():
    dependencia_update_form = DependenciaUpdateForm()

    if dependencia_update_form.validate_on_submit():
        dependencia_id = request.form.get('dependencia_id')
        dependencia = Dependencia.query.get(dependencia_id)

        if dependencia:
            # Actualizar el nombre de la dependencia
            if dependencia_update_form.nombre.data:
                dependencia.nombre = dependencia_update_form.nombre.data

            if dependencia_update_form.foto.data:
                # Eliminar la imagen anterior si existe
                if dependencia.foto:
                    ruta_imagen_anterior = os.path.join(app.config['UPLOAD_FOLDER'], dependencia.foto)
                    if os.path.exists(ruta_imagen_anterior):
                        os.remove(ruta_imagen_anterior)

                # Guardar la nueva imagen
                archivo = dependencia_update_form.foto.data
                nombre_archivo_seguro = secure_filename(archivo.filename)
                ruta_completa = os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo_seguro)
                archivo.save(ruta_completa)
                dependencia.foto = nombre_archivo_seguro

            # Actualizar el estado de habilitación de la dependencia
            dependencia.habilitada = dependencia_update_form.habilitada.data

            # Compromete los cambios en la base de datos
            db.session.commit()
            flash('Dependencia actualizada con éxito', 'success')
        else:
            flash('Dependencia no encontrada', 'danger')
    else:
        flash('Error en el formulario', 'danger')

    return redirect(url_for('agregar_dependencia'))


@app.route('/delete_oic/<int:oic_id>', methods=['GET', 'POST'])
def delete_oic(oic_id):
    oic = OIC.query.get_or_404(oic_id)
    db.session.delete(oic)
    db.session.commit()
    flash('Registro OIC eliminado con éxito.', 'success')
    return redirect(url_for('add_data'))

@app.route('/autocomplete')
def autocomplete():
    query = request.args.get('query', '')  # Obtener la consulta del parámetro URL
    sugerencias = []

    if len(query) > 2:
        # Buscar coincidencias por nombre completo en OIC que estén habilitados
        resultados_oic = OIC.query.filter(
            OIC.nombre_completo.ilike(f'%{query}%'),
            OIC.esta_habilitado == True
        ).limit(5).all()
        sugerencias.extend([oic.nombre_completo for oic in resultados_oic])


    return jsonify(sugerencias)

@app.errorhandler(500)
def internal_error(error):
    return "500 error"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)