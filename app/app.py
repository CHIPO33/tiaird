from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt, check_password_hash
from math import ceil
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import re

app = Flask(__name__)

bcrypt = Bcrypt(app)

app.secret_key = "my_key_david"

app.config['UPLOAD_FOLDER'] = './scr/static/img/uploads'

app.config['SECRET_KEY'] = 'B!1w8NAt1T^%kvhUI*S^'
app.config['DEBUG'] = True
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'david18'
app.config['MYSQL_DB'] = 'bolsadetrabajo'

mysql = MySQL(app)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        contraseña = request.form['contraseña']

        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM usuarios WHERE Correo = %s', (correo,))
        usuario = cur.fetchone()
        cur.close()

        if usuario and check_password_hash(usuario[3], contraseña):
            # Autenticación exitosa
            session['user_id'] = usuario[0]
            session['user_nombre'] = usuario[1]

            if usuario[4] == 'administrador':
                return redirect('/admin')
            elif usuario[4] == 'usuario común':
                return redirect('/user_common')
        else:
            flash('Credenciales inválidas', 'error')
            return redirect('/')

    return render_template('login.html')

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM vacantes')
    vacantes = cur.fetchall()
    cur.close()
    return render_template('admin_dashboard.html', vacantes=vacantes)

@app.route('/user_common')
def user_common_dashboard():
    if 'user_id' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM vacantes')
    vacantes = cur.fetchall()
    cur.close()
    return render_template('user_common_dashboard.html', vacantes=vacantes)


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        # Obtener los datos del formulario enviado
        nombre = request.form['nombre']
        correo = request.form['correo']
        contraseña = request.form['contraseña']

        # Hashear la contraseña antes de almacenarla en la base de datos
        hashed_password = bcrypt.generate_password_hash(contraseña).decode('utf-8')

        # Tipo de usuario por defecto
        tipo_usuario = 'usuario común'

        cur = mysql.connection.cursor()

        # Consultar si ya existe un usuario con el mismo correo electrónico
        cur.execute('SELECT * FROM usuarios WHERE Correo = %s', (correo,))
        usuarios = cur.fetchone()

        if usuarios:
            flash('El correo electrónico ya está registrado.', 'error')
            return render_template('register.html')

        # Insertar los datos del nuevo usuario en la tabla usuarios
        cur.execute('INSERT INTO usuarios (Nombre, Correo, Contraseña, tipo_usuario) VALUES (%s, %s, %s, %s)',
                    (nombre, correo, hashed_password, tipo_usuario))
        mysql.connection.commit()
        cur.close()

        flash('Usuario registrado correctamente como Alumno', 'success')
        

    return render_template('register.html')


# Ruta de cierre de sesión
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Ruta para acceder al panel de administración
@app.route('/user')
def user():
    # Verificar si el ID de administrador está en la sesión, si no, redirigir a la página principal
    if 'user_id' not in session:
        flash('Debe iniciar sesión primero', 'error')
        return redirect('/')

    #cursor para interactuar con la base de datos
    cur = mysql.connection.cursor()

    # Consultar todos los administradores en la tabla Administrador
    cur.execute('SELECT * FROM usuarios')
    usuarios = cur.fetchall()
    cur.close()

    # Obtener el nombre del administrador de la sesión si está disponible
    if 'user_nombre' in session:
        nombre = session['user_nombre']
    else:
        nombre = None

    # Renderizar la página de administración con la lista de administradores y el nombre
    return render_template('user.html', usuarios=usuarios, nombre=nombre)

# Ruta para agregar un nuevo usuario
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    # Verificar si el ID de administrador está en la sesión, si no, redirigir a la página principal
    

    # Manejar la solicitud POST para agregar un nuevo administrador
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        contraseña = request.form['contraseña']
        tipo_usuario = request.form['tipo_usuario']

        # Validar la contraseña utilizando una expresión 
        if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", contraseña):
            flash('La contraseña debe tener al menos 8 caracteres, incluyendo una letra y un número.', 'error')
            return redirect('/register')
        else:
            # Hashear la contraseña antes de almacenarla en la base de datos
            hashed_password = bcrypt.generate_password_hash(contraseña).decode('utf-8')

            #cursor para interactuar con la base de datos
            cur = mysql.connection.cursor()

            # Consultar si ya existe un administrador con el mismo correo electrónico
            cur.execute('SELECT * FROM usuarios WHERE Correo = %s', (correo,))
            administrador = cur.fetchone()

            if administrador:
                flash('El correo electrónico ya está registrado.', 'error')
                return render_template('register.html')

            # Insertar los datos del nuevo administrador en la tabla Administrador
            cur.execute('INSERT INTO usuarios (Nombre, Correo, Contraseña, tipo_usuario) VALUES (%s, %s, %s, %s)',
                        (nombre, correo, hashed_password, tipo_usuario))
            mysql.connection.commit()
            cur.close()

            flash('usuario registrado correctamente', 'success')
            return redirect('/user')

    # Si la solicitud no es POST, renderizar la página de registro
    return render_template('register.html')

# Ruta para eliminar un administrador específico
@app.route('/user/delete/<int:id>', methods=['GET', 'POST'])
def delete_user(id):
    # Verificar si el ID de administrador está en la sesión, si no, redirigir a la página principal
    if 'user_id' not in session:
        return redirect('/')

    # Verificar si se está intentando eliminar el administrador principal
    if id == session['user_id']:
        flash('No puedes eliminar al administrador principal', 'warning')
        return redirect('/usuarios')

    # cursor para interactuar con la base de datos
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM usuarios WHERE idusuarios = %s', (id,))
    usuarios = cur.fetchone()
    cur.close()

    # Verificar si el administrador existe y eliminarlo
    if usuarios:
        cur = mysql.connection.cursor()
        cur.execute('DELETE FROM usuarios WHERE idusuarios = %s', (id,))
        mysql.connection.commit()
        cur.close()

        flash('Usuario eliminado correctamente', 'success')
    else:
        flash('El Usuario no existe', 'error')

    return redirect('/user')
# Función para asignar un ícono y un color a cada tipo de mensaje flash
def get_flash_message_style(category):
    styles = {
        'success': ('fas fa-check-circle', 'success'),
        'error': ('fas fa-exclamation-circle', 'danger'),
        'info': ('fas fa-info-circle', 'info'),
        'warning': ('fas fa-exclamation-triangle', 'warning')
    }
    return styles.get(category, ('', 'secondary'))
# Registrar la función en el contexto de la plantilla
app.add_template_global(get_flash_message_style, name='get_flash_message_style')

@app.route('/registrar_vacantes')
def registrar_vacantes():
    return render_template('registrar_vacante.html')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ruta=app.config['UPLOAD_FOLDER']='./app/static/img/uploads/vacantes'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/registrar_vacante', methods=['GET', 'POST'])
def registrar_vacante():
    if request.method == 'POST':
        titulo = request.form['titulo']
        empresa = request.form['empresa']
        descripcion = request.form['descripcion']
        file=request.files['Imagen_vacante']

        if file and allowed_file(file.filename):
            # Verificar si el archivo con el mismo nombre ya existe
            # Creamos un nombre dinamico para la foto de perfil con el nombre y el numero de empleado
            filename = "img" + titulo + "_" + empresa + "_" + secure_filename(file.filename)
            file_path = os.path.join(ruta, filename)
            if os.path.exists(file_path):
                flash('Advertencia: ¡Un archivo con el mismo nombre ya existe!')
            
            # Guardar el archivo y registrar en la base de datos
            file.save(file_path)
        else:
            flash('Error: ¡Extensión de archivo invalida!')

            return redirect(url_for('Ver'))

        # Guardar los datos en la base de datos (ajusta los nombres de tablas y campos)
        cur = mysql.connection.cursor()
        cur.execute('INSERT INTO vacantes (carrera, puesto, año, imagen_vacante) VALUES (%s, %s, %s, %s)',
                    (titulo, empresa, descripcion, filename))
        mysql.connection.commit()
        cur.close()

        flash('Vacante registrada correctamente', 'success')
    return redirect('/admin')
 

if __name__ == '__main__':
     app.run(debug=True)