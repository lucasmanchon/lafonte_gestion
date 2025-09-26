from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from functools import wraps
from sqlalchemy import func # Necesario para algunas consultas avanzadas (como COUNT)

# --- Configuración Inicial de Flask ---
app = Flask(__name__)
app.secret_key = 'una_clave_secreta_muy_larga_y_unica_para_la_fonte_2025' 

# --- Configuración de Base de Datos (SQLAlchemy) ---
# Usamos SQLite (el archivo se llamará lafonte.db)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lafonte.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db) # Inicializa el motor de migración Alembic

# --- Modelos de Base de Datos (Clases Python que representan las Tablas) ---

# ROL: 'admin', 'manager', 'read_only', 'common'
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    role = db.Column(db.String(20), nullable=False, default='common')
    is_active = db.Column(db.Integer, default=1)
    
    # Relación muchos a muchos con Sucursales
    branches = db.relationship('Branch', secondary='user_branches', 
                               backref=db.backref('users', lazy='dynamic'))

# Tabla intermedia para la relación M:M (Usuarios a Sucursales)
user_branches = db.Table('user_branches',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('branch_id', db.Integer, db.ForeignKey('branch.id', ondelete='CASCADE'), primary_key=True)
)

class Branch(db.Model):
    __tablename__ = 'branch'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.String(200))
    city = db.Column(db.String(80))
    is_active = db.Column(db.Integer, default=1) # 1: Activa, 0: Desactivada
    
# ... (Código existente de la clase Branch) ...

class Employee(db.Model):
    __tablename__ = 'employee'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    dni = db.Column(db.String(20), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True)
    hiring_date = db.Column(db.Date) # Fecha de Contratación
    is_active = db.Column(db.Integer, default=1)
    
    # Clave Foránea: Un empleado pertenece a una única sucursal principal
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'))
    # Relación: Permite acceder a los datos de la sucursal del empleado (e.g., employee.branch.name)
    branch = db.relationship('Branch')

# --- Funciones Auxiliares ---

def create_initial_data():
    """Crea el usuario administrador si no existe."""
    # Nota: Esta función SOLO se llama después de que las tablas han sido creadas (db upgrade)
    if db.session.query(User).filter(User.username == 'admin').first() is None:
        admin_user = User(username='admin', password='123', first_name='Super', last_name='Admin', role='admin', is_active=1)
        db.session.add(admin_user)
        db.session.commit()
        
        # Asignar la primera sucursal que exista al admin
        first_branch = db.session.query(Branch).first()
        if first_branch:
            admin_user.branches.append(first_branch)
            db.session.commit()
        print("Usuario inicial 'admin' (pass: 123) registrado.")

# --- Decoradores y Rutas de Autenticación (Se mantienen) ---

def requires_manager(f):
    """Decorador para restringir el acceso solo a usuarios con rol 'manager' o 'admin'."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
             return redirect(url_for('login'))
        # Permite acceder si el rol es manager O admin
        if session.get('role') not in ['admin', 'manager']:
            return redirect(url_for('index')) 
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Uso de SQLAlchemy para buscar el usuario (activo)
        user = db.session.query(User).filter(
            User.username == username, 
            User.password == password, 
            User.is_active == 1
        ).first()

        if user:
            session['logged_in'] = True
            session['user_id'] = user.id # Guardamos el ID por si lo necesitamos
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('index'))
        else:
            error = 'Usuario, contraseña o estado inactivo inválido.'
            return render_template('login.html', error=error)
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

# ------------------ RUTAS PRINCIPALES ------------------

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'], role=session['role'])

# ------------------ RUTAS DEL MÓDULO SUCURSALES ------------------

@app.route('/branches')
@requires_manager
def manage_branches():
    branches = db.session.query(Branch).order_by(Branch.name).all()
    return render_template('branches_list.html', branches=branches)

@app.route('/branches/add', methods=['GET', 'POST'])
@requires_manager
def add_branch():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        city = request.form['city']
        
        # Verificar duplicado
        if db.session.query(Branch).filter(Branch.name == name).first():
            error = "El nombre de la sucursal ya existe."
            return render_template('branch_form.html', form_title='Añadir Nueva Sucursal', error=error)
            
        new_branch = Branch(name=name, address=address, city=city, is_active=1)
        db.session.add(new_branch)
        db.session.commit()
        
        # Asignar la sucursal recién creada al admin, si es necesario
        if db.session.query(Branch).count() == 1:
            admin_user = db.session.query(User).filter(User.username == 'admin').first()
            if admin_user:
                admin_user.branches.append(new_branch)
                db.session.commit()
                
        return redirect(url_for('manage_branches'))
            
    return render_template('branch_form.html', form_title='Añadir Nueva Sucursal')

@app.route('/branches/edit/<int:branch_id>', methods=['GET', 'POST'])
@requires_manager
def edit_branch(branch_id):
    branch = db.session.query(Branch).get_or_404(branch_id)

    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        city = request.form['city']
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        
        # Verificar duplicado excluyendo la sucursal actual
        if db.session.query(Branch).filter(Branch.name == name, Branch.id != branch_id).first():
            error = "El nombre de la sucursal ya existe."
            return render_template('branch_form.html', branch=branch, form_title='Editar Sucursal', error=error)

        branch.name = name
        branch.address = address
        branch.city = city
        branch.is_active = is_active
        
        db.session.commit()
        return redirect(url_for('manage_branches'))

    return render_template('branch_form.html', branch=branch, form_title='Editar Sucursal')

@app.route('/branches/delete/<int:branch_id>')
@requires_manager
def delete_branch_route(branch_id):
    branch = db.session.query(Branch).get_or_404(branch_id)
    
    # Lógica de "borrado seguro": Si tiene usuarios asignados, no se borra, solo se desactiva.
    if branch.users.count() > 0: 
        branch.is_active = 0 
        db.session.commit()
        flash('La sucursal se ha DESACTIVADO porque tiene usuarios asignados.', 'warning')
    else:
        db.session.delete(branch) 
        db.session.commit()
        flash('La sucursal ha sido BORRADA.', 'success')
            
    return redirect(url_for('manage_branches'))

# ------------------ RUTAS DEL MÓDULO USUARIOS ------------------

@app.route('/users')
@requires_manager
def manage_users():
    users = db.session.query(User).order_by(User.last_name).all()
    return render_template('users_list.html', users=users)

@app.route('/users/form', defaults={'user_id': None}, methods=['GET', 'POST'])
@app.route('/users/form/<int:user_id>', methods=['GET', 'POST'])
@requires_manager
def user_form(user_id):
    user = None
    if user_id:
        user = db.session.query(User).get_or_404(user_id)
        
    all_branches = db.session.query(Branch).filter(Branch.is_active == 1).order_by(Branch.name).all()

    if request.method == 'POST':
        # 1. Recoger datos
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        role = request.form['role']
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        selected_branch_ids = [int(id) for id in request.form.getlist('branch_id')]
        
        # 2. Validación de Contraseña
        if user_id is None and not password:
             error = "La contraseña es obligatoria para nuevos usuarios."
             return render_template('user_form.html', form_title='Añadir Nuevo Usuario', all_branches=all_branches, error=error)
             
        # 3. Validación de Nombre de Usuario Duplicado
        if db.session.query(User).filter(User.username == username, User.id != user_id).first():
            error = "Error: El nombre de usuario ya está en uso."
            return render_template('user_form.html', form_title='Añadir Nuevo Usuario', user=user, all_branches=all_branches, error=error)
            
        # 4. Crear o Actualizar
        if user is None:
            user = User(username=username, password=password, first_name=first_name, last_name=last_name, role=role, is_active=is_active)
            db.session.add(user)
        else:
            user.username = username
            if password: user.password = password
            user.first_name = first_name
            user.last_name = last_name
            user.role = role
            user.is_active = is_active
            
        db.session.commit()
        
        # 5. Actualizar Asignaciones de Sucursales
        user.branches = db.session.query(Branch).filter(Branch.id.in_(selected_branch_ids)).all()
        db.session.commit()
        
        return redirect(url_for('manage_users'))

    form_title = "Editar Usuario" if user_id else "Añadir Nuevo Usuario"
    return render_template('user_form.html', form_title=form_title, user=user, all_branches=all_branches)

@app.route('/users/deactivate/<int:user_id>')
@requires_manager
def deactivate_user_route(user_id):
    user = db.session.query(User).get_or_404(user_id)
    user.is_active = 0
    db.session.commit()
    return redirect(url_for('manage_users'))

# --- Ejecución y Datos Iniciales CORREGIDA (SOLUCIÓN) ---

# ------------------ RUTAS DEL MÓDULO EMPLEADOS ------------------

@app.route('/employees')
@requires_manager
def manage_employees():
    """Muestra la lista de empleados."""
    # Obtenemos empleados y sus sucursales relacionadas
    employees = db.session.query(Employee).order_by(Employee.last_name).all()
    return render_template('employees_list.html', employees=employees)

@app.route('/employees/form', defaults={'employee_id': None}, methods=['GET', 'POST'])
@app.route('/employees/form/<int:employee_id>', methods=['GET', 'POST'])
@requires_manager
def employee_form(employee_id):
    """Permite crear o editar un empleado."""
    employee = None
    if employee_id:
        employee = db.session.query(Employee).get_or_404(employee_id)
        
    # Obtenemos todas las sucursales activas para el campo de selección
    active_branches = db.session.query(Branch).filter(Branch.is_active == 1).order_by(Branch.name).all()

    if request.method == 'POST':
        # 1. Recoger datos
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dni = request.form['dni']
        phone = request.form['phone']
        email = request.form['email']
        hiring_date = request.form['hiring_date']
        branch_id = request.form['branch_id']
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        
        # 2. Validación de DNI Duplicado
        if db.session.query(Employee).filter(Employee.dni == dni, Employee.id != employee_id).first():
            error = "Error: El DNI ya está registrado en el sistema."
            return render_template('employee_form.html', form_title='Formulario de Empleado', employee=employee, active_branches=active_branches, error=error)
            
        # 3. Crear o Actualizar
        if employee is None:
            employee = Employee(
                first_name=first_name, last_name=last_name, dni=dni, phone=phone, email=email, 
                hiring_date=hiring_date, branch_id=branch_id, is_active=is_active
            )
            db.session.add(employee)
        else:
            employee.first_name = first_name
            employee.last_name = last_name
            employee.dni = dni
            employee.phone = phone
            employee.email = email
            employee.hiring_date = hiring_date
            employee.branch_id = branch_id
            employee.is_active = is_active
            
        db.session.commit()
        return redirect(url_for('manage_employees'))

    form_title = "Editar Empleado" if employee_id else "Añadir Nuevo Empleado"
    return render_template('employee_form.html', form_title=form_title, employee=employee, active_branches=active_branches)

@app.route('/employees/deactivate/<int:employee_id>')
@requires_manager
def deactivate_employee_route(employee_id):
    """Desactiva un empleado (borrado seguro)."""
    employee = db.session.query(Employee).get_or_404(employee_id)
    
    # Lógica de "desactivar" para no perder historial
    employee.is_active = 0
    db.session.commit()
    flash(f'El empleado {employee.first_name} {employee.last_name} ha sido DESACTIVADO.', 'warning')
    return redirect(url_for('manage_employees'))

if __name__ == '__main__':
    with app.app_context():
        # Los datos iniciales SÓLO se crean cuando iniciamos el servidor principal,
        # NO cuando ejecutamos los comandos de migración como 'flask db init'.
        create_initial_data() 
        
    app.run(debug=True)