from flask import Flask, render_template

# Creamos la aplicación Flask
app = Flask(__name__)
# Nota: La configuración de la base de datos iría aquí, pero la pondremos después.

@app.route('/')
def index():
    """Ruta para la página de inicio."""
    # Render_template busca el archivo index.html dentro de la carpeta 'templates'
    return render_template('index.html')

# Esto es necesario para que el programa se ejecute localmente durante el desarrollo
if __name__ == '__main__':
    # Ejecuta la aplicación en modo debug para ver errores fácilmente
    app.run(debug=True)