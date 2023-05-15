from flask import Flask, render_template, request, url_for, redirect, flash
import pandas as pd
import sqlite3
import json
import csv
import matplotlib.pyplot as plt
import requests
from sklearn.ensemble import RandomForestClassifier
from werkzeug.security import generate_password_hash, check_password_hash
from sklearn import datasets, linear_model
from sklearn.metrics import mean_squared_error, r2_score, confusion_matrix
from sklearn.tree import DecisionTreeClassifier, export_graphviz
import graphviz

con = sqlite3.connect('p1.db')

cursor = con.cursor()

with open('devices.json') as f:
    datos = json.load(f)

cursor.execute("DROP TABLE IF  EXISTS analisis")
cursor.execute("DROP TABLE IF  EXISTS dispositivo")
cursor.execute("DROP TABLE IF  EXISTS responsable")
cursor.execute("DROP TABLE IF  EXISTS alerta")

cursor.execute('PRAGMA foreign_keys = ON')

con.commit()

cursor.execute("CREATE TABLE IF NOT EXISTS analisis (id integer primary key AUTOINCREMENT, dispositivo text, servicios integer not null, "
               "servicios_inseguros integer not null, vulnerabilidades_detectadas integer not null, "
               "FOREIGN KEY (dispositivo) REFERENCES dispositivo(id))")
cursor.execute("CREATE TABLE IF NOT EXISTS responsable (nombre text primary key, tlf integer, rol text )")
cursor.execute("CREATE TABLE IF NOT EXISTS dispositivo (id text primary key, ip text not null, localizacion text, responsable text, "
               "FOREIGN KEY(responsable) REFERENCES responsable(nombre))")
cursor.execute("CREATE TABLE IF NOT EXISTS alerta (id integer primary key AUTOINCREMENT,fecha_hora text not null,sid integer not null,msg text not null,"
               "clasificacion text not null,prioridad text not null,protocolo text not null,origen text not null,destino text not null,puerto integer not null)")
con.commit()

i = 1
## INSERTAMOS LOS DATOS
for objeto in datos:

    ## TABLA RESPONSABLE
    nombre_responsable = objeto['responsable']['nombre']
    tlf_responsable = objeto['responsable']['telefono']
    if tlf_responsable == "None":
        tlf_responsable = None
    rol_responsable = objeto['responsable']['rol']
    if rol_responsable == "None":
        rol_responsable = None
    cursor.execute("INSERT OR IGNORE INTO responsable VALUES (?, ?, ?)", (nombre_responsable, tlf_responsable, rol_responsable))

    ## TABLA DISPOSITIVO
    id_dispositivo = objeto['id']
    ip_dispositivo = objeto['ip']
    localizacion_dispositivo = objeto['localizacion']
    if localizacion_dispositivo == "None":
        localizacion_dispositivo = None
    cursor.execute("INSERT INTO dispositivo VALUES (?, ?, ?, ?)", (id_dispositivo, ip_dispositivo, localizacion_dispositivo, nombre_responsable))

    ## TABLA ANALISIS
    id_analisis= i
    servicio_normal=objeto["analisis"]["servicios"]
    servicio_inseguro= objeto["analisis"]["servicios_inseguros"]
    vulnerabilidad_detectada=objeto["analisis"]["vulnerabilidades_detectadas"]
    cursor.execute("INSERT INTO analisis(dispositivo, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?)",
                   (id_dispositivo, servicio_normal, servicio_inseguro, vulnerabilidad_detectada))

# IMPORTAMOS EL CSV
with open('alerts.csv', 'r') as csvfile:
    csvreader = csv.reader(csvfile)
    next(csvreader, None)
    for row in csvreader:
        cursor.execute('INSERT INTO alerta (fecha_hora, sid, msg, clasificacion, prioridad, protocolo, origen, destino, puerto) '
                       'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', row)

    con.commit()

con.close()

'''
##############################################################
TRATAMIENTO DE USUARIOS
##############################################################
'''
def usuarios_bd():
    con = sqlite3.connect('p1.db')
    cursor = con.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL)")
    con.close()

import sqlite3

def insert_usuarios(username, passwd):
    con = sqlite3.connect('p1.db')
    cursor = con.cursor()

    # Consultar si el usuario ya existe en la base de datos
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    resultado = cursor.fetchone()

    if resultado is None:
        # El usuario no existe, se puede insertar
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, passwd))
        con.commit()
        resultado = True
    else:
        # El usuario ya existe, no se realiza la inserción
        resultado = False

    con.close()
    return resultado


def check(username, passwd):
    con = sqlite3.connect('p1.db')
    cursor = con.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    resultado = cursor.fetchone()
    con.commit()
    con.close()
    if resultado:
        return True
    else:
        return False

'''
##############################################################
REGRESION LINEAL
##############################################################
'''

with open('devices_IA_clases.json') as f:
    dispositivos_train = json.load(f)

with open('devices_IA_predecir_v2.json') as f:
    dispositivos_predict = json.load(f)

dispositivos_x_train = []
dispositivos_y_train = []
dispositivos_y_predict = []
dispositivos_x_predict = []

for dispositivo in dispositivos_train:
    dispositivos_x_train.append([dispositivo['servicios_inseguros']])
    dispositivos_y_train.append(dispositivo['peligroso'])

for dispositivo in dispositivos_predict:
    dispositivos_x_predict.append([dispositivo['servicios_inseguros']])
    dispositivos_y_predict.append(dispositivo['peligroso'])

# Create linear regression object
regr = linear_model.LinearRegression()
# Train the model using the training sets
regr.fit(dispositivos_x_train, dispositivos_y_train)
# Make predictions using the testing set
dispositivos_y_pred = regr.predict(dispositivos_x_predict)
# The mean squared error
print("Mean squared error: %.2f" % mean_squared_error(dispositivos_y_predict, dispositivos_y_pred))

# Plot outputs
plt.title("Regresion lineal")
plt.xlabel("Servicios inseguros")
plt.ylabel("¿Es peligroso?")
plt.scatter(dispositivos_x_predict, dispositivos_y_predict, color="black")
plt.plot(dispositivos_x_predict, dispositivos_y_pred, color="blue", linewidth=3)
plt.xticks(())
plt.yticks(())
plt.savefig('static/regresion_lineal.png')


'''
##############################################################
DECISION TREE
##############################################################
'''
'''
with open('devices_IA_clases.json') as f:
    dispositivos_train = json.load(f)

with open('devices_IA_predecir_v2.json') as f:
    dispositivos_predict = json.load(f)

# Convertir los datos en un DataFrame de Pandas
df_train = pd.DataFrame(dispositivos_train)
df_predict = pd.DataFrame(dispositivos_predict)

# Seleccionar las columnas relevantes
X_train = df_train[['servicios', 'servicios_inseguros']]
y_train = df_train['peligroso']
X_predict = df_predict[['servicios', 'servicios_inseguros']]

# Crear el clasificador de árbol de decisión
tree = DecisionTreeClassifier()
tree.fit(X_train, y_train)

# Generar el grafo del árbol de decisión y guardarlo en una imagen
dot_data = export_graphviz(tree, out_file=None,
                           feature_names=['servicios', 'servicios_inseguros'],
                           class_names=['No peligroso', 'Peligroso'],
                           filled=True, rounded=True,
                           special_characters=True)
graph = graphviz.Source(dot_data)
graph.format = 'png'
graph.render('static/tree')

'''




'''
##############################################################
RANDOM FOREST
##############################################################
'''
'''

# Convert data to pandas DataFrame
df_train = pd.DataFrame(dispositivos_train)
df_predict = pd.DataFrame(dispositivos_predict)

df_train = df_train.drop('id', axis=1)
df_predict = df_predict.drop('id', axis=1)

# Split features and labels
X_train = df_train.drop('peligroso', axis=1)
y_train = df_train['peligroso']
X_predict = df_predict.drop('peligroso', axis=1)
y_predict = df_predict['peligroso']

# Create random forest classifier
rf = RandomForestClassifier(max_depth=2, random_state=0,n_estimators=10)

# Fit the model to the training data
rf.fit(X_train, y_train)

# Make predictions using the test data
y_pred = rf.predict(X_predict)

# Print the confusion matrix
cm = confusion_matrix(y_predict, y_pred)
print(cm)

# Generate a diagram of the first tree in the forest
dot_data = export_graphviz(rf.estimators_[0], out_file=None,
                           feature_names=X_train.columns,
                           class_names=['no_peligroso', 'peligroso'],
                           filled=True, rounded=True, special_characters=True)
graph = graphviz.Source(dot_data)
graph.format = 'png'
graph.render('static/forest')


'''


app = Flask(__name__)
'''
##############################################################
PRIMERA PAGINA Y HOME (HTML CON ENLACES)
##############################################################
'''
@app.route('/',methods=["GET", "POST"])
def index():
    usuarios_bd()
    return render_template('loggin.html')

@app.route('/home', methods=["GET", "POST"])
def home():
    return render_template('home.html')

'''
##############################################################
LO RELACIONADO CON EL LOGIN
##############################################################
'''
@app.route('/login', methods=['POST', 'GET'])
def login():
    username = ''
    hashed_password = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

    resultado = check(username, hashed_password)

    if resultado:
        # usuario encontrado en la base de datos, iniciar sesión
        return render_template('home.html')
    else:
        # usuario no encontrado en la base de datos, mostrar mensaje de error
        return render_template('loggin.html')


@app.route('/registro', methods=['POST', "GET"])
def registro():
    return render_template("registro.html")

@app.route('/signup', methods=['POST', "GET"])
def signup():
    username = request.form['username']
    password = request.form['password']
    hashed_password = generate_password_hash(password)

    resultado= insert_usuarios(username, hashed_password)

    if resultado is True:
        return render_template('success.html')
    else:
        return render_template("logginMensaje.html")

'''
##############################################################
ENLACES QUE REDIRECCIONAN A LAS GRAFICAS Y AL CUADRO DE MANDOS
##############################################################
'''

@app.route('/numeroIPsInsertar/', methods=["GET", "POST"])
def numeroIPsInsertar():
    return render_template("numeroIPs.html")
@app.route('/top_ips/', methods=["GET", "POST"])
def top_ips():
    if request.method == 'POST':
        cantidad = int(request.form.get('cantidad'))
        if cantidad <= 0:
            flash('Ingrese un número mayor a 0.')
            return redirect('/top_ips/')
        con = sqlite3.connect("p1.db")
        cursor = con.cursor()
        cursor.execute(
            f"SELECT origen, COUNT(*) AS total_alertas FROM alerta WHERE prioridad = 1 GROUP BY origen ORDER BY total_alertas DESC LIMIT {cantidad}")
        ips = cursor.fetchall()
        con.close()
        x_values = [i[0] for i in ips]
        y_values = [i[1] for i in ips]
        plt.figure(figsize=(17, 6))
        plt.bar(x_values, y_values)
        plt.title("Top IPs más problemáticas")
        plt.xlabel("IPs")
        plt.ylabel("Número de alertas")
        plt.savefig("static/top_ips.png")
        return render_template('top_ips.html', ips=ips)
    return render_template('top_ips.html')


@app.route('/numeroDispositivoInsertar/', methods=["GET", "POST"])
def numeroDispositivoInsertar():
    return render_template("numeroDispositivo.html")
@app.route('/top_dispositivos/', methods=["GET", "POST"])
def top_dispositivos():
    if request.method == 'POST':
        cantidad = int(request.form.get('cantidad'))
        if cantidad <= 0:
            flash('Ingrese un número mayor a 0.')
            return redirect('/top_dispositivos/')
        con = sqlite3.connect("p1.db")
        cursor = con.cursor()
        cursor.execute(
            "SELECT dispositivo, servicios_inseguros + vulnerabilidades_detectadas AS servicios_vulnerables FROM analisis GROUP BY dispositivo ORDER BY servicios_vulnerables DESC LIMIT ?", (cantidad,))
        dispositivos = cursor.fetchall()
        con.close()
        # Convertir la lista de tuplas en dos listas separadas para usarlas en el gráfico
        x_values = [i[0] for i in dispositivos]
        y_values = [i[1] for i in dispositivos]
        # Crear el gráfico de barras
        plt.figure(figsize=(9, 6))
        plt.bar(x_values, y_values)
        # Agregar etiquetas al gráfico
        plt.title("Top {} dispositivos más vulnerables".format(cantidad))
        plt.xlabel("Dispositivos")
        plt.ylabel("Número de vulnerabilidades")
        # Guardar el gráfico en un archivo
        plt.savefig("static/top_dispositivos.png")
        return render_template('top_dispositivos.html')
    else:
        return render_template('numeroDispositivo.html')

@app.route('/numeroPeligrosoInsertar/', methods=["GET", "POST"])
def numeroPeligrosoInsertar():
    return render_template("numeroPeligroso.html")
@app.route('/top_peligrosos/', methods=["GET", "POST"])
def top_peligrosos():
    if request.method == 'POST':
        cantidad = int(request.form.get('cantidad'))
        if cantidad <= 0:
            flash('Ingrese un número mayor a 0.')
            return redirect('/top_peligrosos/')
        con = sqlite3.connect("p1.db")
        cursor = con.cursor()
        cursor.execute(
            "SELECT dispositivo, servicios_inseguros FROM analisis WHERE servicios_inseguros > (servicios / 3) GROUP BY dispositivo ORDER BY servicios_inseguros DESC LIMIT ?", (cantidad,))
        dispositivos = cursor.fetchall()
        con.close()

        # Convertir la lista de tuplas en dos listas separadas para usarlas en el gráfico
        x_values = [i[0] for i in dispositivos]
        y_values = [i[1] for i in dispositivos]

        # Crear el gráfico de barras
        plt.figure(figsize=(9, 6))
        plt.bar(x_values, y_values)

        # Agregar etiquetas al gráfico
        plt.title("Dispositivos más peligrosos")
        plt.xlabel("Dispositivos")
        plt.ylabel("Número de servicios inseguros")

        # Guardar el gráfico en un archivo
        plt.savefig("static/top_peligrosos.png")

        return render_template('top_peligrosos.html')
    else:
        return render_template('numeroPeligroso.html')



@app.route('/ultimas_vulnerabilidades/', methods=["GET", "POST"])
def ultimas_vulnerabilidades():
    # Hacer una solicitud HTTP a la API de cve-search.org
    response = requests.get('https://cve.circl.lu/api/last')

    # Procesar los datos JSON que devuelve la API
    if response.status_code == 200:
        data = response.json()
        vulnerabilidades = []
        for i in range(10):
            vuln = {}
            vuln['id'] = data[i]['id']
            vuln['descripcion'] = data[i]['summary']
            vuln['fecha'] = data[i]['Published']
            vulnerabilidades.append(vuln)
        return render_template('ultimas_vulnerabilidades.html', vulnerabilidades=vulnerabilidades)
    else:
        return 'No se pudo obtener los datos de la API de cve-search.org'

@app.route('/cmi',methods=["GET", "POST"])
def cmi():
    return render_template('cmi.html')

if __name__ == '__main__':
    app.run(debug=True)
