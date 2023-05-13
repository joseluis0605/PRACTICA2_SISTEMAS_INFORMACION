from flask import Flask, render_template, request, url_for, redirect
import sqlite3
import json
import csv
import matplotlib.pyplot as plt
import requests

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

app = Flask(__name__)



@app.route('/',methods=["GET", "POST"])
def index():
    return render_template('loggin.html')

@app.route('/home', methods=["GET", "POST"])
def home():
    return render_template('home.html')


@app.route('/login', methods=['POST'])
def login():
    '''
    username = request.form['username']
    password = request.form['password']

    '''


    # Aquí deberías agregar la lógica de autenticación
    # Si las credenciales son válidas, redirecciona al usuario a una página de éxito
    # Si no son válidas, muestra un mensaje de error

    return render_template('home.html')


@app.route('/top_ips/', methods=["GET", "POST"])
def top_ips():
    con = sqlite3.connect("p1.db")
    cursor = con.cursor()
    cursor.execute(
        "SELECT origen, COUNT(*) AS total_alertas FROM alerta WHERE prioridad = 1 GROUP BY origen ORDER BY total_alertas DESC LIMIT 10")
    ips = cursor.fetchall()
    con.close()

    # Convertir la lista de tuplas en dos listas separadas para usarlas en el gráfico
    x_values = [i[0] for i in ips]
    y_values = [i[1] for i in ips]

    # Crear el gráfico de barras
    plt.figure(figsize=(17, 6))
    plt.bar(x_values, y_values)

    # Agregar etiquetas al gráfico
    plt.title("Top 10 IPs más problemáticas")
    plt.xlabel("IPs")
    plt.ylabel("Número de alertas")

    # Guardar el gráfico en un archivo
    plt.savefig("static/top_ips.png")

    return render_template('top_ips.html', ips=ips)

@app.route('/top_dispositivos/', methods=["GET", "POST"])
def top_dispositivos():
    con = sqlite3.connect("p1.db")
    cursor = con.cursor()
    cursor.execute(
        "SELECT dispositivo, servicios_inseguros + vulnerabilidades_detectadas AS servicios_vulnerables FROM analisis DESC LIMIT 10")
    dispositivos = cursor.fetchall()
    con.close()

    # Convertir la lista de tuplas en dos listas separadas para usarlas en el gráfico
    x_values = [i[0] for i in dispositivos]
    y_values = [i[1] for i in dispositivos]

    # Crear el gráfico de barras
    plt.figure(figsize=(9, 6))
    plt.bar(x_values, y_values)

    # Agregar etiquetas al gráfico
    plt.title("Top 10 dispositivos más vulnerables")
    plt.xlabel("Dispositivos")
    plt.ylabel("Número de vulnerabilidades")

    # Guardar el gráfico en un archivo
    plt.savefig("static/top_dispositivos.png")

    return render_template('top_dispositivos.html', dispositivos=dispositivos)

@app.route('/top_peligrosos/', methods=["GET", "POST"])
def top_peligrosos():
    con = sqlite3.connect("p1.db")
    cursor = con.cursor()
    cursor.execute(
        "SELECT dispositivo, servicios_inseguros FROM analisis WHERE servicios_inseguros > (servicios / 3) LIMIT 7")
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

    return render_template('top_peligrosos.html', dispositivos=dispositivos)


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

if __name__ == '__main__':
    app.run(debug=True)

