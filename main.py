from flask import Flask, render_template
import sqlite3
import json
import csv

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

@app.route('/top_ips/<int:x>', methods=["GET", "POST"])
def top_ips(x):
    con = sqlite3.connect("p1.db")
    cursor = con.cursor()
    cursor.execute(
        "SELECT origen, COUNT(*) AS total_alertas FROM alerta GROUP BY origen ORDER BY total_alertas DESC LIMIT ?", (x,))
    ips = cursor.fetchall()
    con.close()
    return render_template('top_ips.html', ips=ips, x=x)



if __name__ == '__main__':
    app.run(debug=True)

