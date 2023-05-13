from flask import Flask, render_template, request, url_for, redirect
import sqlite3

def usuarios_bd():
    con = sqlite3.connect('p1.db')
    cursor = con.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,password TEXT NOT NULL)")
    con.close()

def insert_usuarios(username, passwd):
    con = sqlite3.connect('p1.db')
    cursor = con.cursor()
    cursor.execute(
        "INSERT INTO users(username,password) VALUES (?, ?)", username, passwd)
    con.commit()
    con.close()

def check(username, passwd):
    con = sqlite3.connect('p1.db')
    cursor = con.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE nombre_usuario = ? AND contrasena = ?', (username, passwd))
    resultado = cursor.fetchone()
    return resultado
    con.commit()
    con.close()


