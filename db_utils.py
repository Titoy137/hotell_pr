import mysql.connector
from tkinter import messagebox

def connect_db():
    """Подключение к базе данных"""
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            database='hotelmanagement',
            user='root',
            password='12345'
        )
        return connection
    except mysql.connector.Error as e:
        messagebox.showerror("Ошибка", f"Ошибка подключения к базе данных: {e}")
        return None

def close_db(connection):
    """Закрытие соединения с базой данных"""
    if connection and connection.is_connected():
        connection.close()