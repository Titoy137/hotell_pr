import tkinter as tk
from tkinter import messagebox, ttk
import mysql.connector
from mysql.connector import Error
import hashlib
import logging

# Настройка логирования для отладки и отслеживания ошибок
logging.basicConfig(filename='hotel_management.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class DatabaseConnection:
    """Класс для работы с подключением к БД"""

    @staticmethod
    def connect():
        try:
            connection = mysql.connector.connect(
                host='127.0.0.1',
                database='hotelmanagement',
                user='root',
                password='12345'
            )
            logging.info("Успешное подключение к базе данных")
            return connection
        except Error as e:
            logging.error(f"Ошибка подключения к базе данных: {e}")
            messagebox.showerror("Ошибка", "Не удалось подключиться к базе данных. Проверьте настройки.")
            return None


class PasswordManager:
    """Класс для работы с паролями"""

    @staticmethod
    def hash_password(password):
        if not isinstance(password, str):
            logging.warning("Пароль не является строкой, преобразование в строку")
            password = str(password)
        return hashlib.sha256(password.encode('utf-8')).hexdigest()


class HotelManagementApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hotel Management")
        self.root.minsize(400, 300)
        self.root.maxsize(600, 500)
        self.root.configure(bg='#f0f0f0')

        self.user_id = None
        self.user_role = None

        self.setup_style()
        self.show_login_screen()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)  # Обработка закрытия окна
        self.root.mainloop()

    def setup_style(self):
        """Настройка стиля приложения"""
        try:
            self.style = ttk.Style()
            self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
            self.style.configure('TButton', font=('Arial', 10))
            self.style.configure('TEntry', font=('Arial', 10))
            self.style.configure('Treeview', font=('Arial', 10))
            self.style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
        except Exception as e:
            logging.error(f"Ошибка настройки стилей: {e}")
            messagebox.showerror("Ошибка", "Не удалось настроить интерфейс приложения.")

    def clear_window(self):
        """Очистка окна от текущего контента"""
        try:
            for widget in self.root.winfo_children():
                widget.destroy()
        except Exception as e:
            logging.error(f"Ошибка при очистке окна: {e}")

    def on_closing(self):
        """Обработка закрытия приложения"""
        if messagebox.askokcancel("Выход", "Вы действительно хотите выйти?"):
            logging.info("Приложение закрыто пользователем")
            self.root.destroy()

    def show_login_screen(self):
        """Отображение экрана авторизации"""
        self.clear_window()

        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.pack(expand=True)

        ttk.Label(login_frame, text="Логин:").grid(row=0, column=0, pady=10, padx=5, sticky="e")
        self.entry_username = ttk.Entry(login_frame)
        self.entry_username.grid(row=0, column=1, pady=10, padx=5)
        self.entry_username.focus_set()

        ttk.Label(login_frame, text="Пароль:").grid(row=1, column=0, pady=10, padx=5, sticky="e")
        self.entry_password = ttk.Entry(login_frame, show="*")
        self.entry_password.grid(row=1, column=1, pady=10, padx=5)

        ttk.Button(login_frame, text="Войти", command=self.login).grid(row=2, column=0, columnspan=2, pady=15)

    def login(self):
        """Обработка входа пользователя"""
        username = self.entry_username.get().strip() if self.entry_username.get() else ""
        password = self.entry_password.get() if self.entry_password.get() else ""

        if not username or not password:
            messagebox.showwarning("Предупреждение", "Все поля должны быть заполнены")
            return

        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                if not user:
                    messagebox.showerror("Ошибка", "Пользователь не найден")
                    return

                if user['locked'] == 1:
                    messagebox.showerror("Ошибка", "Аккаунт заблокирован. Обратитесь к администратору")
                    return

                if user['failed_attempts'] >= 3:
                    messagebox.showerror("Ошибка", "Аккаунт заблокирован из-за превышения попыток входа")
                    return

                if PasswordManager.hash_password(password) == user['password']:
                    cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = %s", (username,))
                    connection.commit()
                    messagebox.showinfo("Успех", "Авторизация прошла успешно")
                    self.user_id = user['id']
                    self.user_role = user['role']
                    logging.info(f"Пользователь {username} вошел в систему с ролью {self.user_role}")
                    if user['role'] == 'Admin':
                        self.show_admin_dashboard()
                    else:
                        self.show_user_dashboard()
                else:
                    cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = %s",
                                   (username,))
                    connection.commit()
                    messagebox.showerror("Ошибка", "Неверный логин или пароль")
                    logging.warning(f"Неудачная попытка входа для {username}")
        except Error as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка базы данных: {e}")
            logging.error(f"Ошибка при авторизации: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при входе")
            logging.error(f"Непредвиденная ошибка при авторизации: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def show_admin_dashboard(self):
        """Отображение панели администратора"""
        self.clear_window()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True)

        ttk.Label(main_frame, text="Панель администратора", font=('Arial', 12, 'bold')).pack(pady=10)
        ttk.Button(main_frame, text="Добавить пользователя",
                   command=self.show_add_user_screen).pack(pady=10)
        ttk.Button(main_frame, text="Сменить пароль",
                   command=self.show_change_password_screen).pack(pady=10)
        ttk.Button(main_frame, text="Управление пользователями",
                   command=self.show_user_management_screen).pack(pady=10)
        ttk.Button(main_frame, text="Просмотр комментариев",
                   command=self.show_comments_screen).pack(pady=10)
        ttk.Button(main_frame, text="Выйти",
                   command=self.logout).pack(pady=10)

    def show_user_dashboard(self):
        """Отображение панели пользователя"""
        self.clear_window()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True)

        ttk.Label(main_frame, text="Добро пожаловать в систему!",
                  font=('Arial', 12, 'bold')).pack(pady=20)
        ttk.Button(main_frame, text="Сменить пароль",
                   command=self.show_change_password_screen).pack(pady=10)
        ttk.Button(main_frame, text="Оставить комментарий",
                   command=self.show_comment_form).pack(pady=10)
        likes_count = self.check_likes()
        if likes_count > 0:
            ttk.Label(main_frame, text=f"Ваши комментарии получили {likes_count} лайков!",
                      foreground='green').pack(pady=5)
        ttk.Button(main_frame, text="Выйти",
                   command=self.logout).pack(pady=10)

    def logout(self):
        """Выход из системы"""
        if self.user_id:
            logging.info(f"Пользователь с ID {self.user_id} вышел из системы")
        self.user_id = None
        self.user_role = None
        self.show_login_screen()

    def show_add_user_screen(self):
        """Отображение экрана добавления пользователя"""
        self.clear_window()

        form_frame = ttk.Frame(self.root, padding="20")
        form_frame.pack(expand=True)

        ttk.Label(form_frame, text="Добавление пользователя",
                  font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Label(form_frame, text="Логин:").grid(row=1, column=0, pady=10, padx=5)
        self.entry_new_username = ttk.Entry(form_frame)
        self.entry_new_username.grid(row=1, column=1, pady=10, padx=5)

        ttk.Label(form_frame, text="Пароль:").grid(row=2, column=0, pady=10, padx=5)
        self.entry_new_password = ttk.Entry(form_frame, show="*")
        self.entry_new_password.grid(row=2, column=1, pady=10, padx=5)

        ttk.Label(form_frame, text="Роль:").grid(row=3, column=0, pady=10, padx=5)
        self.role_var = tk.StringVar(value='User')
        ttk.Radiobutton(form_frame, text="Пользователь", variable=self.role_var,
                        value="User").grid(row=3, column=1, sticky="w")
        ttk.Radiobutton(form_frame, text="Администратор", variable=self.role_var,
                        value="Admin").grid(row=4, column=1, sticky="w")

        ttk.Button(form_frame, text="Сохранить",
                   command=self.save_new_user).grid(row=5, column=0, pady=15)
        ttk.Button(form_frame, text="Назад",
                   command=self.show_admin_dashboard).grid(row=5, column=1, pady=15)

    def save_new_user(self):
        """Сохранение нового пользователя"""
        username = self.entry_new_username.get().strip() if self.entry_new_username.get() else ""
        password = self.entry_new_password.get() if self.entry_new_password.get() else ""
        role = self.role_var.get() if self.role_var.get() in ['User', 'Admin'] else 'User'

        if not username or not password:
            messagebox.showwarning("Предупреждение", "Все поля должны быть заполнены")
            return

        if len(username) > 50:  # Проверка длины имени пользователя
            messagebox.showwarning("Предупреждение", "Логин слишком длинный (макс. 50 символов)")
            return

        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    messagebox.showerror("Ошибка", "Пользователь с таким логином уже существует")
                else:
                    hashed_password = PasswordManager.hash_password(password)
                    cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                                   (username, hashed_password, role))
                    connection.commit()
                    messagebox.showinfo("Успех", "Пользователь успешно добавлен")
                    logging.info(f"Добавлен новый пользователь: {username}")
                    self.show_admin_dashboard()
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка базы данных при добавлении пользователя: {e}")
            logging.error(f"Ошибка при добавлении пользователя: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при добавлении пользователя")
            logging.error(f"Непредвиденная ошибка при добавлении пользователя: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def show_change_password_screen(self):
        """Отображение экрана смены пароля"""
        self.clear_window()

        form_frame = ttk.Frame(self.root, padding="20")
        form_frame.pack(expand=True)

        ttk.Label(form_frame, text="Смена пароля",
                  font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Label(form_frame, text="Текущий пароль:").grid(row=1, column=0, pady=10, padx=5)
        self.entry_current = ttk.Entry(form_frame, show="*")
        self.entry_current.grid(row=1, column=1, pady=10, padx=5)

        ttk.Label(form_frame, text="Новый пароль:").grid(row=2, column=0, pady=10, padx=5)
        self.entry_new = ttk.Entry(form_frame, show="*")
        self.entry_new.grid(row=2, column=1, pady=10, padx=5)

        ttk.Label(form_frame, text="Подтверждение:").grid(row=3, column=0, pady=10, padx=5)
        self.entry_confirm = ttk.Entry(form_frame, show="*")
        self.entry_confirm.grid(row=3, column=1, pady=10, padx=5)

        ttk.Button(form_frame, text="Сохранить",
                   command=self.update_password).grid(row=4, column=0, pady=15)
        ttk.Button(form_frame, text="Назад",
                   command=self.return_to_dashboard).grid(row=4, column=1, pady=15)

    def update_password(self):
        """Обновление пароля"""
        current = self.entry_current.get() if self.entry_current.get() else ""
        new = self.entry_new.get() if self.entry_new.get() else ""
        confirm = self.entry_confirm.get() if self.entry_confirm.get() else ""

        if not all([current, new, confirm]):
            messagebox.showwarning("Предупреждение", "Все поля должны быть заполнены")
            return

        if new != confirm:
            messagebox.showerror("Ошибка", "Новый пароль и подтверждение не совпадают")
            return

        if len(new) < 4:  # Минимальная длина пароля
            messagebox.showwarning("Предупреждение", "Пароль должен содержать минимум 4 символа")
            return

        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT password FROM users WHERE id = %s", (self.user_id,))
                user = cursor.fetchone()

                if not user:
                    messagebox.showerror("Ошибка", "Пользователь не найден")
                    self.logout()
                    return

                if PasswordManager.hash_password(current) != user['password']:
                    messagebox.showerror("Ошибка", "Неверный текущий пароль")
                    return

                hashed_new_password = PasswordManager.hash_password(new)
                cursor.execute("UPDATE users SET password = %s WHERE id = %s",
                               (hashed_new_password, self.user_id))
                connection.commit()
                messagebox.showinfo("Успех", "Пароль успешно изменен")
                logging.info(f"Пароль изменен для пользователя ID {self.user_id}")
                self.return_to_dashboard()
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка базы данных при смене пароля: {e}")
            logging.error(f"Ошибка при смене пароля: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при смене пароля")
            logging.error(f"Непредвиденная ошибка при смене пароля: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def show_user_management_screen(self):
        """Отображение экрана управления пользователями"""
        self.clear_window()

        management_frame = ttk.Frame(self.root, padding="20")
        management_frame.pack(expand=True, fill='both')

        ttk.Label(management_frame, text="Управление пользователями",
                  font=('Arial', 12, 'bold')).pack(pady=10)

        self.user_tree = ttk.Treeview(management_frame, columns=('ID', 'Username', 'Role', 'Attempts', 'Locked'),
                                      show='headings', height=8)
        self.user_tree.heading('ID', text='ID')
        self.user_tree.heading('Username', text='Логин')
        self.user_tree.heading('Role', text='Роль')
        self.user_tree.heading('Attempts', text='Неудачные попытки')
        self.user_tree.heading('Locked', text='Заблокирован')

        self.user_tree.column('ID', width=30)
        self.user_tree.column('Username', width=100)
        self.user_tree.column('Role', width=80)
        self.user_tree.column('Attempts', width=100)
        self.user_tree.column('Locked', width=80)

        self.load_users()
        self.user_tree.pack(fill='x', pady=10)

        ttk.Button(management_frame, text="Разблокировать выбранного",
                   command=self.unlock_user).pack(side='left', padx=5, pady=10)
        ttk.Button(management_frame, text="Назад",
                   command=self.show_admin_dashboard).pack(side='right', padx=5, pady=10)

    def load_users(self):
        """Загрузка списка пользователей в таблицу"""
        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT id, username, role, failed_attempts, locked FROM users")
                users = cursor.fetchall()

                for item in self.user_tree.get_children():
                    self.user_tree.delete(item)

                if not users:
                    self.user_tree.insert('', 'end', values=('-', 'Нет пользователей', '-', '-', '-'))
                    return

                for user in users:
                    locked_status = 'Да' if user['failed_attempts'] >= 3 or user['locked'] == 1 else 'Нет'
                    self.user_tree.insert('', 'end', values=(
                        user['id'],
                        user['username'],
                        user['role'],
                        user['failed_attempts'],
                        locked_status
                    ))
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка при загрузке пользователей: {e}")
            logging.error(f"Ошибка при загрузке пользователей: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при загрузке пользователей")
            logging.error(f"Непредвиденная ошибка при загрузке пользователей: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def unlock_user(self):
        """Разблокировка выбранного пользователя"""
        selected_item = self.user_tree.selection()
        if not selected_item:
            messagebox.showwarning("Предупреждение", "Выберите пользователя для разблокировки")
            return

        user_id = self.user_tree.item(selected_item)['values'][0]
        if not isinstance(user_id, int):  # Проверка, что ID корректен
            messagebox.showwarning("Предупреждение", "Невозможно разблокировать: некорректный пользователь")
            return

        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE users SET failed_attempts = 0, locked = 0 WHERE id = %s", (user_id,))
                connection.commit()
                messagebox.showinfo("Успех", "Пользователь успешно разблокирован")
                logging.info(f"Пользователь ID {user_id} разблокирован")
                self.load_users()
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка при разблокировке: {e}")
            logging.error(f"Ошибка при разблокировке: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при разблокировке")
            logging.error(f"Непредвиденная ошибка при разблокировке: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def show_comment_form(self):
        """Отображение формы для написания комментария"""
        self.clear_window()

        comment_frame = ttk.Frame(self.root, padding="20")
        comment_frame.pack(expand=True)

        ttk.Label(comment_frame, text="Оставить комментарий",
                  font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Label(comment_frame, text="Ваш комментарий:").grid(row=1, column=0, pady=10, padx=5)
        self.comment_text = tk.Text(comment_frame, height=5, width=40, font=('Arial', 10))
        self.comment_text.grid(row=1, column=1, pady=10, padx=5)

        ttk.Button(comment_frame, text="Отправить",
                   command=self.save_comment).grid(row=2, column=0, pady=15)
        ttk.Button(comment_frame, text="Назад",
                   command=self.show_user_dashboard).grid(row=2, column=1, pady=15)

    def save_comment(self):
        """Сохранение комментария в БД"""
        try:
            comment = self.comment_text.get("1.0", tk.END).strip()
        except Exception as e:
            messagebox.showerror("Ошибка", "Ошибка при чтении комментария")
            logging.error(f"Ошибка при чтении комментария: {e}")
            return

        if not comment:
            messagebox.showwarning("Предупреждение", "Комментарий не может быть пустым")
            return

        if len(comment) > 1000:  # Ограничение длины комментария
            messagebox.showwarning("Предупреждение", "Комментарий слишком длинный (макс. 1000 символов)")
            return

        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS comments (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT,
                        comment_text TEXT,
                        likes INT DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                """)
                cursor.execute("INSERT INTO comments (user_id, comment_text) VALUES (%s, %s)",
                               (self.user_id, comment))
                connection.commit()
                messagebox.showinfo("Успех", "Комментарий успешно отправлен")
                logging.info(f"Комментарий сохранен пользователем ID {self.user_id}")
                self.show_user_dashboard()
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка базы данных при сохранении комментария: {e}")
            logging.error(f"Ошибка при сохранении комментария: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при сохранении комментария")
            logging.error(f"Непредвиденная ошибка при сохранении комментария: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def show_comments_screen(self):
        """Отображение экрана просмотра комментариев для админа"""
        self.clear_window()

        comments_frame = ttk.Frame(self.root, padding="20")
        comments_frame.pack(expand=True, fill='both')

        ttk.Label(comments_frame, text="Просмотр комментариев",
                  font=('Arial', 12, 'bold')).pack(pady=10)

        self.comments_tree = ttk.Treeview(comments_frame,
                                          columns=('ID', 'UserID', 'Username', 'Comment', 'Likes'),
                                          show='headings', height=8)
        self.comments_tree.heading('ID', text='ID')
        self.comments_tree.heading('UserID', text='ID Пользователя')
        self.comments_tree.heading('Username', text='Логин')
        self.comments_tree.heading('Comment', text='Комментарий')
        self.comments_tree.heading('Likes', text='Лайки')

        self.comments_tree.column('ID', width=30)
        self.comments_tree.column('UserID', width=80)
        self.comments_tree.column('Username', width=100)
        self.comments_tree.column('Comment', width=200)
        self.comments_tree.column('Likes', width=50)

        self.load_comments()
        self.comments_tree.pack(fill='x', pady=10)

        ttk.Button(comments_frame, text="Поставить лайк",
               command=self.like_comment).pack(side='left', padx=5, pady=10)
        ttk.Button(comments_frame, text="Назад",
                   command=self.show_admin_dashboard).pack(side='right', padx=5, pady=10)

    def load_comments(self):
        """Загрузка комментариев в таблицу"""
        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("""
                    SELECT c.id, c.user_id, u.username, c.comment_text, c.likes 
                    FROM comments c 
                    LEFT JOIN users u ON c.user_id = u.id
                """)  # LEFT JOIN на случай, если пользователь удален
                comments = cursor.fetchall()

                for item in self.comments_tree.get_children():
                    self.comments_tree.delete(item)

                if not comments:
                    self.comments_tree.insert('', 'end', values=('-', '-', 'Нет комментариев', '-', '-'))
                    return

                for comment in comments:
                    username = comment['username'] if comment['username'] else "Удалённый пользователь"
                    self.comments_tree.insert('', 'end', values=(
                        comment['id'],
                        comment['user_id'],
                        username,
                        comment['comment_text'],
                        comment['likes']
                    ))
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка при загрузке комментариев: {e}")
            logging.error(f"Ошибка при загрузке комментариев: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при загрузке комментариев")
            logging.error(f"Непредвиденная ошибка при загрузке комментариев: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def like_comment(self):
        """Добавление лайка к выбранному комментарию"""
        selected_item = self.comments_tree.selection()
        if not selected_item:
            messagebox.showwarning("Предупреждение", "Выберите комментарий для оценки")
            return

        comment_id = self.comments_tree.item(selected_item)['values'][0]
        if not isinstance(comment_id, int):  # Проверка корректности ID
            messagebox.showwarning("Предупреждение", "Невозможно поставить лайк: некорректный комментарий")
            return

        connection = DatabaseConnection.connect()
        if not connection:
            return

        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE comments SET likes = likes + 1 WHERE id = %s", (comment_id,))
                connection.commit()
                messagebox.showinfo("Успех", "Лайк добавлен")
                logging.info(f"Лайк добавлен к комментарию ID {comment_id}")
                self.load_comments()
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка при добавлении лайка: {e}")
            logging.error(f"Ошибка при добавлении лайка: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при добавлении лайка")
            logging.error(f"Непредвиденная ошибка при добавлении лайка: {e}")
        finally:
            if connection and connection.is_connected():
                connection.close()

    def check_likes(self):
        """Проверка количества лайков для текущего пользователя"""
        if not self.user_id:
            return 0

        connection = DatabaseConnection.connect()
        if not connection:
            return 0

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT SUM(likes) as total_likes FROM comments WHERE user_id = %s",
                               (self.user_id,))
                result = cursor.fetchone()
                return result['total_likes'] if result and result['total_likes'] is not None else 0
        except Error as e:
            messagebox.showerror("Ошибка", f"Ошибка при проверке лайков: {e}")
            logging.error(f"Ошибка при проверке лайков: {e}")
            return 0
        except Exception as e:
            messagebox.showerror("Ошибка", "Непредвиденная ошибка при проверке лайков")
            logging.error(f"Непредвиденная ошибка при проверке лайков: {e}")
            return 0
        finally:
            if connection and connection.is_connected():
                connection.close()

    def return_to_dashboard(self):
        """Возврат к соответствующей панели"""
        if not self.user_role:
            self.show_login_screen()
        elif self.user_role == 'Admin':
            self.show_admin_dashboard()
        else:
            self.show_user_dashboard()


if __name__ == "__main__":
    try:
        HotelManagementApp()
    except Exception as e:
        logging.critical(f"Критическая ошибка при запуске приложения: {e}")
        messagebox.showerror("Критическая ошибка", "Приложение не может быть запущено. Проверьте лог-файл.")