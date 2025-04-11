import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import logging
from db_utils import connect_db, close_db

# Глобальные переменные
root = tk.Tk()
root.title("Hotel Management")
root.minsize(400, 300)
root.maxsize(600, 500)
root.configure(bg='#f0f0f0')
user_id = None
user_role = None


# Утилиты
def setup_styles():
    """Настройка стилей интерфейса"""
    style = ttk.Style()
    style.configure("TButton", font=('Arial', 10))
    style.configure("TLabel", font=('Arial', 10), background='#f0f0f0')
    style.configure("TEntry", font=('Arial', 10))


def clear_window(root):
    """Очистка окна"""
    for widget in root.winfo_children():
        widget.destroy()


def on_closing(root):
    """Обработка закрытия окна"""
    if messagebox.askokcancel("Выход", "Вы действительно хотите выйти?"):
        root.destroy()


def hash_password(password):
    """Хеширование пароля"""
    if not isinstance(password, str):
        logging.warning("Пароль не является строкой, преобразование в строку")
        password = str(password)
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# Экран авторизации
def show_login_screen():
    """Отображение экрана авторизации"""
    global user_id, user_role
    clear_window(root)

    login_frame = ttk.Frame(root, padding="20")
    login_frame.pack(expand=True)

    ttk.Label(login_frame, text="Логин:").grid(row=0, column=0, pady=10, padx=5, sticky="e")
    entry_username = ttk.Entry(login_frame)
    entry_username.grid(row=0, column=1, pady=10, padx=5)
    entry_username.focus_set()

    ttk.Label(login_frame, text="Пароль:").grid(row=1, column=0, pady=10, padx=5, sticky="e")
    entry_password = ttk.Entry(login_frame, show="*")
    entry_password.grid(row=1, column=1, pady=10, padx=5)

    def handle_login():
        global user_id, user_role
        user_id, user_role = login(entry_username.get().strip(), entry_password.get())

    ttk.Button(login_frame, text="Войти", command=handle_login).grid(row=2, column=0, columnspan=2, pady=15)


def login(username, password):
    """Обработка входа пользователя"""
    if not username or not password:
        messagebox.showwarning("Предупреждение", "Все поля должны быть заполнены")
        return None, None

    connection = connect_db()
    if not connection:
        return None, None

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if not user:
                messagebox.showerror("Ошибка", "Пользователь не найден")
                return None, None

            if user['locked'] == 1 or user['failed_attempts'] >= 3:
                messagebox.showerror("Ошибка", "Аккаунт заблокирован")
                return None, None

            if hash_password(password) == user['password']:
                cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = %s", (username,))
                connection.commit()
                messagebox.showinfo("Успех", "Авторизация прошла успешно")
                logging.info(f"Пользователь {username} вошел в систему с ролью {user['role']}")
                if user['role'] == 'Admin':
                    show_admin_dashboard()
                else:
                    show_user_dashboard()
                return user['id'], user['role']
            else:
                cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = %s",
                               (username,))
                connection.commit()
                messagebox.showerror("Ошибка", "Неверный логин или пароль")
                return None, None
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при авторизации: {e}")
        return None, None
    finally:
        close_db(connection)


# Пользовательские функции
def show_user_dashboard():
    """Отображение панели пользователя"""
    clear_window(root)

    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(expand=True)

    ttk.Label(main_frame, text="Добро пожаловать в систему!", font=('Arial', 12, 'bold')).pack(pady=20)
    ttk.Button(main_frame, text="Сменить пароль", command=show_change_password_screen).pack(pady=10)
    ttk.Button(main_frame, text="Оставить комментарий", command=show_comment_form).pack(pady=10)
    likes_count = check_likes()
    if likes_count > 0:
        ttk.Label(main_frame, text=f"Ваши комментарии получили {likes_count} лайков!", foreground='green').pack(pady=5)
    ttk.Button(main_frame, text="Выйти", command=logout).pack(pady=10)


def show_change_password_screen():
    """Отображение экрана смены пароля"""
    clear_window(root)

    form_frame = ttk.Frame(root, padding="20")
    form_frame.pack(expand=True)

    ttk.Label(form_frame, text="Смена пароля", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)

    ttk.Label(form_frame, text="Текущий пароль:").grid(row=1, column=0, pady=10, padx=5)
    entry_current = ttk.Entry(form_frame, show="*")
    entry_current.grid(row=1, column=1, pady=10, padx=5)

    ttk.Label(form_frame, text="Новый пароль:").grid(row=2, column=0, pady=10, padx=5)
    entry_new = ttk.Entry(form_frame, show="*")
    entry_new.grid(row=2, column=1, pady=10, padx=5)

    ttk.Label(form_frame, text="Подтверждение:").grid(row=3, column=0, pady=10, padx=5)
    entry_confirm = ttk.Entry(form_frame, show="*")
    entry_confirm.grid(row=3, column=1, pady=10, padx=5)

    ttk.Button(form_frame, text="Сохранить",
               command=lambda: update_password(entry_current.get(), entry_new.get(), entry_confirm.get())).grid(row=4,
                                                                                                                column=0,
                                                                                                                pady=15)
    # Проверяем роль и возвращаем на соответствующий дашборд
    back_command = show_admin_dashboard if user_role == 'Admin' else show_user_dashboard
    ttk.Button(form_frame, text="Назад", command=back_command).grid(row=4, column=1, pady=15)


def update_password(current, new, confirm):
    """Обновление пароля"""
    if not all([current, new, confirm]):
        messagebox.showwarning("Предупреждение", "Все поля должны быть заполнены")
        return

    if new != confirm:
        messagebox.showerror("Ошибка", "Новый пароль и подтверждение не совпадают")
        return

    if len(new) < 4:
        messagebox.showwarning("Предупреждение", "Пароль должен содержать минимум 4 символа")
        return

    connection = connect_db()
    if not connection:
        return

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

            if not user or hash_password(current) != user['password']:
                messagebox.showerror("Ошибка", "Неверный текущий пароль")
                return

            hashed_new_password = hash_password(new)
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, user_id))
            connection.commit()
            messagebox.showinfo("Успех", "Пароль успешно изменен")
            logging.info(f"Пароль изменен для пользователя ID {user_id}")
            if user_role == 'Admin':
                show_admin_dashboard()
            else:
                show_user_dashboard()
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при смене пароля: {e}")
    finally:
        close_db(connection)


def show_comment_form():
    """Отображение формы для написания комментария"""
    clear_window(root)

    comment_frame = ttk.Frame(root, padding="20")
    comment_frame.pack(expand=True)

    ttk.Label(comment_frame, text="Оставить комментарий", font=('Arial', 12, 'bold')).grid(row=0, column=0,
                                                                                           columnspan=2, pady=10)

    ttk.Label(comment_frame, text="Ваш комментарий:").grid(row=1, column=0, pady=10, padx=5)
    comment_text = tk.Text(comment_frame, height=5, width=40, font=('Arial', 10))
    comment_text.grid(row=1, column=1, pady=10, padx=5)

    ttk.Button(comment_frame, text="Отправить",
               command=lambda: save_comment(comment_text.get("1.0", tk.END).strip())).grid(row=2, column=0, pady=15)
    ttk.Button(comment_frame, text="Назад", command=show_user_dashboard).grid(row=2, column=1, pady=15)


def save_comment(comment):
    """Сохранение комментария в БД"""
    if not comment or len(comment) > 1000:
        messagebox.showwarning("Предупреждение", "Комментарий должен быть непустым и не длиннее 1000 символов")
        return

    connection = connect_db()
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
            cursor.execute("INSERT INTO comments (user_id, comment_text) VALUES (%s, %s)", (user_id, comment))
            connection.commit()
            messagebox.showinfo("Успех", "Комментарий успешно отправлен")
            logging.info(f"Комментарий сохранен пользователем ID {user_id}")
            show_user_dashboard()
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при сохранении комментария: {e}")
    finally:
        close_db(connection)


def check_likes():
    """Проверка количества лайков для текущего пользователя"""
    if not user_id:
        return 0

    connection = connect_db()
    if not connection:
        return 0

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT SUM(likes) as total_likes FROM comments WHERE user_id = %s", (user_id,))
            result = cursor.fetchone()
            return result['total_likes'] if result and result['total_likes'] is not None else 0
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при проверке лайков: {e}")
        return 0
    finally:
        close_db(connection)


# Админские функции
def show_admin_dashboard():
    """Отображение панели администратора"""
    clear_window(root)

    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(expand=True)

    ttk.Label(main_frame, text="Панель администратора", font=('Arial', 12, 'bold')).pack(pady=10)
    ttk.Button(main_frame, text="Добавить пользователя", command=show_add_user_screen).pack(pady=10)
    ttk.Button(main_frame, text="Сменить пароль", command=show_change_password_screen).pack(pady=10)
    ttk.Button(main_frame, text="Управление пользователями", command=show_user_management_screen).pack(pady=10)
    ttk.Button(main_frame, text="Просмотр комментариев", command=show_comments_screen).pack(pady=10)
    ttk.Button(main_frame, text="Выйти", command=logout).pack(pady=10)


def show_add_user_screen():
    """Отображение экрана добавления пользователя"""
    clear_window(root)

    form_frame = ttk.Frame(root, padding="20")
    form_frame.pack(expand=True)

    ttk.Label(form_frame, text="Добавление пользователя", font=('Arial', 12, 'bold')).grid(row=0, column=0,
                                                                                           columnspan=2, pady=10)

    ttk.Label(form_frame, text="Логин:").grid(row=1, column=0, pady=10, padx=5)
    entry_new_username = ttk.Entry(form_frame)
    entry_new_username.grid(row=1, column=1, pady=10, padx=5)

    ttk.Label(form_frame, text="Пароль:").grid(row=2, column=0, pady=10, padx=5)
    entry_new_password = ttk.Entry(form_frame, show="*")
    entry_new_password.grid(row=2, column=1, pady=10, padx=5)

    ttk.Label(form_frame, text="Роль:").grid(row=3, column=0, pady=10, padx=5)
    role_var = tk.StringVar(value='User')
    ttk.Radiobutton(form_frame, text="Пользователь", variable=role_var, value="User").grid(row=3, column=1, sticky="w")
    ttk.Radiobutton(form_frame, text="Администратор", variable=role_var, value="Admin").grid(row=4, column=1,
                                                                                             sticky="w")

    ttk.Button(form_frame, text="Сохранить",
               command=lambda: save_new_user(entry_new_username.get().strip(), entry_new_password.get(),
                                             role_var.get())).grid(row=5, column=0, pady=15)
    ttk.Button(form_frame, text="Назад", command=show_admin_dashboard).grid(row=5, column=1, pady=15)


def save_new_user(username, password, role):
    """Сохранение нового пользователя"""
    if not username or not password or len(username) > 50:
        messagebox.showwarning("Предупреждение", "Логин и пароль должны быть заполнены, логин не длиннее 50 символов")
        return

    connection = connect_db()
    if not connection:
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                messagebox.showerror("Ошибка", "Пользователь с таким логином уже существует")
            else:
                hashed_password = hash_password(password)
                cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                               (username, hashed_password, role))
                connection.commit()
                messagebox.showinfo("Успех", "Пользователь успешно добавлен")
                logging.info(f"Добавлен новый пользователь: {username}")
                show_admin_dashboard()
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при добавлении пользователя: {e}")
    finally:
        close_db(connection)


def show_user_management_screen():
    """Отображение экрана управления пользователями"""
    clear_window(root)

    management_frame = ttk.Frame(root, padding="20")
    management_frame.pack(expand=True, fill='both')

    ttk.Label(management_frame, text="Управление пользователями", font=('Arial', 12, 'bold')).pack(pady=10)

    user_tree = ttk.Treeview(management_frame, columns=('ID', 'Username', 'Role', 'Attempts', 'Locked'),
                             show='headings', height=8)
    user_tree.heading('ID', text='ID')
    user_tree.heading('Username', text='Логин')
    user_tree.heading('Role', text='Роль')
    user_tree.heading('Attempts', text='Неудачные попытки')
    user_tree.heading('Locked', text='Заблокирован')

    user_tree.column('ID', width=30)
    user_tree.column('Username', width=100)
    user_tree.column('Role', width=80)
    user_tree.column('Attempts', width=100)
    user_tree.column('Locked', width=80)

    load_users(user_tree)
    user_tree.pack(fill='x', pady=10)

    ttk.Button(management_frame, text="Разблокировать выбранного",
               command=lambda: unlock_user(user_tree)).pack(side='left', padx=5, pady=10)
    ttk.Button(management_frame, text="Назад", command=show_admin_dashboard).pack(side='right', padx=5, pady=10)


def load_users(user_tree):
    """Загрузка списка пользователей в таблицу"""
    connection = connect_db()
    if not connection:
        return

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username, role, failed_attempts, locked FROM users")
            users = cursor.fetchall()

            for item in user_tree.get_children():
                user_tree.delete(item)

            if not users:
                user_tree.insert('', 'end', values=('-', 'Нет пользователей', '-', '-', '-'))
                return

            for user in users:
                locked_status = 'Да' if user['failed_attempts'] >= 3 or user['locked'] == 1 else 'Нет'
                user_tree.insert('', 'end', values=(
                    user['id'],
                    user['username'],
                    user['role'],
                    user['failed_attempts'],
                    locked_status
                ))
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при загрузке пользователей: {e}")
    finally:
        close_db(connection)


def unlock_user(user_tree):
    """Разблокировка выбранного пользователя"""
    selected_item = user_tree.selection()
    if not selected_item:
        messagebox.showwarning("Предупреждение", "Выберите пользователя для разблокировки")
        return

    selected_user_id = user_tree.item(selected_item)['values'][0]
    if not isinstance(selected_user_id, int):
        messagebox.showwarning("Предупреждение", "Невозможно разблокировать: некорректный пользователь")
        return

    connection = connect_db()
    if not connection:
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE users SET failed_attempts = 0, locked = 0 WHERE id = %s", (selected_user_id,))
            connection.commit()
            messagebox.showinfo("Успех", "Пользователь успешно разблокирован")
            logging.info(f"Пользователь ID {selected_user_id} разблокирован")
            load_users(user_tree)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при разблокировке: {e}")
    finally:
        close_db(connection)


def show_comments_screen():
    """Отображение экрана просмотра комментариев для админа"""
    clear_window(root)

    comments_frame = ttk.Frame(root, padding="20")
    comments_frame.pack(expand=True, fill='both')

    ttk.Label(comments_frame, text="Просмотр комментариев", font=('Arial', 12, 'bold')).pack(pady=10)

    comments_tree = ttk.Treeview(comments_frame, columns=('ID', 'UserID', 'Username', 'Comment', 'Likes'),
                                 show='headings', height=8)
    comments_tree.heading('ID', text='ID')
    comments_tree.heading('UserID', text='ID Пользователя')
    comments_tree.heading('Username', text='Логин')
    comments_tree.heading('Comment', text='Комментарий')
    comments_tree.heading('Likes', text='Лайки')

    comments_tree.column('ID', width=30)
    comments_tree.column('UserID', width=80)
    comments_tree.column('Username', width=100)
    comments_tree.column('Comment', width=200)
    comments_tree.column('Likes', width=50)

    load_comments(comments_tree)
    comments_tree.pack(fill='x', pady=10)

    ttk.Button(comments_frame, text="Поставить лайк",
               command=lambda: like_comment(comments_tree)).pack(side='left', padx=5, pady=10)
    ttk.Button(comments_frame, text="Назад", command=show_admin_dashboard).pack(side='right', padx=5, pady=10)


def load_comments(comments_tree):
    """Загрузка комментариев в таблицу"""
    connection = connect_db()
    if not connection:
        return

    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT c.id, c.user_id, u.username, c.comment_text, c.likes 
                FROM comments c 
                LEFT JOIN users u ON c.user_id = u.id
            """)
            comments = cursor.fetchall()

            for item in comments_tree.get_children():
                comments_tree.delete(item)

            if not comments:
                comments_tree.insert('', 'end', values=('-', '-', 'Нет комментариев', '-', '-'))
                return

            for comment in comments:
                username = comment['username'] if comment['username'] else "Удалённый пользователь"
                comments_tree.insert('', 'end', values=(
                    comment['id'],
                    comment['user_id'],
                    username,
                    comment['comment_text'],
                    comment['likes']
                ))
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при загрузке комментариев: {e}")
    finally:
        close_db(connection)


def like_comment(comments_tree):
    """Добавление лайка к выбранному комментарию"""
    selected_item = comments_tree.selection()
    if not selected_item:
        messagebox.showwarning("Предупреждение", "Выберите комментарий для оценки")
        return

    comment_id = comments_tree.item(selected_item)['values'][0]
    if not isinstance(comment_id, int):
        messagebox.showwarning("Предупреждение", "Невозможно поставить лайк: некорректный комментарий")
        return

    connection = connect_db()
    if not connection:
        return

    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE comments SET likes = likes + 1 WHERE id = %s", (comment_id,))
            connection.commit()
            messagebox.showinfo("Успех", "Лайк добавлен")
            logging.info(f"Лайк добавлен к комментарию ID {comment_id}")
            load_comments(comments_tree)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка: {e}")
        logging.error(f"Ошибка при добавлении лайка: {e}")
    finally:
        close_db(connection)


# Логика выхода
def logout():
    """Выход из системы"""
    global user_id, user_role
    if user_id:
        logging.info(f"Пользователь с ID {user_id} вышел из системы")
    user_id = None
    user_role = None
    show_login_screen()


# Запуск программы
if __name__ == "__main__":
    setup_styles()
    show_login_screen()
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))
    root.mainloop()