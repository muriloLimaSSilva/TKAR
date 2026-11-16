"""Automação de teclado com login, temas e preferências guardadas em SQLite."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import colorchooser, messagebox, ttk

import pyautogui


APP_NAME = "JumpScreenSoftware"

THEMES = {
    "Dark (VS Code)": {"bg": "#1e1e1e", "surface": "#252526", "field": "#333333", "fg": "#d4d4d4", "muted": "#9da0a4", "accent": "#007acc", "button_fg": "#ffffff"},
    "Monokai": {"bg": "#272822", "surface": "#303127", "field": "#3e3d32", "fg": "#f8f8f2", "muted": "#b8b8a8", "accent": "#a6e22e", "button_fg": "#202116"},
    "Dracula": {"bg": "#282a36", "surface": "#343746", "field": "#44475a", "fg": "#f8f8f2", "muted": "#bd93f9", "accent": "#bd93f9", "button_fg": "#282a36"},
    "Light (IDE)": {"bg": "#f3f3f3", "surface": "#ffffff", "field": "#ffffff", "fg": "#242424", "muted": "#606060", "accent": "#0078d4", "button_fg": "#ffffff"},
}


def readable_foreground(hex_color: str) -> str:
    """Choose black or white text for readable contrast on the chosen color."""
    try:
        red, green, blue = (int(hex_color[index:index + 2], 16) for index in (1, 3, 5))
        brightness = (red * 299 + green * 587 + blue * 114) / 1000
        return "#171717" if brightness > 145 else "#ffffff"
    except (ValueError, IndexError):
        return "#ffffff"


def normalize_user_name(name: str) -> str:
    cleaned = name.strip()
    return cleaned[0].upper() + cleaned[1:] if cleaned else ""


def colors_for_user(store: "SettingsStore", theme_name: str) -> dict[str, str]:
    colors = THEMES.get(theme_name, THEMES["Dark (VS Code)"]).copy()
    background = store.get("background_color")
    button_color = store.get("button_color")
    if background:
        colors.update(bg=background, surface=background, fg=readable_foreground(background), muted=readable_foreground(background))
    if button_color:
        colors.update(accent=button_color, button_fg=readable_foreground(button_color))
    return colors

pyautogui.FAILSAFE = True


class SettingsStore:
    """Preferências do usuário em um SQLite fora da pasta do executável."""

    def __init__(self) -> None:
        base = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
        base.mkdir(parents=True, exist_ok=True)
        self.path = base / "settings.db"
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("""CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                start_time TEXT NOT NULL, end_time TEXT, access_date TEXT NOT NULL
            )""")
            db.execute("CREATE TABLE IF NOT EXISTS valid_users (name TEXT PRIMARY KEY COLLATE NOCASE)")
            db.execute("CREATE TABLE IF NOT EXISTS history_clears (id INTEGER PRIMARY KEY AUTOINCREMENT, cleared_by TEXT NOT NULL, cleared_at TEXT NOT NULL)")

        if self.get("theme") is None:
            self.set("theme", "Dark (VS Code)")
        if self.get("delay") is None:
            self.set("delay", "1.0")


    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def get(self, key: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def delete(self, key: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM settings WHERE key = ?", (key,))

    def start_access(self, name: str, started_at: datetime) -> int:
        with self.connect() as db:
            cursor = db.execute("INSERT INTO access_logs(name, start_time, access_date) VALUES (?, ?, ?)",
                                (name, started_at.strftime("%H:%M:%S"), started_at.strftime("%Y-%m-%d")))
            return int(cursor.lastrowid)

    def finish_access(self, access_id: int, ended_at: datetime) -> None:
        with self.connect() as db:
            db.execute("UPDATE access_logs SET end_time = ? WHERE id = ?",
                       (ended_at.strftime("%H:%M:%S"), access_id))

    def get_access_logs(self) -> list[tuple[int, str, str, str | None, str]]:
        with self.connect() as db:
            return db.execute("SELECT id, name, start_time, end_time, access_date FROM access_logs ORDER BY id DESC").fetchall()

    def get_valid_users(self) -> list[str]:
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT name FROM valid_users ORDER BY name COLLATE NOCASE")]

    def is_valid_user(self, name: str) -> bool:
        candidate = normalize_user_name(name).casefold()
        return any(user.casefold() == candidate for user in self.get_valid_users())

    def add_valid_user(self, name: str) -> bool:
        normalized = normalize_user_name(name)
        if not normalized:
            return False
        with self.connect() as db:
            cursor = db.execute("INSERT OR IGNORE INTO valid_users(name) VALUES (?)", (normalized,))
            return cursor.rowcount > 0

    def remove_valid_user(self, name: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM valid_users WHERE name = ? COLLATE NOCASE", (name,))

    def clear_access_history(self, cleared_by: str, cleared_at: datetime) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM access_logs")
            db.execute(
                "INSERT INTO history_clears(cleared_by, cleared_at) VALUES (?, ?)",
                (cleared_by, cleared_at.strftime("%Y-%m-%d %H:%M:%S")),
            )

    def get_last_history_clear(self) -> tuple[str, str] | None:
        with self.connect() as db:
            return db.execute(
                "SELECT cleared_by, cleared_at FROM history_clears ORDER BY id DESC LIMIT 1"
            ).fetchone()

    @staticmethod
    def _hash_password(password: str, salt: bytes | None = None) -> str:
        salt = salt or secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
        return f"{salt.hex()}:{digest.hex()}"

    @staticmethod
    def password_meets_policy(password: str) -> bool:
        return (
            len(password) >= 8
            and any(char.isupper() for char in password)
            and any(char.isdigit() for char in password)
            and any(not char.isalnum() for char in password)
        )

    @classmethod
    def password_matches(cls, password: str, stored: str) -> bool:
        try:
            salt_hex, digest_hex = stored.split(":", 1)
            candidate = cls._hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
            return hmac.compare_digest(candidate, digest_hex)
        except (ValueError, TypeError):
            return False


class LoginDialog:
    def __init__(self, root: tk.Tk, store: SettingsStore, colors: dict[str, str]) -> None:
        self.root, self.store, self.colors = root, store, colors
        self.accepted = False
        self.user_name = ""
        self.first_run = self.store.get("password_hash") is None
        self.window = tk.Toplevel(root)
        self.window.title("Criar senha" if self.first_run else "Acesso")
        self.window.resizable(False, False)
        self.window.configure(bg=colors["surface"])
        self.window.protocol("WM_DELETE_WINDOW", root.destroy)
        frame = tk.Frame(self.window, bg=colors["surface"], padx=26, pady=22)
        frame.pack()
        tk.Label(frame, text="Defina uma senha para o aplicativo" if self.first_run else "Acesso ao aplicativo", font=("Segoe UI", 14, "bold"), bg=colors["surface"], fg=colors["fg"]).pack(anchor="w", pady=(0, 12))
        tk.Label(frame, text="Nome", bg=colors["surface"], fg=colors["fg"]).pack(anchor="w")
        self.name_entry = tk.Entry(frame, bg=colors["field"], fg=colors["fg"], insertbackground=colors["fg"], relief="flat", width=32)
        self.name_entry.pack(pady=(5, 12), ipady=6)
        self.name_entry.bind("<KeyRelease>", self._capitalize_first_letter)
        tk.Label(frame, text="Criar senha" if self.first_run else "Senha", bg=colors["surface"], fg=colors["fg"]).pack(anchor="w")
        self.entry = tk.Entry(frame, show="•", bg=colors["field"], fg=colors["fg"], insertbackground=colors["fg"], relief="flat", width=32)
        self.entry.pack(pady=(5, 12), ipady=6)
        self.confirm_entry = None
        if self.first_run:
            tk.Label(frame, text="Confirmar senha", bg=colors["surface"], fg=colors["fg"]).pack(anchor="w")
            self.confirm_entry = tk.Entry(frame, show="•", bg=colors["field"], fg=colors["fg"],
                                          insertbackground=colors["fg"], relief="flat", width=32)
            self.confirm_entry.pack(pady=(5, 12), ipady=6)
        self.name_entry.bind("<Return>", lambda _event: self.entry.focus_set())
        self.name_entry.focus_set()
        self.entry.bind("<Return>", lambda _event: self.confirm_entry.focus_set() if self.confirm_entry is not None else self.submit())
        if self.confirm_entry is not None:
            self.confirm_entry.bind("<Return>", lambda _event: self.submit())
        tk.Button(frame, text="Salvar senha" if self.first_run else "Entrar", command=self.submit,
                  bg=colors["accent"], fg=colors["button_fg"], relief="flat", padx=20, pady=7).pack(fill="x")
        self.name_entry.focus_set()
        self.window.grab_set()
        root.wait_window(self.window)

    def _capitalize_first_letter(self, _event: object = None) -> None:
        value = self.name_entry.get()
        if value and value[0].isalpha() and value[0].islower():
            cursor = self.name_entry.index(tk.INSERT)
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, value[0].upper() + value[1:])
            self.name_entry.icursor(cursor)

    def submit(self) -> None:
        user_name = self.name_entry.get().strip()
        if user_name:
            user_name = user_name[0].upper() + user_name[1:]
        if not user_name:
            messagebox.showerror("Nome obrigatório", "Digite seu nome para registrar o acesso.", parent=self.window)
            self.name_entry.focus_set()
            return
        if self.store.get_valid_users() and not self.store.is_valid_user(user_name):
            messagebox.showerror("Usuário não autorizado", "Esse nome não está na lista de usuários válidos.", parent=self.window)
            self.name_entry.focus_set()
            return
        password = self.entry.get()
        if self.first_run:
            if not SettingsStore.password_meets_policy(password):
                messagebox.showerror(
                    "Formato de senha inválido",
                    "Use pelo menos 8 caracteres, incluindo uma letra maiúscula, um número e um símbolo.",
                    parent=self.window,
                )
                self.entry.focus_set()
                return
            if password != self.confirm_entry.get():
                messagebox.showerror("Confirmação diferente", "A confirmação não corresponde à senha.", parent=self.window)
                self.confirm_entry.delete(0, tk.END)
                self.confirm_entry.focus_set()
                return
            self.store.set("password_hash", SettingsStore._hash_password(password))
            if not self.store.get_valid_users():
                self.store.add_valid_user(user_name)
            self.user_name = user_name
            self.accepted = True
            self.window.destroy()
            return
        stored = self.store.get("password_hash") or ""
        if SettingsStore.password_matches(password, stored):
            self.user_name = user_name
            self.accepted = True
            self.window.destroy()
        else:
            messagebox.showerror("Senha incorreta", "A senha informada não confere.", parent=self.window)
            self.entry.delete(0, tk.END)
            self.entry.focus_set()


class AutomationApp:
    def __init__(self, root: tk.Tk, store: SettingsStore, user_name: str) -> None:
        self.root, self.store = root, store
        self.user_name = user_name
        self.access_log_id = store.start_access(user_name, datetime.now())
        self.access_finished = False
        self.root.title("TKAR — Timed Keyboard Action Runner")
        self.root.geometry("820x580")
        self.root.minsize(680, 500)
        self.running = False
        self.paused = threading.Event()
        self.delay_lock = threading.Lock()
        self.delay_seconds = float(store.get("delay") or "1.0")
        self.theme_name = store.get("theme") or "Dark (VS Code)"
        if self.theme_name not in THEMES:
            self.theme_name = "Dark (VS Code)"
        self.colors = colors_for_user(store, self.theme_name)
        self.root.configure(bg=self.colors["bg"])

        self._build_ui()
        self._apply_theme()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _build_ui(self) -> None:
        self.notebook = ttk.Notebook(self.root, style="App.TNotebook")
        self.notebook.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.84, relheight=0.82)
        self.main_page = tk.Frame(self.notebook, padx=32, pady=28)
        self.settings_page = tk.Frame(self.notebook, padx=28, pady=24)
        self.records_page = tk.Frame(self.notebook, padx=28, pady=24)
        self.notebook.add(self.main_page, text="Automação")
        self.notebook.add(self.settings_page, text="Configurações")
        self.notebook.add(self.records_page, text="Registro")

        self.title_label = tk.Label(self.main_page, text="Jump Screen Software", font=("Segoe UI", 20, "bold"))
        self.title_label.pack(pady=(5, 26))
        self.speed_label = tk.Label(self.main_page, text="Intervalo entre ações (segundos)", font=("Segoe UI", 10))
        self.speed_label.pack(anchor="w")
        row = tk.Frame(self.main_page)
        row.pack(fill="x", pady=(8, 24))
        self.delay = tk.DoubleVar(value=self.delay_seconds)
        self.delay_scale = tk.Scale(row, from_=0.1, to=10, resolution=0.1, orient="horizontal", variable=self.delay,
                                    showvalue=True, highlightthickness=0, length=390, command=self._on_scale)
        self.delay_scale.pack(side="left", fill="x", expand=True)
        self.delay_entry = tk.Entry(row, width=8, relief="flat", justify="center")
        self.delay_entry.insert(0, f"{self.delay_seconds:.1f}")
        self.delay_entry.pack(side="left", padx=(12, 0), ipady=6)
        self.delay_entry.bind("<FocusOut>", self._sync_scale)
        self.delay_entry.bind("<Return>", self._sync_scale)

        buttons = tk.Frame(self.main_page)
        buttons.pack(fill="x")
        self.start_button = tk.Button(buttons, text="Iniciar", command=self.start, relief="flat", padx=20, pady=11,
                                      font=("Segoe UI", 10, "bold"), cursor="hand2")
        self.start_button.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.pause_button = tk.Button(buttons, text="Pausar", command=self.toggle_pause, relief="flat", padx=20, pady=11,
                                      font=("Segoe UI", 10, "bold"), cursor="hand2", state="disabled")
        self.pause_button.pack(side="left", expand=True, fill="x", padx=(6, 0))
        self.status = tk.StringVar(value="Pronto")
        self.status_label = tk.Label(self.main_page, textvariable=self.status, font=("Segoe UI", 9))
        self.status_label.pack(pady=(22, 0))

        self.settings_title = tk.Label(self.settings_page, text="Preferências", font=("Segoe UI", 17, "bold"))
        self.settings_title.pack(anchor="w", pady=(0, 18))
        self.theme_label = tk.Label(self.settings_page, text="Tema de cores", font=("Segoe UI", 10))
        self.theme_label.pack(anchor="w")
        self.theme_var = tk.StringVar(value=self.theme_name)
        self.theme_combo = ttk.Combobox(self.settings_page, textvariable=self.theme_var, values=list(THEMES), state="readonly", width=32)
        self.theme_combo.pack(anchor="w", pady=(6, 16))
        self.theme_combo.bind("<<ComboboxSelected>>", self.change_theme)
        self.colors_title = tk.Label(self.settings_page, text="Cores da interface", font=("Segoe UI", 11, "bold"))
        self.colors_title.pack(anchor="w", pady=(0, 8))
        color_row = tk.Frame(self.settings_page)
        color_row.pack(anchor="w", fill="x", pady=(0, 14))
        self.background_color_button = tk.Button(color_row, text="Cor do fundo", command=self.choose_background_color,
                                                 relief="flat", padx=14, pady=8, cursor="hand2")
        self.background_color_button.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.button_color_button = tk.Button(color_row, text="Cor dos botões", command=self.choose_button_color,
                                             relief="flat", padx=14, pady=8, cursor="hand2")
        self.button_color_button.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.password_title = tk.Label(self.settings_page, text="Alterar senha", font=("Segoe UI", 11, "bold"))
        self.password_title.pack(anchor="w", pady=(4, 8))
        self.password_row_labels: list[tk.Label] = []
        self.password_row_frames: list[tk.Frame] = []
        self.current_password = self._password_row(self.settings_page, "Senha atual")
        self.new_password = self._password_row(self.settings_page, "Nova senha")
        self.confirm_password = self._password_row(self.settings_page, "Confirmar nova senha")
        self.password_button = tk.Button(self.settings_page, text="Salvar nova senha", command=self.change_password,
                                         relief="flat", padx=14, pady=8, cursor="hand2")
        self.password_button.pack(anchor="w", pady=(12, 0))
        self._build_records_page()

    def _build_records_page(self) -> None:
        self.valid_users_title = tk.Label(self.records_page, text="Usuários válidos", font=("Segoe UI", 12, "bold"))
        self.valid_users_title.pack(anchor="w", pady=(0, 6))
        self.user_add_row = tk.Frame(self.records_page)
        self.user_add_row.pack(fill="x", pady=(0, 6))
        self.valid_user_entry = tk.Entry(self.user_add_row, relief="flat")
        self.valid_user_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        self.add_user_button = tk.Button(self.user_add_row, text="Adicionar usuário", command=self.add_valid_user_from_ui,
                                         relief="flat", padx=12, pady=6, cursor="hand2")
        self.add_user_button.pack(side="left")
        self.valid_users_frame = tk.Frame(self.records_page)
        self.valid_users_frame.pack(fill="x", pady=(0, 8))
        self.records_header = tk.Frame(self.records_page)
        self.records_header.pack(fill="x", pady=(4, 8))
        self.records_title = tk.Label(self.records_header, text="Registro de acessos", font=("Segoe UI", 15, "bold"))
        self.records_title.pack(side="left")
        self.clear_history_button = tk.Button(
            self.records_header, text="Limpar histórico", command=self.confirm_clear_history,
            relief="flat", padx=10, pady=6, cursor="hand2",
        )
        self.clear_history_button.pack(side="right")
        self.records_tree = ttk.Treeview(self.records_page, columns=("name", "start", "end"), show="headings",
                                         height=7, style="Records.Treeview")
        for column, heading, width in (("name", "NOME", 230), ("start", "HORÁRIO INICIAL", 150),
                                       ("end", "HORÁRIO FINAL", 150)):
            self.records_tree.heading(column, text=heading)
            self.records_tree.column(column, width=width, anchor="w" if column == "name" else "center")
        self.records_tree.pack(fill="both", expand=True)
        self.records_tree.bind("<<TreeviewSelect>>", self._show_selected_access_date)
        self.records_date = tk.Label(self.records_page, text="Data: —", font=("Segoe UI", 10))
        self.records_date.pack(anchor="w", pady=(8, 0))
        self.clear_history_status = tk.Label(self.records_page, text="Última limpeza: ainda não realizada", font=("Segoe UI", 9))
        self.clear_history_status.pack(anchor="w", pady=(4, 0))
        self._refresh_valid_users()
        self._load_access_logs()
        self._show_last_history_clear()

    def _load_access_logs(self) -> None:
        self.access_dates = {}
        self.records_date.configure(text="Data: —")
        for row in self.records_tree.get_children():
            self.records_tree.delete(row)
        for access_id, name, start, end, date in self.store.get_access_logs():
            item = str(access_id)
            self.access_dates[item] = datetime.strptime(date, "%Y-%m-%d").strftime("%d/%m/%Y")
            self.records_tree.insert("", "end", iid=item,
                values=(name, start[:5], end[:5] if end else "Em andamento"))
        rows = self.records_tree.get_children()
        if rows:
            self.records_tree.selection_set(rows[0])
            self._show_selected_access_date()

    def _show_selected_access_date(self, _event: object = None) -> None:
        selected = self.records_tree.selection()
        date = self.access_dates.get(selected[0]) if selected else None
        self.records_date.configure(text=f"Data: {date or '—'}")

    def _show_last_history_clear(self) -> None:
        last_clear = self.store.get_last_history_clear()
        if last_clear:
            cleared_by, timestamp = last_clear
            shown_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y %H:%M:%S")
            self.clear_history_status.configure(text=f"Última limpeza: {shown_time} por {cleared_by}")
        else:
            self.clear_history_status.configure(text="Última limpeza: ainda não realizada")

    def confirm_clear_history(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Confirmar limpeza do histórico")
        dialog.resizable(False, False)
        dialog.configure(bg=self.colors["surface"])
        dialog.transient(self.root)
        frame = tk.Frame(dialog, bg=self.colors["surface"], padx=20, pady=18)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="Confirme seu usuário e senha para limpar o histórico.",
                 bg=self.colors["surface"], fg=self.colors["fg"], wraplength=320).pack(anchor="w", pady=(0, 12))
        tk.Label(frame, text="Usuário", bg=self.colors["surface"], fg=self.colors["fg"]).pack(anchor="w")
        user_entry = tk.Entry(frame, bg=self.colors["field"], fg=self.colors["fg"],
                              insertbackground=self.colors["fg"], relief="flat", width=34)
        user_entry.insert(0, self.user_name)
        user_entry.pack(fill="x", pady=(4, 10), ipady=5)
        tk.Label(frame, text="Senha", bg=self.colors["surface"], fg=self.colors["fg"]).pack(anchor="w")
        password_entry = tk.Entry(frame, show="•", bg=self.colors["field"], fg=self.colors["fg"],
                                  insertbackground=self.colors["fg"], relief="flat", width=34)
        password_entry.pack(fill="x", pady=(4, 12), ipady=5)

        def submit_clear() -> None:
            cleared_by = normalize_user_name(user_entry.get())
            if cleared_by.casefold() != normalize_user_name(self.user_name).casefold():
                messagebox.showerror("Usuário diferente", "Informe o usuário conectado a esta sessão.", parent=dialog)
                user_entry.focus_set()
                return
            if not self.store.is_valid_user(cleared_by):
                messagebox.showerror("Usuário inválido", "Esse usuário não está cadastrado como válido.", parent=dialog)
                user_entry.focus_set()
                return
            stored = self.store.get("password_hash") or ""
            if not SettingsStore.password_matches(password_entry.get(), stored):
                messagebox.showerror("Senha incorreta", "A senha informada não confere.", parent=dialog)
                password_entry.delete(0, tk.END)
                password_entry.focus_set()
                return
            if not messagebox.askyesno(
                "Confirmar limpeza",
                "Todos os acessos registrados serão apagados. A auditoria da limpeza será mantida. Continuar?",
                parent=dialog,
            ):
                return
            cleaned_at = datetime.now()
            self.store.clear_access_history(cleared_by, cleaned_at)
            dialog.destroy()
            self._load_access_logs()
            self._show_last_history_clear()
            messagebox.showinfo(
                "Histórico limpo",
                f"Limpeza realizada em {cleaned_at.strftime('%d/%m/%Y %H:%M:%S')} por {cleared_by}.",
                parent=self.root,
            )

        buttons = tk.Frame(frame, bg=self.colors["surface"])
        buttons.pack(fill="x")
        tk.Button(buttons, text="Cancelar", command=dialog.destroy, relief="flat", padx=12, pady=7).pack(side="right")
        tk.Button(buttons, text="Confirmar", command=submit_clear, bg=self.colors["accent"],
                  fg=self.colors["button_fg"], relief="flat", padx=12, pady=7).pack(side="right", padx=(0, 8))
        user_entry.bind("<Return>", lambda _event: password_entry.focus_set())
        password_entry.bind("<Return>", lambda _event: submit_clear())
        user_entry.focus_set()
        dialog.grab_set()
        dialog.wait_window()

    def _refresh_valid_users(self) -> None:
        for child in self.valid_users_frame.winfo_children():
            child.destroy()
        for name in self.store.get_valid_users():
            row = tk.Frame(self.valid_users_frame, bg=self.colors["surface"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=name, anchor="w", bg=self.colors["surface"], fg=self.colors["fg"]).pack(
                side="left", fill="x", expand=True, padx=6, pady=3)
            tk.Button(row, text="×", command=lambda selected=name: self.remove_valid_user(selected),
                      bg=self.colors["accent"], activebackground=self.colors["accent"],
                      fg=self.colors["button_fg"], activeforeground=self.colors["button_fg"],
                      relief="flat", width=3, cursor="hand2").pack(side="right")

    def add_valid_user_from_ui(self) -> None:
        name = normalize_user_name(self.valid_user_entry.get())
        if not name:
            messagebox.showerror("Nome obrigatório", "Digite o nome que deseja adicionar.", parent=self.root)
            self.valid_user_entry.focus_set()
            return
        if not self.store.add_valid_user(name):
            messagebox.showerror("Usuário já cadastrado", f"{name} já está na lista de usuários válidos.", parent=self.root)
            return
        self.valid_user_entry.delete(0, tk.END)
        self._refresh_valid_users()

    def remove_valid_user(self, name: str) -> None:
        if len(self.store.get_valid_users()) <= 1:
            messagebox.showerror("Não é possível remover", "Mantenha pelo menos um usuário válido para acessar o aplicativo.", parent=self.root)
            return
        if not messagebox.askyesno("Confirmar remoção", f"Remover {name} da lista de usuários válidos?", parent=self.root):
            return
        if not messagebox.askyesno("Confirmar novamente", f"Confirma pela segunda vez a remoção de {name}?", parent=self.root):
            return
        self.store.remove_valid_user(name)
        self._refresh_valid_users()

    def _password_row(self, parent: tk.Widget, label: str) -> tk.Entry:
        line = tk.Frame(parent)
        line.pack(anchor="w", fill="x", pady=3)
        self.password_row_frames.append(line)
        label_widget = tk.Label(line, text=label, width=22, anchor="w")
        label_widget.pack(side="left")
        entry = tk.Entry(line, show="•", width=32, relief="flat")
        entry.pack(side="left", ipady=5)
        self.password_row_labels.append(label_widget)
        return entry

    def _apply_theme(self) -> None:
        c = self.colors
        self.root.configure(bg=c["bg"])
        for page in (self.main_page, self.settings_page, self.records_page):
            page.configure(bg=c["surface"])
        for widget in (self.title_label, self.speed_label, self.status_label, self.settings_title,
                       self.theme_label, self.colors_title, self.password_title, self.records_title, self.records_date,
                       self.valid_users_title, self.clear_history_status):
            widget.configure(bg=c["surface"], fg=c["fg"] if widget is not self.status_label else c["muted"])
        for row in (self.delay_scale.master, self.start_button.master, self.background_color_button.master,
                    self.user_add_row, self.valid_users_frame, self.records_header):
            row.configure(bg=c["surface"])
        self.valid_user_entry.configure(bg=c["field"], fg=c["fg"], insertbackground=c["fg"])
        self.add_user_button.configure(bg=c["accent"], activebackground=c["accent"],
                                       fg=c["button_fg"], activeforeground=c["button_fg"])
        self.clear_history_button.configure(bg=c["accent"], activebackground=c["accent"],
                                            fg=c["button_fg"], activeforeground=c["button_fg"])
        for row in self.password_row_frames:
            row.configure(bg=c["surface"])
        for label in self.password_row_labels:
            label.configure(bg=c["surface"], fg=c["fg"])
        for entry in (self.delay_entry, self.current_password, self.new_password, self.confirm_password):
            entry.configure(bg=c["field"], fg=c["fg"], insertbackground=c["fg"])
        for button in (self.start_button, self.pause_button, self.background_color_button,
                       self.button_color_button, self.password_button):
            button.configure(bg=c["accent"], activebackground=c["accent"], fg=c["button_fg"], activeforeground=c["button_fg"])
        self.background_color_button.configure(bg=c["bg"], activebackground=c["bg"], fg=c["fg"],
                                               activeforeground=c["fg"], text=f"Fundo: {c['bg']}")
        self.button_color_button.configure(bg=c["accent"], activebackground=c["accent"],
                                           fg=c["button_fg"], activeforeground=c["button_fg"],
                                           text=f"Botões: {c['accent']}")
        self.delay_scale.configure(bg=c["surface"], fg=c["fg"], troughcolor=c["field"], activebackground=c["accent"])
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TNotebook", background=c["bg"], borderwidth=0)
        style.configure("App.TNotebook.Tab", background=c["accent"], foreground=c["button_fg"], padding=(16, 8))
        style.map("App.TNotebook.Tab",
                  background=[("selected", c["accent"]), ("active", c["accent"])],
                  foreground=[("selected", c["button_fg"]), ("active", c["button_fg"])])
        style.configure("TCombobox", fieldbackground=c["field"], background=c["field"], foreground=c["fg"])
        style.configure("Records.Treeview", background=c["field"], foreground=c["fg"], fieldbackground=c["field"], rowheight=28)
        style.configure("Records.Treeview.Heading", background=c["accent"], foreground=c["button_fg"], padding=8)
        style.map("Records.Treeview", background=[("selected", c["accent"])], foreground=[("selected", c["button_fg"])])
        self._refresh_valid_users()

    def choose_background_color(self) -> None:
        selected = colorchooser.askcolor(color=self.colors["bg"], title="Escolher cor do fundo", parent=self.root)[1]
        if selected:
            self.store.set("background_color", selected)
            self.colors = colors_for_user(self.store, self.theme_name)
            self._apply_theme()

    def choose_button_color(self) -> None:
        selected = colorchooser.askcolor(color=self.colors["accent"], title="Escolher cor dos botões", parent=self.root)[1]
        if selected:
            self.store.set("button_color", selected)
            self.colors = colors_for_user(self.store, self.theme_name)
            self._apply_theme()

    def change_theme(self, _event: object = None) -> None:
        self.theme_name = self.theme_var.get()
        self.store.set("theme", self.theme_name)
        # A seleção de um tema restaura sua paleta completa, removendo qualquer
        # cor personalizada que estivesse substituindo o fundo ou os botões.
        self.store.delete("background_color")
        self.store.delete("button_color")
        self.colors = THEMES[self.theme_name].copy()
        self._apply_theme()

    def _on_scale(self, value: str) -> None:
        delay = float(value)
        self.delay_entry.delete(0, tk.END)
        self.delay_entry.insert(0, f"{delay:.1f}")
        with self.delay_lock:
            self.delay_seconds = delay
        self.store.set("delay", f"{delay:.1f}")

    def _sync_scale(self, _event: object = None) -> None:
        try:
            delay = min(10.0, max(0.1, float(self.delay_entry.get().replace(",", "."))))
        except ValueError:
            delay = self.delay_seconds
        self.delay.set(delay)
        self._on_scale(str(delay))

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.paused.clear()
        self.start_button.configure(state="disabled")
        self.pause_button.configure(state="normal", text="Pausar")
        self.status.set("Em execução — selecione o aplicativo que receberá as teclas")
        threading.Thread(target=self._run, daemon=True).start()

    def toggle_pause(self) -> None:
        if not self.running:
            return
        if self.paused.is_set():
            self.paused.clear()
            self.pause_button.configure(text="Pausar")
            self.status.set("Em execução")
        else:
            self.paused.set()
            self.pause_button.configure(text="Retomar")
            self.status.set("Pausada")

    def _wait(self, seconds: float) -> bool:
        remaining = seconds
        while self.running:
            while self.running and self.paused.is_set():
                threading.Event().wait(0.1)
            if not self.running or remaining <= 0:
                break
            step = min(0.1, remaining)
            threading.Event().wait(step)
            remaining -= step
        return self.running

    def _run(self) -> None:
        try:
            while self.running:
                if not self._wait(0):
                    break
                pyautogui.press("f2")
                with self.delay_lock:
                    delay = self.delay_seconds
                if not self._wait(delay):
                    break
                minute_value = datetime.now().minute * 2 + 3
                pyautogui.write(str(minute_value))
                with self.delay_lock:
                    delay = self.delay_seconds
                if not self._wait(delay):
                    break
                pyautogui.press("enter")
                with self.delay_lock:
                    delay = self.delay_seconds
                if not self._wait(delay):
                    break
        except Exception as exc:
            error = str(exc)
            self.root.after(0, lambda message=error: messagebox.showerror("Erro na automação", message, parent=self.root))
        finally:
            self.running = False
            self.root.after(0, self._finished)

    def _finished(self) -> None:
        self.start_button.configure(state="normal")
        self.pause_button.configure(state="disabled", text="Pausar")
        self.status.set("Pronto")

    def change_password(self) -> None:
        current, new, confirm = self.current_password.get(), self.new_password.get(), self.confirm_password.get()
        stored = self.store.get("password_hash") or ""
        if not SettingsStore.password_matches(current, stored):
            messagebox.showerror("Senha atual incorreta", "Digite corretamente a senha atual.", parent=self.root)
            return
        if not SettingsStore.password_meets_policy(new):
            messagebox.showerror(
                "Formato de senha inválido",
                "Use pelo menos 8 caracteres, incluindo uma letra maiúscula, um número e um símbolo.",
                parent=self.root,
            )
            return
        if new != confirm:
            messagebox.showerror("Confirmação diferente", "A confirmação não corresponde à nova senha.", parent=self.root)
            return
        self.store.set("password_hash", SettingsStore._hash_password(new))
        for entry in (self.current_password, self.new_password, self.confirm_password):
            entry.delete(0, tk.END)
        messagebox.showinfo("Senha alterada", "A nova senha foi salva com segurança.", parent=self.root)

    def close(self) -> None:
        self.running = False
        self.paused.clear()
        if not self.access_finished:
            self.store.finish_access(self.access_log_id, datetime.now())
            self.access_finished = True
        self.root.destroy()


if __name__ == "__main__":
    store = SettingsStore()
    root = tk.Tk()
    root.withdraw()
    colors = colors_for_user(store, store.get("theme") or "Dark (VS Code)")
    login = LoginDialog(root, store, colors)
    if login.accepted:
        app = AutomationApp(root, store, login.user_name)
        root.deiconify()
        root.mainloop()
