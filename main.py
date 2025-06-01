# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import sqlite3
import hashlib
import os
import binascii
import logging
import csv
import pandas as pd
from datetime import datetime
import re
from logging.handlers import RotatingFileHandler

# ---- Configuração aprimorada de logging ----
# Cria pasta de logs se não existir
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)
# Arquivo de log com timestamp
log_file = os.path.join(LOG_DIR, datetime.now().strftime('%Y%m%d_%H%M%S') + '.log')

# Logger principal
logger = logging.getLogger('OrcaFacil')
logger.setLevel(logging.DEBUG)

# Handler de arquivo rotativo
file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d — %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Handler de console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Redireciona root para nosso logger
logging.root.handlers = [file_handler, console_handler]
logging.root.setLevel(logging.DEBUG)
# ---- Fim da configuração de logging ----

# Configurações gerais
db_name = 'orcafacil.db'
AREA_OPTIONS = ['Informática', 'Indústria', 'Papelaria', 'Materiais de Limpeza', 'Outros']
TIPO_OPTIONS = ['Fornecedor', 'Prestador', 'Fornecedor/prestado']
EQUIP_OPTIONS = ['Firewall', 'Antivírus', 'Produto de Limpeza', 'Outros']
COMPANY_SIZE_OPTIONS = [
    'MEI – Até R$ 81.000,00',
    'ME – Até R$ 360.000,00',
    'EPP – De R$ 360.000,01 até R$ 4.800.000,00',
    'Média Empresa – De R$ 4.800.000,01 até R$ 300.000.000,00',
    'Grande Empresa – Acima de R$ 300.000.000,00'
]
SEARCH_FIELDS = {
    'Todos': None,
    'Razão Social': 'razao_social',
    'CNPJ': 'cnpj',
    'Tipo': 'tipo',
    'Área': 'area',
    'Porte da Empresa': 'company_size',
    'Equip': 'equip',
    'E-mail': 'email',
    'Telefone': 'phone',
    'Contato': 'contact_name'
}

PRIMARY_BG = '#E8F1FA'
SECOND_BG = '#FFFFFF'
ACCENT = '#2E6EB5'
FONT = ('Segoe UI', 10)
FONT_BOLD = ('Segoe UI', 11, 'bold')

# Regex para CNPJ
CNPJ_PATTERN = r"^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$"

def format_cnpj_string(digits):
    logger.debug('format_cnpj_string chamado')
    m = re.match(CNPJ_PATTERN, digits)
    result = f"{m.group(1)}.{m.group(2)}.{m.group(3)}/{m.group(4)}-{m.group(5)}" if m else digits
    logger.debug(f'format_cnpj_string retornou {result}')
    return result


def format_cnpj_event(widget):
    logger.debug('format_cnpj_event chamado')
    d = re.sub(r"\D", "", widget.get())
    widget.delete(0, tk.END)
    widget.insert(0, format_cnpj_string(d))

# Funções de segurança
def hash_password(pw):
    logger.debug('hash_password chamado')
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    h = hashlib.pbkdf2_hmac('sha512', pw.encode(), salt, 100000)
    result = (salt + binascii.hexlify(h)).decode('ascii')
    logger.debug('hash_password gerou hash')
    return result


def verify_password(stored, provided):
    logger.debug('verify_password chamado')
    salt, stored_hash = stored[:64], stored[64:]
    h = hashlib.pbkdf2_hmac('sha512', provided.encode(), salt.encode(), 100000)
    valid = binascii.hexlify(h).decode('ascii') == stored_hash
    logger.debug(f'verify_password retorna {valid}')
    return valid

# Inicialização do banco
def init_db():
    logger.info('init_db: iniciando setup do banco')
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY,
            razao_social TEXT NOT NULL,
            cnpj TEXT NOT NULL,
            tipo TEXT NOT NULL,
            area TEXT NOT NULL
        )
    ''')
    c.execute('PRAGMA table_info(contacts)')
    cols = {row[1] for row in c.fetchall()}
    extras = {
        'equip': "ALTER TABLE contacts ADD COLUMN equip TEXT DEFAULT ''",
        'email': "ALTER TABLE contacts ADD COLUMN email TEXT DEFAULT ''",
        'phone': "ALTER TABLE contacts ADD COLUMN phone TEXT DEFAULT ''",
        'contact_name': "ALTER TABLE contacts ADD COLUMN contact_name TEXT DEFAULT ''",
        'company_size': "ALTER TABLE contacts ADD COLUMN company_size TEXT DEFAULT ''"
    }
    for col, stmt in extras.items():
        if col not in cols:
            logger.info(f'init_db: adicionando coluna {col}')
            c.execute(stmt)
    conn.commit()
    conn.close()
    logger.info('init_db: banco preparado')

# Janela base
ttk_style = None
class BaseWindow(tk.Tk):
    def __init__(self, title):
        super().__init__()
        logger.debug(f'BaseWindow: iniciando janela {title}')
        self.title(title)
        self.configure(bg=PRIMARY_BG)
        global ttk_style
        if 'ttk_style' not in globals() or ttk_style is None:
            from tkinter import ttk
            ttk_style = ttk.Style(self)
            ttk_style.theme_use('clam')
            ttk_style.configure('TButton', font=FONT_BOLD, padding=6)
            ttk_style.map('TButton', background=[('active', ACCENT)])
            ttk_style.configure('TLabel', background=PRIMARY_BG, font=FONT)
            ttk_style.configure('TEntry', font=FONT)
            ttk_style.configure('Treeview', font=FONT, background=SECOND_BG, fieldbackground=SECOND_BG)
            ttk_style.configure('Treeview.Heading', font=FONT_BOLD, background=ACCENT, foreground='white')
        logger.debug('BaseWindow configurado')

# Janela de registro do Admin
class RegistrationWindow(BaseWindow):
    def __init__(self):
        logger.debug('RegistrationWindow.__init__ entry')
        super().__init__('OrçaFácil - Configure Admin')
        self.geometry('400x240')

        ttk.Label(self, text='Primeiro acesso: crie a senha de admin', font=FONT_BOLD).pack(pady=15)
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='x')

        ttk.Label(frm, text='Senha:').grid(row=0, column=0, sticky='w')
        self.pwd = ttk.Entry(frm, show='*')
        self.pwd.grid(row=0, column=1, sticky='ew', padx=5)

        ttk.Label(frm, text='Confirmar senha:').grid(row=1, column=0, sticky='w', pady=5)
        self.cfm = ttk.Entry(frm, show='*')
        self.cfm.grid(row=1, column=1, sticky='ew', padx=5)

        frm.columnconfigure(1, weight=1)
        ttk.Button(self, text='Salvar', command=self.save).pack(pady=20)
        logger.debug('RegistrationWindow.__init__ exit')

    def save(self):
        logger.debug('RegistrationWindow.save entry')
        pw, cf = self.pwd.get(), self.cfm.get()
        if not pw or pw != cf:
            logger.warning('RegistrationWindow.save: senhas não conferem')
            messagebox.showwarning('Aviso', 'Senhas não conferem')
            return

        try:
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO users(username,password) VALUES(?,?)',
                ('admin', hash_password(pw))
            )
            conn.commit()
            conn.close()

            logger.info('Administrador criado com sucesso')
            messagebox.showinfo('Sucesso', 'Administrador criado')
            self.destroy()
            LoginWindow()
        except Exception as e:
            logger.exception('RegistrationWindow.save: erro ao criar admin')
            messagebox.showerror('Erro', 'Falha ao criar admin')
        finally:
            logger.debug('RegistrationWindow.save exit')


# Janela de login
class LoginWindow(BaseWindow):
    def __init__(self):
        logger.debug('LoginWindow.__init__ entry')
        super().__init__('OrçaFácil - Login')
        self.geometry('320x200')

        ttk.Label(self, text='Usuário: admin').pack(pady=10)
        self.entry = ttk.Entry(self, show='*')
        self.entry.pack(pady=5, padx=20, fill='x')
        ttk.Button(self, text='Entrar', command=self.login).pack(pady=20)
        logger.debug('LoginWindow.__init__ exit')

    def login(self):
        logger.debug('LoginWindow.login entry')
        pw = self.entry.get()
        try:
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute('SELECT password FROM users WHERE username=?', ('admin',))
            row = cur.fetchone()
            conn.close()

            if row and verify_password(row[0], pw):
                logger.info('LoginWindow.login: autenticação bem-sucedida')
                self.destroy()
                MainWindow()
            else:
                logger.warning('LoginWindow.login: senha incorreta')
                messagebox.showerror('Erro', 'Senha incorreta')
        except Exception:
            logger.exception('LoginWindow.login: falha ao verificar credenciais')
            messagebox.showerror('Erro', 'Falha no login')
        finally:
            logger.debug('LoginWindow.login exit')


# Janela de importação de mailing
class ImportWindow(BaseWindow):
    def __init__(self):
        logger.debug('ImportWindow.__init__ entry')
        super().__init__('OrçaFácil - Importar Mailing')
        self.geometry('600x450')

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='x')

        ttk.Button(frm, text='Selecionar arquivo', command=self.load_file).pack(side='left')
        ttk.Button(frm, text='Analisar dados', command=self.analyze_data).pack(side='left', padx=5)
        ttk.Button(frm, text='Importar dados', command=self.import_data).pack(side='left', padx=5)

        self.progress = ttk.Progressbar(self, mode='determinate')
        self.progress.pack(fill='x', padx=10, pady=5)
        self.log_console = tk.Text(self, height=15)
        self.log_console.pack(fill='both', padx=10, pady=5, expand=True)

        self.imported_path = None
        self.df = None
        self.mapping = {}
        self.map_vars = {}
        logger.debug('ImportWindow.__init__ exit')

    def load_file(self):
        logger.debug('ImportWindow.load_file entry')
        path = filedialog.askopenfilename(filetypes=[('Planilhas', '*.csv *.xls *.xlsx')])
        if not path:
            logger.debug('load_file: nenhum arquivo selecionado')
            return
        self.imported_path = path
        logger.info(f'load_file: arquivo selecionado {path}')
        self.log_console.insert(tk.END, f"Arquivo selecionado: {os.path.basename(path)}\n")

        try:
            if path.lower().endswith('.csv'):
                df0 = pd.read_csv(path, nrows=0)
            else:
                df0 = pd.read_excel(path, nrows=0)
            cols = list(df0.columns)
            logger.debug(f'load_file: cabeçalhos lidos {cols}')
            self.open_mapping_window(cols)
        except Exception:
            logger.exception('load_file: erro ao ler cabeçalhos para mapeamento')
            messagebox.showerror('Erro', 'Falha ao ler arquivo para mapeamento')
        finally:
            logger.debug('ImportWindow.load_file exit')

    def open_mapping_window(self, cols):
        logger.debug('ImportWindow.open_mapping_window entry')
        win = tk.Toplevel(self)
        win.title('Mapeamento de Colunas')
        altura = len(cols) * 40 + 60
        win.geometry(f'400x{altura}')

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill='both', expand=True)

        self.map_vars.clear()
        options = ['-- Ignorar --'] + list(SEARCH_FIELDS.keys())
        for i, col in enumerate(cols):
            ttk.Label(frame, text=col).grid(row=i, column=0, sticky='w', pady=5)
            var = tk.StringVar(value='-- Ignorar --')
            cb = ttk.Combobox(frame, values=options, textvariable=var, state='readonly')
            cb.grid(row=i, column=1, sticky='ew', padx=5)
            self.map_vars[col] = var

        ttk.Button(win, text='Confirmar', command=lambda: self.confirm_mapping(win)).pack(pady=10)
        logger.debug('ImportWindow.open_mapping_window exit')

    def confirm_mapping(self, win):
        logger.debug('ImportWindow.confirm_mapping entry')
        self.mapping.clear()
        for col, var in self.map_vars.items():
            escolha = var.get()
            if escolha != '-- Ignorar --':
                self.mapping[col] = SEARCH_FIELDS[escolha]

        win.destroy()
        if self.mapping:
            logger.info(f'confirm_mapping: mapeamento definido {self.mapping}')
            self.log_console.insert(tk.END,
                f"Mapeamento definido para colunas: {list(self.mapping.keys())}\n")
        else:
            logger.warning('confirm_mapping: nenhum mapeamento válido definido')
            self.log_console.insert(tk.END,
                "Nenhuma coluna mapeada. Você precisa mapear antes de importar.\n")
        logger.debug('ImportWindow.confirm_mapping exit')

    def analyze_data(self):
        logger.debug('ImportWindow.analyze_data entry')
        if not self.imported_path:
            logger.warning('analyze_data: nenhum arquivo selecionado')
            messagebox.showwarning('Aviso', 'Selecione um arquivo primeiro')
            return

        try:
            if self.imported_path.lower().endswith('.csv'):
                self.df = pd.read_csv(self.imported_path)
            else:
                self.df = pd.read_excel(self.imported_path)
            logger.debug(f'analyze_data: dataframe carregado com {len(self.df)} linhas')
        except Exception:
            logger.exception('analyze_data: erro ao ler arquivo completo')
            messagebox.showerror('Erro', 'Falha ao ler arquivo')
            return

        cols = list(self.df.columns)
        total_rows = len(self.df)
        self.log_console.insert(tk.END, f"Cabeçalhos: {cols}\n")
        self.log_console.insert(tk.END, f"Total registros: {total_rows}\n")
        missing = self.df.isnull().sum()
        for col, miss in missing.items():
            self.log_console.insert(tk.END, f"{col}: {miss} faltando\n")
        logger.info('analyze_data: análise concluída')
        logger.debug('ImportWindow.analyze_data exit')

    def import_data(self):
        logger.debug('ImportWindow.import_data entry')
        if not self.mapping:
            logger.warning('import_data: mapeamento não definido')
            messagebox.showwarning('Aviso', 'Defina o mapeamento antes de importar')
            return
        if self.df is None:
            logger.warning('import_data: dados não analisados')
            messagebox.showwarning('Aviso', 'Analise os dados antes de importar')
            return

        total = len(self.df)
        self.progress['maximum'] = total
        conn = sqlite3.connect(db_name)
        cur = conn.cursor()
        inserted = 0

        for i, row in self.df.iterrows():
            vals = []
            for fld in SEARCH_FIELDS.values():
                col_csv = next((c for c, f in self.mapping.items() if f == fld), None)
                vals.append(row[col_csv] if col_csv else '')
            try:
                cur.execute(
                    'INSERT INTO contacts (razao_social, cnpj, tipo, area, company_size, equip, email, phone, contact_name) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    tuple(vals)
                )
                inserted += 1
            except Exception:
                logger.exception(f'import_data: erro ao importar linha {i}')
            self.progress['value'] = i + 1
            self.update_idletasks()

        conn.commit()
        conn.close()
        self.log_console.insert(tk.END, f"Importação concluída: {inserted}/{total} registros.\n")
        logger.info(f'import_data: inseridos {inserted} de {total}')
        logger.debug('ImportWindow.import_data exit')

# Janela principal
class MainWindow(BaseWindow):
    def __init__(self):
        logger.debug('MainWindow.__init__ entry')
        super().__init__('OrçaFácil - Contatos')
        self.geometry('950x650')

        # Menu
        menu = tk.Menu(self)
        self.config(menu=menu)
        arquivo_menu = tk.Menu(menu, tearoff=False)
        arquivo_menu.add_command(label='Exportar CSV', command=self.export_csv)
        arquivo_menu.add_separator()
        arquivo_menu.add_command(label='Sair', command=self.quit)
        menu.add_cascade(label='Arquivo', menu=arquivo_menu)
        import_menu = tk.Menu(menu, tearoff=False)
        import_menu.add_command(label='Importar Mailing', command=lambda: ImportWindow())
        menu.add_cascade(label='Importação', menu=import_menu)

        # Busca
        sf = ttk.Frame(self, padding=5)
        sf.pack(fill='x')
        ttk.Label(sf, text='Campo:').pack(side='left')
        self.field_cb = ttk.Combobox(sf, values=list(SEARCH_FIELDS.keys()), state='readonly')
        self.field_cb.set('Todos')
        self.field_cb.pack(side='left', padx=(0,10))
        ttk.Label(sf, text='Termo:').pack(side='left')
        self.search_var = tk.StringVar()
        ttk.Entry(sf, textvariable=self.search_var).pack(side='left', padx=5, fill='x', expand=True)
        ttk.Button(sf, text='Buscar', command=self.search_contacts).pack(side='left', padx=5)
        ttk.Button(sf, text='Limpar', command=self.clear_search).pack(side='left')

        # Toolbar
        tb = ttk.Frame(self, padding=5)
        tb.pack(fill='x')
        icons = {n: load_icon(n) for n in ['add', 'edit', 'delete']}
        ttk.Button(tb, text='Adicionar', image=icons['add'], compound='left',
                   command=lambda: ContactForm(self)).pack(side='left', padx=5)
        ttk.Button(tb, text='Editar', image=icons['edit'], compound='left',
                   command=self.edit_contact).pack(side='left', padx=5)
        ttk.Button(tb, text='Excluir', image=icons['delete'], compound='left',
                   command=self.delete_contact).pack(side='left', padx=5)

        # Treeview
        self.columns = ('id','razao_social','cnpj','tipo','area','company_size','equip','email','phone','contact_name')
        self.tree = ttk.Treeview(self, columns=self.columns, show='headings')
        headers = ['Razão', 'CNPJ', 'Tipo', 'Área', 'Porte da Empresa', 'Equip', 'E-mail', 'Telefone', 'Contato']
        for col, head in zip(self.columns[1:], headers):
            self.tree.heading(col, text=head)
            self.tree.column(col, anchor='center', width=100)
        self.tree.pack(fill='both', expand=True, padx=10, pady=5)

        # Status bar
        self.status = ttk.Label(self, text='Total de contatos: 0', anchor='w')
        self.status.pack(fill='x', padx=5, pady=(0,5))

        self.load_contacts()
        logger.debug('MainWindow.__init__ exit')

    def load_contacts(self):
        logger.debug('MainWindow.load_contacts entry')
        try:
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute('SELECT id, razao_social, cnpj, tipo, area, company_size, equip, email, phone, contact_name FROM contacts')
            rows = cur.fetchall()
            conn.close()
            logger.info(f'load_contacts: carregados {len(rows)} contatos')
        except Exception:
            logger.exception('MainWindow.load_contacts: erro ao carregar contatos')
            messagebox.showerror('Erro', 'Falha ao carregar contatos')
            rows = []

        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert('', tk.END, values=row)
        self.status.config(text=f'Total de contatos: {len(rows)}')
        logger.debug('MainWindow.load_contacts exit')

    def search_contacts(self):
        logger.debug('MainWindow.search_contacts entry')
        field = SEARCH_FIELDS[self.field_cb.get()]
        term = self.search_var.get().strip()
        if not term:
            logger.warning('search_contacts: termo vazio')
            messagebox.showwarning('Aviso', 'Digite um termo para buscar')
            return

        base_sql = 'SELECT id, razao_social, cnpj, tipo, area, company_size, equip, email, phone, contact_name FROM contacts'
        if field:
            sql = f"{base_sql} WHERE {field} LIKE ?"
            params = [f"%{term}%"]
        else:
            clauses = [f"{c} LIKE ?" for c in SEARCH_FIELDS.values() if c]
            sql = f"{base_sql} WHERE {' OR '.join(clauses)}"
            params = [f"%{term}%"] * len(clauses)

        try:
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            conn.close()
            logger.info(f'search_contacts: encontrados {len(rows)} resultados para "{term}"')
        except Exception:
            logger.exception('MainWindow.search_contacts: erro na busca')
            messagebox.showerror('Erro', 'Falha na busca')
            return

        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert('', tk.END, values=row)
        self.status.config(text=f'Total de contatos: {len(rows)}')
        logger.debug('MainWindow.search_contacts exit')

    def clear_search(self):
        logger.debug('MainWindow.clear_search entry')
        self.search_var.set('')
        self.field_cb.set('Todos')
        self.load_contacts()
        logger.debug('MainWindow.clear_search exit')

    def export_csv(self):
        logger.debug('MainWindow.export_csv entry')
        path = filedialog.asksaveasfilename(defaultextension='.csv')
        if not path:
            logger.debug('export_csv: operação cancelada pelo usuário')
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Razão Social','CNPJ','Tipo','Área','Porte da Empresa','Equip','E-mail','Telefone','Contato'])
                for iid in self.tree.get_children():
                    writer.writerow(self.tree.item(iid)['values'][1:])
            messagebox.showinfo('Sucesso', 'Exportado com sucesso')
            logger.info(f'export_csv: dados exportados para {path}')
        except Exception:
            logger.exception('MainWindow.export_csv: erro ao exportar CSV')
            messagebox.showerror('Erro', 'Falha ao exportar CSV')
        finally:
            logger.debug('MainWindow.export_csv exit')

    def edit_contact(self):
        logger.debug('MainWindow.edit_contact entry')
        selected = self.tree.focus()
        if not selected:
            logger.warning('edit_contact: nenhum contato selecionado')
            messagebox.showwarning('Aviso', 'Selecione um contato')
            return
        cid = self.tree.item(selected)['values'][0]
        try:
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute('SELECT razao_social, cnpj, tipo, area, company_size, equip, email, phone, contact_name FROM contacts WHERE id=?', (cid,))
            data = cur.fetchone()
            conn.close()
            logger.info(f'edit_contact: carregando contato id={cid}')
            ContactForm(self, cid, data)
        except Exception:
            logger.exception('MainWindow.edit_contact: erro ao buscar contato')
            messagebox.showerror('Erro', 'Falha ao carregar dados do contato')
        finally:
            logger.debug('MainWindow.edit_contact exit')

    def delete_contact(self):
        logger.debug('MainWindow.delete_contact entry')
        selected = self.tree.focus()
        if not selected:
            logger.warning('delete_contact: nenhum contato selecionado')
            messagebox.showwarning('Aviso', 'Selecione um contato')
            return
        if not messagebox.askyesno('Confirmação', 'Excluir contato?'):
            logger.debug('delete_contact: usuário cancelou exclusão')
            return
        cid = self.tree.item(selected)['values'][0]
        try:
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute('DELETE FROM contacts WHERE id=?', (cid,))
            conn.commit()
            conn.close()
            logger.info(f'delete_contact: contato id={cid} excluído')
            self.load_contacts()
        except Exception:
            logger.exception('MainWindow.delete_contact: erro ao excluir contato')
            messagebox.showerror('Erro', 'Falha ao excluir contato')
        finally:
            logger.debug('MainWindow.delete_contact exit')


# Formulário de Contato
def ContactForm(parent, cid=None, data=None):
    win = tk.Toplevel(parent)
    win.title('Contato')
    win.configure(bg=PRIMARY_BG)
    win.columnconfigure(1, weight=1)
    fields = [
        ('Razão Social', 'entry'),
        ('CNPJ', 'entry'),
        ('Tipo', 'combo', TIPO_OPTIONS),
        ('Área', 'combo', AREA_OPTIONS),
        ('Porte da Empresa', 'combo', COMPANY_SIZE_OPTIONS),
        ('Equip./Serviços', 'combo', EQUIP_OPTIONS),
        ('E-mail*', 'entry'),
        ('Telefone', 'entry'),
        ('Contato', 'entry'),
    ]
    widgets = {}
    for i, (label, typ, *opts) in enumerate(fields):
        ttk.Label(win, text=f"{label}:").grid(row=i, column=0, padx=10, pady=5, sticky='w')
        if typ == 'combo':
            cb = ttk.Combobox(win, values=opts[0], state='readonly')
            cb.grid(row=i, column=1, sticky='ew', padx=10)
            widgets[label] = cb
            if label in ('Área', 'Equip./Serviços'):
                ttk.Button(win, text='+', width=3, command=lambda l=label: simpledialog.askstring('Nova opção', f'Digite nova {l}:')).grid(row=i, column=2)
        else:
            e = ttk.Entry(win)
            e.grid(row=i, column=1, sticky='ew', padx=10)
            widgets[label] = e
            if label == 'CNPJ':
                e.bind('<FocusOut>', lambda ev, w=e: format_cnpj_event(w))
    if data:
        for (label, *_), val in zip(fields, data):
            w = widgets[label]
            if isinstance(w, ttk.Combobox):
                w.set(val)
            else:
                w.insert(0, val or '')
    btnf = ttk.Frame(win)
    btnf.grid(row=len(fields), column=0, columnspan=3, pady=15)
    ttk.Button(btnf, text='Salvar', command=lambda: save_contact(win, parent, cid, widgets)).pack(side='left', padx=5)
    ttk.Button(btnf, text='Cancelar', command=win.destroy).pack(side='left', padx=5)
    return win

def save_contact(win, parent, cid, widgets):
    r = widgets['Razão Social'].get().strip()
    cnpj = widgets['CNPJ'].get().strip()
    tipo = widgets['Tipo'].get()
    area = widgets['Área'].get()
    size = widgets['Porte da Empresa'].get()
    equip = widgets['Equip./Serviços'].get()
    email = widgets['E-mail*'].get().strip()
    phone = widgets['Telefone'].get().strip()
    contato = widgets['Contato'].get().strip()
    if not all([r, cnpj, tipo, area, size, equip, email]):
        messagebox.showwarning('Aviso', 'Campos obrigatórios faltando')
        return
    try:
        conn = sqlite3.connect(db_name)
        cur = conn.cursor()
        if cid:
            cur.execute(
                'UPDATE contacts SET razao_social=?, cnpj=?, tipo=?, area=?, company_size=?, equip=?, email=?, phone=?, contact_name=? WHERE id=?',
                (r, cnpj, tipo, area, size, equip, email, phone, contato, cid)
            )
        else:
            cur.execute(
                'INSERT INTO contacts (razao_social, cnpj, tipo, area, company_size, equip, email, phone, contact_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (r, cnpj, tipo, area, size, equip, email, phone, contato)
            )
        conn.commit()
        conn.close()
        parent.load_contacts()
        win.destroy()
    except Exception:
        logging.exception('Erro ao salvar contato')
        messagebox.showerror('Erro', 'Falha ao salvar contato')

if __name__ == '__main__':
    init_db()
    conn = sqlite3.connect(db_name)
    first = conn.cursor().execute("SELECT COUNT(*) FROM users WHERE username='admin'").fetchone()[0] == 0
    conn.close()
    if first:
        RegistrationWindow()
    else:
        LoginWindow()
    tk.mainloop()
