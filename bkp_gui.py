import os
import shutil
import hashlib
from datetime import datetime
import zipfile
import pyzipper
import logging
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from threading import Thread

# Configuração do logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('EpexBackupToolGUI')

class EpexBackupToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Epex Backup Tool")
        self.version = "1.0"
        self.author = "Emmanuel Siqueira"
        
        # Configuração do estilo
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('TCombobox', font=('Arial', 10))
        
        # Cabeçalho
        self.header_frame = ttk.Frame(root, padding="10")
        self.header_frame.pack(fill=X)
        
        self.title_label = Label(self.header_frame, 
                               text=f"Epex Backup Tool v{self.version}\nCriado por {self.author}",
                               font=('Arial', 12, 'bold'),
                               background='#f0f0f0')
        self.title_label.pack()
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Aba de Backup
        self.create_backup_tab()
        
        # Aba de Restauração
        self.create_restore_tab()
        
        # Aba de Verificação
        self.create_verify_tab()
        
        # Aba de Limpeza
        self.create_cleanup_tab()
        
        # Barra de status
        self.status_var = StringVar()
        self.status_var.set("Pronto")
        self.status_bar = Label(root, textvariable=self.status_var, 
                               relief=SUNKEN, anchor=W, 
                               font=('Arial', 9), background='#e0e0e0')
        self.status_bar.pack(fill=X, side=BOTTOM)
        
        # Configuração do redimensionamento
        root.minsize(600, 500)
        root.geometry("700x550")
    
    def create_backup_tab(self):
        """Cria a aba de backup"""
        self.backup_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.backup_frame, text="Criar Backup")
        
        # Origem
        ttk.Label(self.backup_frame, text="Origem:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.source_entry = ttk.Entry(self.backup_frame, width=50)
        self.source_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.backup_frame, text="Procurar", 
                  command=self.browse_source).grid(row=0, column=2, padx=5, pady=5)
        
        # Destino
        ttk.Label(self.backup_frame, text="Destino:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.dest_entry = ttk.Entry(self.backup_frame, width=50)
        self.dest_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.backup_frame, text="Procurar", 
                  command=self.browse_destination).grid(row=1, column=2, padx=5, pady=5)
        
        # Senha
        ttk.Label(self.backup_frame, text="Senha (opcional):").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.backup_frame, width=50, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Manter backups por (dias)
        ttk.Label(self.backup_frame, text="Manter backups por (dias):").grid(row=3, column=0, sticky=W, padx=5, pady=5)
        self.max_age_spinbox = Spinbox(self.backup_frame, from_=1, to=365, width=5)
        self.max_age_spinbox.grid(row=3, column=1, sticky=W, padx=5, pady=5)
        self.max_age_spinbox.delete(0, "end")
        self.max_age_spinbox.insert(0, "30")
        
        # Botão de backup
        self.backup_button = ttk.Button(self.backup_frame, text="Criar Backup", 
                                      command=self.start_backup_thread)
        self.backup_button.grid(row=4, column=1, pady=10)
        
        # Barra de progresso
        self.backup_progress = ttk.Progressbar(self.backup_frame, orient=HORIZONTAL, length=400, mode='determinate')
        self.backup_progress.grid(row=5, column=0, columnspan=3, pady=10)
        
        # Configuração do grid
        for child in self.backup_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
    
    def create_restore_tab(self):
        """Cria a aba de restauração"""
        self.restore_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.restore_frame, text="Restaurar Backup")
        
        # Arquivo de backup
        ttk.Label(self.restore_frame, text="Arquivo de backup:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.restore_file_entry = ttk.Entry(self.restore_frame, width=50)
        self.restore_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.restore_frame, text="Procurar", 
                  command=self.browse_restore_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Destino
        ttk.Label(self.restore_frame, text="Destino da restauração:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.restore_dest_entry = ttk.Entry(self.restore_frame, width=50)
        self.restore_dest_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.restore_frame, text="Procurar", 
                  command=self.browse_restore_destination).grid(row=1, column=2, padx=5, pady=5)
        
        # Senha
        ttk.Label(self.restore_frame, text="Senha (se criptografado):").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        self.restore_password_entry = ttk.Entry(self.restore_frame, width=50, show="*")
        self.restore_password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Botão de restauração
        self.restore_button = ttk.Button(self.restore_frame, text="Restaurar Backup", 
                                       command=self.start_restore_thread)
        self.restore_button.grid(row=3, column=1, pady=10)
        
        # Barra de progresso
        self.restore_progress = ttk.Progressbar(self.restore_frame, orient=HORIZONTAL, length=400, mode='determinate')
        self.restore_progress.grid(row=4, column=0, columnspan=3, pady=10)
        
        # Configuração do grid
        for child in self.restore_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
    
    def create_verify_tab(self):
        """Cria a aba de verificação"""
        self.verify_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.verify_frame, text="Verificar Backup")
        
        # Arquivo de backup
        ttk.Label(self.verify_frame, text="Arquivo de backup:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.verify_file_entry = ttk.Entry(self.verify_frame, width=50)
        self.verify_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.verify_frame, text="Procurar", 
                  command=self.browse_verify_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Senha
        ttk.Label(self.verify_frame, text="Senha (se criptografado):").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.verify_password_entry = ttk.Entry(self.verify_frame, width=50, show="*")
        self.verify_password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Hash original
        ttk.Label(self.verify_frame, text="Hash original (opcional):").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        self.original_hash_entry = ttk.Entry(self.verify_frame, width=50)
        self.original_hash_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Botão de verificação
        self.verify_button = ttk.Button(self.verify_frame, text="Verificar Backup", 
                                       command=self.start_verify_thread)
        self.verify_button.grid(row=3, column=1, pady=10)
        
        # Resultado
        self.verify_result = Text(self.verify_frame, height=5, width=60, wrap=WORD, state=DISABLED)
        self.verify_result.grid(row=4, column=0, columnspan=3, pady=10)
        
        # Configuração do grid
        for child in self.verify_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
    
    def create_cleanup_tab(self):
        """Cria a aba de limpeza"""
        self.cleanup_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cleanup_frame, text="Limpar Backups Antigos")
        
        # Diretório
        ttk.Label(self.cleanup_frame, text="Diretório dos backups:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.cleanup_dir_entry = ttk.Entry(self.cleanup_frame, width=50)
        self.cleanup_dir_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.cleanup_frame, text="Procurar", 
                  command=self.browse_cleanup_dir).grid(row=0, column=2, padx=5, pady=5)
        
        # Manter backups por (dias)
        ttk.Label(self.cleanup_frame, text="Manter backups por (dias):").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.cleanup_days_spinbox = Spinbox(self.cleanup_frame, from_=1, to=365, width=5)
        self.cleanup_days_spinbox.grid(row=1, column=1, sticky=W, padx=5, pady=5)
        self.cleanup_days_spinbox.delete(0, "end")
        self.cleanup_days_spinbox.insert(0, "30")
        
        # Botão de limpeza
        self.cleanup_button = ttk.Button(self.cleanup_frame, text="Limpar Backups Antigos", 
                                       command=self.start_cleanup_thread)
        self.cleanup_button.grid(row=2, column=1, pady=10)
        
        # Resultado
        self.cleanup_result = Text(self.cleanup_frame, height=5, width=60, wrap=WORD, state=DISABLED)
        self.cleanup_result.grid(row=3, column=0, columnspan=3, pady=10)
        
        # Configuração do grid
        for child in self.cleanup_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
    
    # Métodos auxiliares para navegação de arquivos
    def browse_source(self):
        path = filedialog.askopenfilename()
        if path:
            self.source_entry.delete(0, END)
            self.source_entry.insert(0, path)
    
    def browse_destination(self):
        path = filedialog.askdirectory()
        if path:
            self.dest_entry.delete(0, END)
            self.dest_entry.insert(0, path)
    
    def browse_restore_file(self):
        path = filedialog.askopenfilename(filetypes=[("Arquivos ZIP", "*.zip"), ("Todos os arquivos", "*.*")])
        if path:
            self.restore_file_entry.delete(0, END)
            self.restore_file_entry.insert(0, path)
    
    def browse_restore_destination(self):
        path = filedialog.askdirectory()
        if path:
            self.restore_dest_entry.delete(0, END)
            self.restore_dest_entry.insert(0, path)
    
    def browse_verify_file(self):
        path = filedialog.askopenfilename(filetypes=[("Arquivos ZIP", "*.zip"), ("Todos os arquivos", "*.*")])
        if path:
            self.verify_file_entry.delete(0, END)
            self.verify_file_entry.insert(0, path)
    
    def browse_cleanup_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.cleanup_dir_entry.delete(0, END)
            self.cleanup_dir_entry.insert(0, path)
    
    # Métodos para executar em threads
    def start_backup_thread(self):
        self.backup_button.config(state=DISABLED)
        self.status_var.set("Criando backup...")
        Thread(target=self.create_backup, daemon=True).start()
    
    def start_restore_thread(self):
        self.restore_button.config(state=DISABLED)
        self.status_var.set("Restaurando backup...")
        Thread(target=self.restore_backup, daemon=True).start()
    
    def start_verify_thread(self):
        self.verify_button.config(state=DISABLED)
        self.status_var.set("Verificando backup...")
        Thread(target=self.verify_backup, daemon=True).start()
    
    def start_cleanup_thread(self):
        self.cleanup_button.config(state=DISABLED)
        self.status_var.set("Limpando backups antigos...")
        Thread(target=self.cleanup_backups, daemon=True).start()
    
    # Métodos principais
    def calculate_hash(self, file_path, hash_type='sha256'):
        """Calcula o hash de um arquivo"""
        hash_func = hashlib.sha256() if hash_type == 'sha256' else hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def create_backup(self):
        """Cria um backup do arquivo ou diretório"""
        try:
            source = self.source_entry.get()
            destination = self.dest_entry.get()
            password = self.password_entry.get() or None
            max_age_days = int(self.max_age_spinbox.get()) if self.max_age_spinbox.get() else None
            
            # Verifica se o source existe
            if not source or not os.path.exists(source):
                messagebox.showerror("Erro", "Origem não especificada ou não encontrada!")
                return
            
            # Verifica o destino
            if not destination:
                messagebox.showerror("Erro", "Destino não especificado!")
                return
            
            # Cria diretório de destino se não existir
            os.makedirs(destination, exist_ok=True)
            
            # Remove backups antigos se especificado
            if max_age_days:
                self.delete_old_backups(destination, max_age_days)
            
            # Gera nome do arquivo de backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}"
            backup_path = os.path.join(destination, backup_name)
            
            # Cria o log file
            log_filename = f"backup_log_{timestamp}.txt"
            log_path = os.path.join(destination, log_filename)
            
            # Atualiza a barra de progresso
            self.backup_progress['value'] = 10
            self.root.update_idletasks()
            
            # Cria o backup
            if os.path.isfile(source):
                # Backup de arquivo único
                if password:
                    backup_path += '.zip'
                    self._encrypt_file(source, backup_path, password)
                else:
                    shutil.copy2(source, backup_path)
            else:
                # Backup de diretório
                if password:
                    backup_path += '.zip'
                    self._encrypt_directory(source, backup_path, password)
                else:
                    backup_path += '.zip'
                    shutil.make_archive(backup_path.replace('.zip', ''), 'zip', source)
            
            # Atualiza a barra de progresso
            self.backup_progress['value'] = 70
            self.root.update_idletasks()
            
            # Gera informações para o log
            log_content = self._generate_log_content(source, backup_path, timestamp, password is not None)
            
            # Escreve o log
            with open(log_path, 'w') as log_file:
                log_file.write(log_content)
            
            # Atualiza a barra de progresso
            self.backup_progress['value'] = 100
            self.root.update_idletasks()
            
            messagebox.showinfo("Sucesso", f"Backup criado com sucesso:\n{backup_path}")
            self.status_var.set("Backup criado com sucesso")
            
        except Exception as e:
            logger.error(f"Erro ao criar backup: {str(e)}")
            messagebox.showerror("Erro", f"Falha ao criar backup:\n{str(e)}")
            self.status_var.set("Erro ao criar backup")
        finally:
            self.backup_button.config(state=NORMAL)
            self.backup_progress['value'] = 0
    
    def _encrypt_file(self, source, destination, password):
        """Criptografa um arquivo único com senha"""
        with pyzipper.AESZipFile(destination, 'w', compression=pyzipper.ZIP_LZMA) as zf:
            zf.setpassword(password.encode())
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            zf.write(source, os.path.basename(source))
    
    def _encrypt_directory(self, source, destination, password):
        """Criptografa um diretório com senha"""
        with pyzipper.AESZipFile(destination, 'w', compression=pyzipper.ZIP_LZMA) as zf:
            zf.setpassword(password.encode())
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            for root, dirs, files in os.walk(source):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=source)
                    zf.write(file_path, arcname)
                    # Atualiza a barra de progresso incrementalmente
                    self.backup_progress['value'] += 30/len(files)
                    self.root.update_idletasks()
    
    def _generate_log_content(self, source, backup_path, timestamp, encrypted):
        """Gera o conteúdo do arquivo de log"""
        backup_size = os.path.getsize(backup_path)
        backup_hash = self.calculate_hash(backup_path)
        
        content = [
            "Epex Backup Tool - Log de Backup",
            f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Origem: {source}",
            f"Backup: {backup_path}",
            f"Tamanho do backup: {backup_size} bytes",
            f"SHA-256 do backup: {backup_hash}",
            f"Criptografado: {'Sim' if encrypted else 'Não'}",
            "",
            "Metadados:",
            f"Versão do Epex Backup Tool: {self.version}",
            f"Criado por: {self.author}"
        ]
        
        return '\n'.join(content)
    
    def delete_old_backups(self, directory, max_age_days):
        """Exclui backups mais antigos que max_age_days"""
        try:
            now = datetime.now()
            cutoff = now.timestamp() - (max_age_days * 86400)
            
            deleted_files = 0
            
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    # Verifica se é um arquivo de backup ou log
                    if filename.startswith('backup_') or filename.startswith('backup_log_'):
                        file_time = os.path.getmtime(filepath)
                        if file_time < cutoff:
                            try:
                                os.remove(filepath)
                                logger.info(f"Backup antigo removido: {filename}")
                                deleted_files += 1
                            except Exception as e:
                                logger.error(f"Erro ao remover backup antigo {filename}: {str(e)}")
            
            logger.info(f"Total de backups antigos removidos: {deleted_files}")
            return deleted_files
        except Exception as e:
            logger.error(f"Erro ao excluir backups antigos: {str(e)}")
            return 0
    
    def restore_backup(self):
        """Restaura um backup criptografado ou não"""
        try:
            backup_file = self.restore_file_entry.get()
            destination = self.restore_dest_entry.get()
            password = self.restore_password_entry.get() or None
            
            # Verifica se o arquivo de backup existe
            if not backup_file or not os.path.exists(backup_file):
                messagebox.showerror("Erro", "Arquivo de backup não especificado ou não encontrado!")
                return
            
            # Verifica o destino
            if not destination:
                messagebox.showerror("Erro", "Destino da restauração não especificado!")
                return
            
            # Cria diretório de destino se não existir
            os.makedirs(destination, exist_ok=True)
            
            self.restore_progress['value'] = 20
            self.root.update_idletasks()
            
            if backup_file.endswith('.zip'):
                if password:
                    # Backup criptografado
                    with pyzipper.AESZipFile(backup_file) as zf:
                        zf.setpassword(password.encode())
                        file_list = zf.filelist
                        total_files = len(file_list)
                        
                        for i, file_info in enumerate(file_list, 1):
                            zf.extract(file_info, destination)
                            progress = 20 + (i / total_files) * 80
                            self.restore_progress['value'] = progress
                            self.root.update_idletasks()
                else:
                    # Backup ZIP normal
                    with zipfile.ZipFile(backup_file, 'r') as zf:
                        file_list = zf.filelist
                        total_files = len(file_list)
                        
                        for i, file_info in enumerate(file_list, 1):
                            zf.extract(file_info, destination)
                            progress = 20 + (i / total_files) * 80
                            self.restore_progress['value'] = progress
                            self.root.update_idletasks()
            else:
                # Backup de arquivo único não criptografado
                shutil.copy2(backup_file, destination)
                self.restore_progress['value'] = 100
                self.root.update_idletasks()
            
            messagebox.showinfo("Sucesso", f"Backup restaurado com sucesso para:\n{destination}")
            self.status_var.set("Backup restaurado com sucesso")
            
        except Exception as e:
            logger.error(f"Erro ao restaurar backup: {str(e)}")
            messagebox.showerror("Erro", f"Falha ao restaurar backup:\n{str(e)}")
            self.status_var.set("Erro ao restaurar backup")
        finally:
            self.restore_button.config(state=NORMAL)
            self.restore_progress['value'] = 0
    
    def verify_backup(self):
        """Verifica a integridade de um backup"""
        try:
            backup_file = self.verify_file_entry.get()
            password = self.verify_password_entry.get() or None
            original_hash = self.original_hash_entry.get() or None
            
            # Verifica se o arquivo existe
            if not backup_file or not os.path.exists(backup_file):
                messagebox.showerror("Erro", "Arquivo de backup não especificado ou não encontrado!")
                return
            
            self.verify_result.config(state=NORMAL)
            self.verify_result.delete(1.0, END)
            
            # Calcula o hash atual
            current_hash = self.calculate_hash(backup_file)
            self.verify_result.insert(END, f"Hash SHA-256 calculado: {current_hash}\n\n")
            
            # Verifica se é um ZIP válido (se for o caso)
            if backup_file.endswith('.zip'):
                try:
                    if password:
                        with pyzipper.AESZipFile(backup_file) as zf:
                            zf.setpassword(password.encode())
                            # Tenta ler a lista de arquivos para verificar a senha
                            file_list = zf.filelist
                            self.verify_result.insert(END, f"Arquivo ZIP válido com {len(file_list)} arquivos.\n")
                            self.verify_result.insert(END, "Senha correta.\n")
                    else:
                        with zipfile.ZipFile(backup_file, 'r') as zf:
                            # Testa a integridade do ZIP
                            bad_file = zf.testzip()
                            if bad_file is not None:
                                raise ValueError(f"Arquivo corrompido no ZIP: {bad_file}")
                            self.verify_result.insert(END, "Arquivo ZIP válido e íntegro.\n")
                except Exception as e:
                    self.verify_result.insert(END, f"ERRO: {str(e)}\n")
                    self.verify_result.tag_add("error", "1.0", END)
                    self.verify_result.tag_config("error", foreground="red")
            
            # Compara com o hash original se fornecido
            if original_hash:
                if current_hash.lower() == original_hash.lower():
                    self.verify_result.insert(END, "\nVERIFICAÇÃO BEM-SUCEDIDA: hash corresponde ao original!")
                    self.verify_result.tag_add("success", "end-1l", END)
                    self.verify_result.tag_config("success", foreground="green")
                else:
                    self.verify_result.insert(END, "\nFALHA NA VERIFICAÇÃO: hash não corresponde ao original!")
                    self.verify_result.tag_add("error", "end-1l", END)
                    self.verify_result.tag_config("error", foreground="red")
            
            self.status_var.set("Verificação concluída")
            
        except Exception as e:
            logger.error(f"Erro ao verificar backup: {str(e)}")
            self.verify_result.insert(END, f"ERRO: {str(e)}")
            self.verify_result.tag_add("error", "1.0", END)
            self.verify_result.tag_config("error", foreground="red")
            self.status_var.set("Erro na verificação")
        finally:
            self.verify_button.config(state=NORMAL)
            self.verify_result.config(state=DISABLED)
    
    def cleanup_backups(self):
        """Limpa backups antigos"""
        try:
            directory = self.cleanup_dir_entry.get()
            max_age_days = int(self.cleanup_days_spinbox.get()) if self.cleanup_days_spinbox.get() else None
            
            # Verifica o diretório
            if not directory or not os.path.isdir(directory):
                messagebox.showerror("Erro", "Diretório não especificado ou inválido!")
                return
            
            if not max_age_days or max_age_days <= 0:
                messagebox.showerror("Erro", "Número de dias inválido!")
                return
            
            self.cleanup_result.config(state=NORMAL)
            self.cleanup_result.delete(1.0, END)
            
            deleted = self.delete_old_backups(directory, max_age_days)
            
            self.cleanup_result.insert(END, f"Limpeza concluída.\n")
            self.cleanup_result.insert(END, f"Total de backups antigos removidos: {deleted}\n")
            self.cleanup_result.insert(END, f"Backups mantidos: últimos {max_age_days} dias")
            
            self.status_var.set("Limpeza de backups concluída")
            
        except Exception as e:
            logger.error(f"Erro ao limpar backups: {str(e)}")
            self.cleanup_result.insert(END, f"ERRO: {str(e)}")
            self.cleanup_result.tag_add("error", "1.0", END)
            self.cleanup_result.tag_config("error", foreground="red")
            self.status_var.set("Erro na limpeza de backups")
        finally:
            self.cleanup_button.config(state=NORMAL)
            self.cleanup_result.config(state=DISABLED)

def main():
    root = Tk()
    app = EpexBackupToolGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()