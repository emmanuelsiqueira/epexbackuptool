import os
import sys
import argparse
import shutil
import hashlib
from datetime import datetime
import zipfile
import pyzipper
import logging
from pathlib import Path

# Configuração do logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('EpexBackupTool')

class EpexBackupTool:
    def __init__(self):
        self.version = "1.0"
        self.author = "Emmanuel Siqueira | Coordenador Geral de Informática"
        self.banner = f"""
        #############################################
        #          Epex Backup Tool v{self.version} #
        #  Criado por {self.author}                 #
        #############################################
        """
        
    def print_banner(self):
        print(self.banner)
    
    def calculate_hash(self, file_path, hash_type='sha256'):
        """Calcula o hash de um arquivo"""
        hash_func = hashlib.sha256() if hash_type == 'sha256' else hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def create_backup(self, source, destination, password=None, max_age_days=None):
        """Cria um backup do arquivo ou diretório"""
        try:
            # Verifica se o source existe
            if not os.path.exists(source):
                raise FileNotFoundError(f"Origem não encontrada: {source}")
            
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
            
            # Gera informações para o log
            log_content = self._generate_log_content(source, backup_path, timestamp, password is not None)
            
            # Escreve o log
            with open(log_path, 'w') as log_file:
                log_file.write(log_content)
            
            logger.info(f"Backup criado com sucesso: {backup_path}")
            logger.info(f"Log gerado: {log_path}")
            
            return True
        except Exception as e:
            logger.error(f"Erro ao criar backup: {str(e)}")
            return False
    
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
    
    def restore_backup(self, backup_file, destination, password=None):
        """Restaura um backup criptografado ou não"""
        try:
            # Verifica se o arquivo de backup existe
            if not os.path.exists(backup_file):
                raise FileNotFoundError(f"Arquivo de backup não encontrado: {backup_file}")
            
            # Cria diretório de destino se não existir
            os.makedirs(destination, exist_ok=True)
            
            if backup_file.endswith('.zip'):
                if password:
                    # Backup criptografado
                    with pyzipper.AESZipFile(backup_file) as zf:
                        zf.setpassword(password.encode())
                        zf.extractall(destination)
                else:
                    # Backup ZIP normal
                    with zipfile.ZipFile(backup_file, 'r') as zf:
                        zf.extractall(destination)
            else:
                # Backup de arquivo único não criptografado
                shutil.copy2(backup_file, destination)
            
            logger.info(f"Backup restaurado com sucesso para: {destination}")
            return True
        except Exception as e:
            logger.error(f"Erro ao restaurar backup: {str(e)}")
            return False
    
    def verify_backup(self, backup_file, original_hash=None, password=None):
        """Verifica a integridade de um backup"""
        try:
            # Verifica se o arquivo existe
            if not os.path.exists(backup_file):
                raise FileNotFoundError(f"Arquivo de backup não encontrado: {backup_file}")
            
            # Calcula o hash atual
            current_hash = self.calculate_hash(backup_file)
            
            # Verifica se é um ZIP válido (se for o caso)
            if backup_file.endswith('.zip'):
                try:
                    if password:
                        with pyzipper.AESZipFile(backup_file) as zf:
                            zf.setpassword(password.encode())
                            # Tenta ler a lista de arquivos para verificar a senha
                            zf.filelist
                    else:
                        with zipfile.ZipFile(backup_file, 'r') as zf:
                            # Testa a integridade do ZIP
                            bad_file = zf.testzip()
                            if bad_file is not None:
                                raise ValueError(f"Arquivo corrompido no ZIP: {bad_file}")
                except Exception as e:
                    logger.error(f"Verificação do arquivo ZIP falhou: {str(e)}")
                    return False
            
            # Compara com o hash original se fornecido
            if original_hash:
                if current_hash == original_hash:
                    logger.info("Verificação bem-sucedida: hash corresponde ao original")
                    return True
                else:
                    logger.error("Falha na verificação: hash não corresponde ao original")
                    return False
            else:
                logger.info(f"Hash SHA-256 do backup: {current_hash}")
                return True
        except Exception as e:
            logger.error(f"Erro ao verificar backup: {str(e)}")
            return False

def main():
    backup_tool = EpexBackupTool()
    backup_tool.print_banner()
    
    parser = argparse.ArgumentParser(description='Epex Backup Tool - Ferramenta de backup com criptografia')
    
    # Comandos principais
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponíveis', required=True)
    
    # Comando create
    create_parser = subparsers.add_parser('create', help='Criar um novo backup')
    create_parser.add_argument('-s', '--source', required=True, help='Arquivo ou diretório de origem')
    create_parser.add_argument('-d', '--destination', required=True, help='Diretório de destino do backup')
    create_parser.add_argument('-p', '--password', help='Senha para criptografar o backup (opcional)')
    create_parser.add_argument('-a', '--max-age-days', type=int, 
                             help='Número máximo de dias para manter backups antigos (opcional)')
    
    # Comando restore
    restore_parser = subparsers.add_parser('restore', help='Restaurar um backup')
    restore_parser.add_argument('-b', '--backup-file', required=True, help='Arquivo de backup para restaurar')
    restore_parser.add_argument('-d', '--destination', required=True, help='Diretório de destino da restauração')
    restore_parser.add_argument('-p', '--password', help='Senha para descriptografar o backup (se necessário)')
    
    # Comando verify
    verify_parser = subparsers.add_parser('verify', help='Verificar a integridade de um backup')
    verify_parser.add_argument('-b', '--backup-file', required=True, help='Arquivo de backup para verificar')
    verify_parser.add_argument('-p', '--password', help='Senha para verificar backup criptografado (se necessário)')
    verify_parser.add_argument('--original-hash', help='Hash SHA-256 original para comparação (opcional)')
    
    # Comando delete-old
    delete_parser = subparsers.add_parser('delete-old', help='Excluir backups antigos')
    delete_parser.add_argument('-d', '--directory', required=True, help='Diretório contendo os backups')
    delete_parser.add_argument('-a', '--max-age-days', type=int, required=True, 
                             help='Número máximo de dias para manter backups')
    
    args = parser.parse_args()
    
    try:
        if args.command == 'create':
            success = backup_tool.create_backup(
                args.source, 
                args.destination, 
                args.password, 
                args.max_age_days
            )
        elif args.command == 'restore':
            success = backup_tool.restore_backup(
                args.backup_file, 
                args.destination, 
                args.password
            )
        elif args.command == 'verify':
            success = backup_tool.verify_backup(
                args.backup_file, 
                args.original_hash, 
                args.password
            )
        elif args.command == 'delete-old':
            deleted = backup_tool.delete_old_backups(
                args.directory, 
                args.max_age_days
            )
            success = deleted >= 0
        else:
            logger.error("Comando inválido")
            success = False
        
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Erro durante a execução: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()