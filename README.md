# epexbackuptool
Como usar o Epex Backup Tool
Pré-requisitos
Python 3.6 ou superior

Biblioteca pyzipper (para criptografia AES-256): pip install pyzipper

Comandos disponíveis

Criar backup:
python backup_tool.py create -s [origem] -d [destino] [-p senha] [-a dias]
Exemplo:
python backup_tool.py create -s /caminho/para/arquivo -d /backups -p minhasenha -a 30

Restaurar backup:
python backup_tool.py restore -b [arquivo_backup] -d [destino] [-p senha]
Exemplo:
python backup_tool.py restore -b /backups/backup_20250101_120000.zip -d /restore -p minhasenha
Verificar backup:
python backup_tool.py verify -b [arquivo_backup] [-p senha] [--original-hash HASH]
Exemplo:
python backup_tool.py verify -b /backups/backup_20250101_120000.zip -p minhasenha
Excluir backups antigos:
python backup_tool.py delete-old -d [diretorio] -a [dias]
Exemplo:
python backup_tool.py delete-old -d /backups -a 30

Funcionalidades implementadas
- Backup de arquivos únicos ou diretórios completos
- Criptografia AES-256 com senha
- Descriptografia com senha
- Exclusão automática de backups antigos
- Geração de arquivo de log com hash SHA-256
- Verificação de integridade de backups
- Interface de linha de comando (CLI) com parâmetros
- Nomeação automática de arquivos com timestamp
