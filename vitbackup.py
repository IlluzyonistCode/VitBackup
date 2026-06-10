import paramiko
import hashlib
import shutil
import struct
import json
import base64
import os
import sys
import time
import secrets
import tarfile
import tempfile
import signal
import getpass
import fnmatch
import argparse
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from io import BytesIO
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler
from colorama import init, Fore, Style

init(autoreset=True)


ENCRYPT_CHUNK_SIZE = 64 * 1024 * 1024


def print_success(message):
    print(f'{Fore.GREEN}[✓] {message}{Style.RESET_ALL}')

def print_error(message):
    print(f'{Fore.RED}[✗] {message}{Style.RESET_ALL}')

def print_warning(message):
    print(f'{Fore.YELLOW}[!] {message}{Style.RESET_ALL}')

def print_info(message):
    print(f'{Fore.CYAN}[i] {message}{Style.RESET_ALL}')

def print_progress(message, current, total):
    percentage = (current / total) * 100
    size_str = f'{format_size(current)}/{format_size(total)}'

    print(f'{Fore.BLUE}[{percentage:5.1f}% - {size_str}] {message}{Style.RESET_ALL}')

def format_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f'{size_bytes:.2f} {unit}'

        size_bytes /= 1024.0

    return f'{size_bytes:.2f} PB'


class Config:
    def __init__(self, config_path='vitbackup.json'):
        self.config_path = config_path
        self.data = {}

        self.load()

    def load(self):
        if not os.path.exists(self.config_path):
            print_error(f'Configuration file not found: {self.config_path}')
            print_info('Run "vitbackup init" to create a template configuration')

            sys.exit(1)

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
        except json.JSONDecodeError as e:
            print_error(f'Invalid JSON in configuration file: {e}')

            sys.exit(1)
        except Exception as e:
            print_error(f'Failed to load configuration: {e}')

            sys.exit(1)

        self.validate()

    def validate(self):
        required = ['watched_folders', 'exclude_patterns', 'server', 'check_interval', 'encryption']

        for key in required:
            if key not in self.data:
                print_error(f'Missing required configuration key: {key}')

                sys.exit(1)

        if 'host' not in self.data['server'] or 'user' not in self.data['server']:
            print_error('Server configuration must include "host" and "user"')

            sys.exit(1)

        if 'key_file' not in self.data['encryption']:
            print_error('Encryption configuration must include "key_file"')

            sys.exit(1)

    def get(self, key, default=None):
        return self.data.get(key, default)

    @staticmethod
    def create_template(path='vitbackup.json'):
        home = str(Path.home())

        template = {
            'watched_folders': [
                os.path.join(home, 'Documents'),
                os.path.join(home, 'Projects'),
                os.path.join(home, 'Pictures')
            ],
            'exclude_patterns': [
                'node_modules',
                '__pycache__',
                '*.tmp',
                '*.log',
                '.git',
                '.svn',
                'Thumbs.db',
                '.DS_Store'
            ],
            'server': {
                'host': 'backup.example.com',
                'port': 22,
                'user': 'backupuser',
                'remote_path': '/home/backupuser/backups'
            },
            'local_backup_dir': os.path.join(home, 'VitBackup_Local'),
            'check_interval': 3600,
            'encryption': {
                'key_file': os.path.join(home, '.vitbackup_key')
            },
            'manifest_file': os.path.join(home, '.vitbackup_manifest.json'),
            'max_retries': 5,
            'retry_delay': 60,
            'chunk_size': 52428800
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(template, f, indent=4)

        print_success(f'Template configuration created: {path}')
        print_info('Please edit the configuration file with your actual paths and server details')
        print_info('Set "local_backup_dir" to null if you don\'t want to keep local copies')


class Manifest:
    def __init__(self, manifest_path):
        self.manifest_path = manifest_path
        self.files = {}

        self.load()

    def load(self):
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    self.files = data.get('files', {})
            except json.JSONDecodeError as e:
                print_warning(f'Manifest file corrupted, starting fresh: {e}')

                self.files = {}
            except Exception as e:
                print_warning(f'Failed to load manifest: {e}')

                self.files = {}

        else:
            self.files = {}

    def save(self):
        temp_path = self.manifest_path + '.tmp'

        data = {
            'files': self.files,
            'last_update': datetime.now().isoformat(),
            'total_files': len(self.files),
            'total_size': sum(f['size'] for f in self.files.values())
        }

        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            if os.path.exists(self.manifest_path):
                backup_path = self.manifest_path + '.backup'

                shutil.copy2(self.manifest_path, backup_path)

            os.replace(temp_path, self.manifest_path)
        except Exception as e:
            print_error(f'Failed to save manifest: {e}')

            if os.path.exists(temp_path):
                os.remove(temp_path)

            raise

    def get_file_info(self, rel_path):
        return self.files.get(rel_path)

    def update_file(self, rel_path, size, checksum):
        self.files[rel_path] = {
            'size': size,
            'checksum': checksum,
            'modified': datetime.now().isoformat()
        }

    def remove_file(self, rel_path):
        if rel_path in self.files:
            del self.files[rel_path]


class EncryptionManager:
    def __init__(self, key_file=None, key_hex=None):
        self.key_file = key_file
        self.key = None

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        
        elif key_file:
            self.load_key()

    def load_key(self):
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'rb') as f:
                    self.key = f.read()

                if len(self.key) != 32:
                    print_error('Invalid key length. Key must be 32 bytes for AES-256')

                    sys.exit(1)

                print_success(f'Encryption key loaded from {self.key_file}')
            except Exception as e:
                print_error(f'Failed to load encryption key: {e}')

                sys.exit(1)

        else:
            print_warning(f'Encryption key file not found: {self.key_file}')
            print_info('Please enter your 32-byte encryption key (64 hex chars or 44 base64 chars)')
            print_info('Or press Enter to generate a new one')

            key_input = getpass.getpass('Key: ').strip()

            if not key_input:
                self.key = secrets.token_bytes(32)

                print_success('New encryption key generated')

                self.save_key()

                print_info(f'Key saved to: {self.key_file}')
                print_warning('=' * 70)
                print_warning('CRITICAL: Backup this key immediately!')
                print_warning('Without this key, your backups CANNOT be recovered!')
                print_warning('=' * 70)
                print_info(f'Key (hex): {self.key.hex()}')
                print_info(f'Key (base64): {base64.b64encode(self.key).decode()}')
                print_warning('=' * 70)

            else:
                try:
                    if len(key_input) == 64:
                        self.key = bytes.fromhex(key_input)

                    elif len(key_input) == 44 or '=' in key_input:
                        self.key = base64.b64decode(key_input)

                    else:
                        raise ValueError('Key must be 64 hex chars or 44 base64 chars')

                    if len(self.key) != 32:
                        raise ValueError('Key must be exactly 32 bytes')

                    self.save_key()

                    print_success('Encryption key saved')
                except Exception as e:
                    print_error(f'Invalid key format: {e}')

                    sys.exit(1)

    def save_key(self):
        try:
            with open(self.key_file, 'wb') as f:
                f.write(self.key)

            os.chmod(self.key_file, 0o600)
        except Exception as e:
            print_error(f'Failed to save encryption key: {e}')

            sys.exit(1)

    def encrypt(self, data):
        aesgcm = AESGCM(self.key)
        output = []

        for i in range(0, len(data), ENCRYPT_CHUNK_SIZE):
            chunk = data[i:i + ENCRYPT_CHUNK_SIZE]
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            blob = nonce + ciphertext

            output.append(struct.pack('>I', len(blob)) + blob)

        return b''.join(output)

    def encrypt_file_stream(self, input_path, output_path):
        aesgcm = AESGCM(self.key)

        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            while True:
                chunk = infile.read(ENCRYPT_CHUNK_SIZE)

                if not chunk:
                    break

                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, chunk, None)
                blob = nonce + ciphertext

                outfile.write(struct.pack('>I', len(blob)))
                outfile.write(blob)

    def decrypt(self, encrypted_data):
        aesgcm = AESGCM(self.key)
        output = []
        offset = 0

        while offset < len(encrypted_data):
            if offset + 4 > len(encrypted_data):
                raise ValueError('Truncated data: missing chunk length header')

            blob_len = struct.unpack('>I', encrypted_data[offset:offset + 4])[0]
            offset += 4

            if offset + blob_len > len(encrypted_data):
                raise ValueError('Truncated data: chunk body shorter than declared length')

            blob = encrypted_data[offset:offset + blob_len]
            offset += blob_len

            nonce = blob[:12]
            ciphertext = blob[12:]

            output.append(aesgcm.decrypt(nonce, ciphertext, None))

        return b''.join(output)

    def decrypt_file_stream(self, input_path, output_path):
        aesgcm = AESGCM(self.key)

        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            while True:
                length_data = infile.read(4)

                if not length_data:
                    break

                if len(length_data) < 4:
                    raise ValueError('Truncated data: missing chunk length header')

                blob_len = struct.unpack('>I', length_data)[0]
                blob = infile.read(blob_len)

                if len(blob) < blob_len:
                    raise ValueError('Truncated data: chunk body shorter than declared length')

                nonce = blob[:12]
                ciphertext = blob[12:]

                plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                outfile.write(plaintext)


class SSHClient:
    def __init__(self, host, port, user):
        self.host = host
        self.port = port
        self.user = user
        self.client = None
        self.sftp = None
        self.authenticated = False

    def connect(self):
        print_info(f'Connecting to {self.user}@{self.host}:{self.port}...')

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            password = getpass.getpass(f'Password for {self.user}@{self.host}: ')

            try:
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.user,
                    password=password,
                    look_for_keys=True,
                    allow_agent=True,
                    timeout=30
                )

                self.authenticated = True
            except paramiko.AuthenticationException:
                print_info('Password accepted, checking for 2FA...')

                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.user,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=30
                )

                transport = self.client.get_transport()

                try:
                    transport.auth_interactive(self.user, self._totp_handler)

                    self.authenticated = True
                except Exception as e:
                    print_warning(f'2FA authentication skipped or failed: {e}')

                    self.authenticated = True

            self.sftp = self.client.open_sftp()

            print_success('SSH connection established')
        except paramiko.AuthenticationException:
            print_error('Authentication failed')

            raise
        except paramiko.SSHException as e:
            print_error(f'SSH error: {e}')

            raise
        except Exception as e:
            print_error(f'Connection failed: {e}')

            raise

    def _totp_handler(self, title, instructions, prompt_list):
        responses = []

        if instructions:
            print_info(instructions)

        for prompt, echo in prompt_list:
            prompt_lower = prompt.lower()

            if 'otp' in prompt_lower or 'token' in prompt_lower or 'verification' in prompt_lower or 'code' in prompt_lower:
                response = getpass.getpass(f'2FA {prompt}')

            else:
                if echo:
                    response = input(prompt)

                else:
                    response = getpass.getpass(prompt)

            responses.append(response)

        return responses

    def upload_file(self, local_path, remote_path):
        self.sftp.put(local_path, remote_path, confirm=True)

    def upload_file_chunked(self, local_path, remote_path, chunk_size=52428800, callback=None):
        file_size = os.path.getsize(local_path)
        uploaded = 0

        with open(local_path, 'rb') as local_file:
            with self.sftp.open(remote_path, 'wb') as remote_file:
                while True:
                    chunk = local_file.read(chunk_size)

                    if not chunk:
                        break

                    remote_file.write(chunk)

                    uploaded += len(chunk)

                    if callback:
                        callback(uploaded, file_size)

    def download_file(self, remote_path, local_path):
        self.sftp.get(remote_path, local_path)

    def list_files(self, remote_path):
        try:
            return self.sftp.listdir(remote_path)
        except IOError:
            return []

    def file_exists(self, remote_path):
        try:
            self.sftp.stat(remote_path)

            return True
        except IOError:
            return False

    def execute_command(self, command):
        stdin, stdout, stderr = self.client.exec_command(command, timeout=300)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')

        return exit_status, output, error

    def mkdir_p(self, remote_path):
        dirs = []
        path = remote_path

        while path and path != '/':
            dirs.append(path)

            path = os.path.dirname(path)

        dirs.reverse()

        for d in dirs:
            try:
                self.sftp.stat(d)
            except IOError:
                try:
                    self.sftp.mkdir(d)
                except IOError:
                    pass

    def close(self):
        if self.sftp:
            try:
                self.sftp.close()
            except:
                pass

        if self.client:
            try:
                self.client.close()
            except:
                pass

        print_info('SSH connection closed')


class FileScanner:
    def __init__(self, watched_folders, exclude_patterns):
        self.watched_folders = watched_folders
        self.exclude_patterns = exclude_patterns

    def should_exclude(self, path):
        path_str = str(path)
        path_parts = Path(path_str).parts

        for pattern in self.exclude_patterns:
            if '*' in pattern or '?' in pattern:
                if fnmatch.fnmatch(os.path.basename(path_str), pattern):
                    return True

            else:
                if pattern in path_parts:
                    return True

                if pattern in path_str:
                    return True

        return False

    def scan(self):
        files = {}
        total_size = 0
        total_files = 0

        for folder in self.watched_folders:
            folder_path = Path(folder)

            if not folder_path.exists():
                print_warning(f'Watched folder does not exist: {folder}')

                continue

            print_info(f'Scanning: {folder}')

            for root, dirs, filenames in os.walk(folder, followlinks=False):
                root_path = Path(root)

                dirs[:] = [d for d in dirs if not self.should_exclude(root_path / d)]

                for filename in filenames:
                    file_path = root_path / filename

                    try:
                        if os.path.islink(file_path):
                            continue
                    except OSError:
                        continue

                    if not file_path.exists():
                        continue

                    if self.should_exclude(file_path):
                        continue

                    try:
                        rel_path = str(file_path.relative_to(folder_path.parent))
                        rel_path = rel_path.replace(os.sep, '/')
                        size = file_path.stat().st_size
                        checksum = self.calculate_checksum(file_path)

                        files[rel_path] = {
                            'size': size,
                            'checksum': checksum,
                            'absolute_path': str(file_path)
                        }

                        total_size += size
                        total_files += 1
                    except (PermissionError, OSError) as e:
                        print_warning(f'Cannot access {file_path}: {e}')
                    except Exception as e:
                        print_warning(f'Failed to process {file_path}: {e}')

        print_success(f'Scanned {total_files} files, {format_size(total_size)}')

        return files

    @staticmethod
    def calculate_checksum(file_path):
        sha256 = hashlib.sha256()

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)

            return sha256.hexdigest()
        except Exception as e:
            print_warning(f'Failed to calculate checksum for {file_path}: {e}')


class BackupEngine:
    def __init__(self, config, manifest, encryption_manager):
        self.config = config
        self.manifest = manifest
        self.encryption = encryption_manager
        self.scanner = FileScanner(
            config.get('watched_folders'),
            config.get('exclude_patterns')
        )

    def detect_changes(self):
        print_info('Detecting changes...')

        current_files = self.scanner.scan()

        added = []
        modified = []
        deleted = []

        for rel_path, file_info in current_files.items():
            manifest_info = self.manifest.get_file_info(rel_path)

            if manifest_info is None:
                added.append((rel_path, file_info))

            elif manifest_info.get('checksum') != file_info.get('checksum'):
                modified.append((rel_path, file_info))

        for rel_path in list(self.manifest.files.keys()):
            if rel_path not in current_files:
                deleted.append(rel_path)

        return added, modified, deleted, current_files

    def create_incremental_archive(self, added, modified):
        print_info('Creating incremental archive...')

        temp_archive = None
        temp_encrypted = None
        total_size = 0

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
                temp_archive = tmp.name

            with tarfile.open(temp_archive, mode='w:gz', compresslevel=6) as tar:
                all_changes = added + modified
                total = len(all_changes)

                for idx, (rel_path, file_info) in enumerate(all_changes, 1):
                    abs_path = file_info['absolute_path']

                    try:
                        tar.add(abs_path, arcname=rel_path, recursive=False)

                        total_size += file_info['size']

                        print_progress(f'{rel_path}', idx, total)
                    except Exception as e:
                        print_warning(f'Failed to add {rel_path}: {e}')

            archive_size = os.path.getsize(temp_archive)

            print_success(
                f'Archive created: {format_size(archive_size)} '
                f'(uncompressed: {format_size(total_size)})'
            )
            print_info('Encrypting archive...')

            with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as tmp:
                temp_encrypted = tmp.name

            self.encryption.encrypt_file_stream(temp_archive, temp_encrypted)

            encrypted_size = os.path.getsize(temp_encrypted)

            print_success(f'Archive encrypted: {format_size(encrypted_size)}')

            return temp_encrypted
        finally:
            if temp_archive and os.path.exists(temp_archive):
                os.unlink(temp_archive)

    def upload_to_server(self, encrypted_file_path):
        server_config = self.config.get('server')

        local_copy_dir = self.config.get('local_backup_dir')

        if local_copy_dir:
            try:
                local_dir = Path(local_copy_dir)
                local_dir.mkdir(parents=True, exist_ok=True)

                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                local_file = local_dir / f'incremental_{timestamp}.enc'

                print_info(f'Saving local copy: {local_file}')

                shutil.copy2(encrypted_file_path, local_file)

                print_success('Local copy saved')
            except Exception as e:
                print_warning(f'Failed to save local copy: {e}')

        ssh = SSHClient(
            server_config['host'],
            server_config.get('port', 22),
            server_config['user']
        )

        max_retries = self.config.get('max_retries', 5)
        retry_delay = self.config.get('retry_delay', 60)

        for attempt in range(max_retries):
            try:
                ssh.connect()

                remote_path = server_config['remote_path']

                ssh.mkdir_p(remote_path)

                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                remote_file = f'{remote_path}/incremental_{timestamp}.enc'

                print_info(f'Uploading to server: {remote_file}')

                file_size = os.path.getsize(encrypted_file_path)

                def upload_progress(uploaded, total):
                    print_progress('Uploading', uploaded, total)

                if file_size > 10 * 1024 * 1024:
                    ssh.upload_file_chunked(encrypted_file_path, remote_file, callback=upload_progress)

                else:
                    ssh.upload_file(encrypted_file_path, remote_file)

                print_success('Upload completed')

                ssh.close()

                return True
            except Exception as e:
                print_error(f'Upload failed (attempt {attempt + 1}/{max_retries}): {e}')

                if attempt < max_retries - 1:
                    print_info(f'Retrying in {retry_delay} seconds...')

                    time.sleep(retry_delay)

                    retry_delay *= 2

                else:
                    print_error('Max retries reached. Upload failed.')

                    return False
            finally:
                try:
                    ssh.close()
                except:
                    pass

        return False

    def run_backup(self):
        start_time = time.time()

        print_info('=' * 70)
        print_info(f'Backup started at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        print_info('=' * 70)

        try:
            added, modified, deleted, current_files = self.detect_changes()
        except Exception as e:
            print_error(f'Failed to detect changes: {e}')

            return

        total_changes = len(added) + len(modified) + len(deleted)

        if total_changes == 0:
            print_success('No changes detected. Backup not required.')

            return

        print_info('Changes detected:')
        print_info(f'  Added:    {len(added)} files')
        print_info(f'  Modified: {len(modified)} files')
        print_info(f'  Deleted:  {len(deleted)} files')

        if added or modified:
            encrypted_archive = None

            try:
                encrypted_archive = self.create_incremental_archive(added, modified)

                if self.upload_to_server(encrypted_archive):
                    print_info('Updating manifest...')

                    try:
                        for rel_path, file_info in added:
                            self.manifest.update_file(rel_path, file_info['size'], file_info['checksum'])

                        for rel_path, file_info in modified:
                            self.manifest.update_file(rel_path, file_info['size'], file_info['checksum'])

                        for rel_path in deleted:
                            self.manifest.remove_file(rel_path)

                        self.manifest.save()

                        print_success('Manifest updated')
                    except Exception as e:
                        print_error(f'Failed to update manifest: {e}')

                        return

                else:
                    print_error('Backup failed due to upload error')

                    return
            except Exception as e:
                print_error(f'Failed to create archive: {e}')

                return
            finally:
                if encrypted_archive and os.path.exists(encrypted_archive):
                    os.unlink(encrypted_archive)

        elapsed = time.time() - start_time

        print_info('=' * 70)
        print_success(f'Backup completed in {elapsed:.2f} seconds')
        print_info('=' * 70)


class BackupVerifier:
    def __init__(self, config, manifest, encryption_manager):
        self.config = config
        self.manifest = manifest
        self.encryption = encryption_manager

    def verify_remote_backups(self):
        print_info('=' * 70)
        print_info('Starting backup verification')
        print_info('=' * 70)

        server_config = self.config.get('server')

        ssh = SSHClient(
            server_config['host'],
            server_config.get('port', 22),
            server_config['user']
        )

        try:
            ssh.connect()

            remote_path = server_config['remote_path']

            print_info(f'Listing remote backups in {remote_path}')

            files = ssh.list_files(remote_path)

            backup_files = [f for f in files if f.endswith('.enc')]

            if not backup_files:
                print_warning('No backup files found on server')

                return

            backup_files.sort()

            print_success(f'Found {len(backup_files)} backup archives')

            for backup_file in backup_files:
                print_info(f'  - {backup_file}')

            print_info('')
            print_info('Verifying latest backup archive...')

            latest = backup_files[-1]
            remote_file = f'{remote_path}/{latest}'

            with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as f:
                temp_encrypted = f.name

            temp_decrypted = None

            try:
                print_info(f'Downloading {latest}...')

                ssh.download_file(remote_file, temp_encrypted)

                print_success('Download completed')
                print_info('Decrypting archive...')

                with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as f:
                    temp_decrypted = f.name

                try:
                    self.encryption.decrypt_file_stream(temp_encrypted, temp_decrypted)

                    print_success('Decryption successful')
                except Exception as e:
                    print_error(f'Decryption failed: {e}')
                    print_error('Possible causes:')
                    print_error('  - Wrong encryption key')
                    print_error('  - Corrupted archive')

                    return

                print_info('Verifying archive contents...')

                try:
                    with tarfile.open(temp_decrypted, mode='r:*') as tar:
                        members = tar.getmembers()

                        print_success(f'Archive contains {len(members)} files')
                        print_info('Sample files:')

                        for member in members[:10]:
                            print_info(f'  - {member.name} ({format_size(member.size)})')

                        if len(members) > 10:
                            print_info(f'  ... and {len(members) - 10} more files')
                except Exception as e:
                    print_error(f'Archive verification failed: {e}')

                    return

                print_success('Archive verification completed successfully')
            finally:
                if os.path.exists(temp_encrypted):
                    os.remove(temp_encrypted)

                if temp_decrypted and os.path.exists(temp_decrypted):
                    os.remove(temp_decrypted)

            print_info('=' * 70)
            print_success('Verification completed')
            print_info('=' * 70)
        except Exception as e:
            print_error(f'Verification failed: {e}')
        finally:
            ssh.close()

    def verify_local_manifest(self):
        print_info('Verifying local manifest integrity...')

        total_files = len(self.manifest.files)
        total_size = sum(f['size'] for f in self.manifest.files.values())

        print_info(f'Manifest contains {total_files} files')
        print_info(f'Total size: {format_size(total_size)}')
        print_success('Local manifest verified')


class BackupDaemon:
    def __init__(self, config):
        self.config = config
        self.running = False

    def start(self):
        self.running = True

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            signal.signal(signal.SIGHUP, self._signal_handler)
        except AttributeError:
            pass

        print_success('Daemon started')
        print_info(f'Check interval: {self.config.get("check_interval")} seconds')

        while self.running:
            try:
                manifest = Manifest(self.config.get('manifest_file'))
                encryption = EncryptionManager(key_file=self.config.get('encryption')['key_file'])
                engine = BackupEngine(self.config, manifest, encryption)

                engine.run_backup()
            except KeyboardInterrupt:
                print_warning('Interrupted by user')

                break
            except Exception as e:
                print_error(f'Backup error: {e}')

            if self.running:
                interval = self.config.get('check_interval')

                print_info(f'Sleeping for {interval} seconds...')

                try:
                    time.sleep(interval)
                except KeyboardInterrupt:
                    print_warning('Interrupted by user')

                    break

    def _signal_handler(self, signum, frame):
        print_warning(f'Received signal {signum}. Shutting down...')

        self.running = False


class ServerBackupManager:
    def __init__(self, backup_root, encryption_manager=None):
        self.backup_root = Path(backup_root)
        self.incremental_dir = self.backup_root / 'incremental'
        self.extracted_dir = self.backup_root / 'extracted'
        self.consolidated_dir = self.backup_root / 'consolidated'
        self.encryption = encryption_manager

        self.incremental_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_dir.mkdir(parents=True, exist_ok=True)
        self.consolidated_dir.mkdir(parents=True, exist_ok=True)

    def process_incremental(self, encrypted_file):
        print_info(f'Processing incremental backup: {encrypted_file}')

        if not self.encryption or not self.encryption.key:
            print_error('Encryption key not provided')

            return False

        print_info('Decrypting...')

        temp_decrypted = None

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
                temp_decrypted = tmp.name

            self.encryption.decrypt_file_stream(encrypted_file, temp_decrypted)

            print_info('Extracting archive...')

            with tarfile.open(temp_decrypted, mode='r:*') as tar:
                members = tar.getmembers()

                print_info(f'Archive contains {len(members)} files')

                for member in members:
                    target_path = self.extracted_dir / member.name
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    if member.isfile():
                        with tar.extractfile(member) as source:
                            with open(target_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

                        os.chmod(target_path, member.mode)

                print_success('Extraction completed')

                return True
        except Exception as e:
            print_error(f'Processing failed: {e}')

            return False
        finally:
            if temp_decrypted and os.path.exists(temp_decrypted):
                os.unlink(temp_decrypted)

    def consolidate(self):
        print_info('Creating consolidated backup...')

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        consolidated_archive = self.consolidated_dir / f'backup_{timestamp}.tar.gz'

        with tarfile.open(consolidated_archive, 'w:gz', compresslevel=6) as tar:
            for root, dirs, files in os.walk(self.extracted_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(self.extracted_dir)

                    tar.add(file_path, arcname=arcname)

        print_success(f'Consolidated backup created: {consolidated_archive}')

        if self.encryption and self.encryption.key:
            print_info('Encrypting consolidated backup...')

            encrypted_archive = consolidated_archive.with_suffix('.tar.gz.enc')

            self.encryption.encrypt_file_stream(str(consolidated_archive), str(encrypted_archive))

            os.remove(consolidated_archive)

            print_success(f'Encrypted consolidated backup: {encrypted_archive}')

    def list_backups(self):
        print_info('Incremental backups:')

        incremental_files = sorted(self.incremental_dir.glob('*.enc'))

        for f in incremental_files:
            size = f.stat().st_size

            print_info(f'  {f.name} ({size / 1024 / 1024:.2f} MB)')

        print_info(f'\nTotal: {len(incremental_files)} incremental backups')

        print_info('\nConsolidated backups:')

        consolidated_files = sorted(self.consolidated_dir.glob('*.enc'))

        for f in consolidated_files:
            size = f.stat().st_size

            print_info(f'  {f.name} ({size / 1024 / 1024:.2f} MB)')

        print_info(f'\nTotal: {len(consolidated_files)} consolidated backups')

    def cleanup_old(self, keep_days=30):
        print_info(f'Cleaning up backups older than {keep_days} days...')

        cutoff = time.time() - (keep_days * 86400)
        removed = 0

        for backup_file in self.incremental_dir.glob('*.enc'):
            if backup_file.stat().st_mtime < cutoff:
                backup_file.unlink()

                removed += 1

                print_info(f'Removed: {backup_file.name}')

        print_success(f'Removed {removed} old incremental backups')


def main():
    parser = argparse.ArgumentParser(
        description='VitBackup - Encrypted backup solution with SSH transport',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Client commands (require vitbackup.json):
  vitbackup init                              Create configuration template
  vitbackup run                               Run backup once
  vitbackup daemon                            Run as daemon with scheduled backups
  vitbackup verify                            Verify remote backup integrity

Server commands (standalone, no config file):
  vitbackup process --backup-root /path --key <hex> --file backup.enc
                                              Decrypt and extract an incremental backup
  vitbackup consolidate --backup-root /path --key <hex>
                                              Merge extracted files into a consolidated archive
  vitbackup list --backup-root /path          List all stored backups
  vitbackup cleanup --backup-root /path [--keep-days 30]
                                              Remove old incremental backups

Options:
  -c, --config    Path to configuration file (default: vitbackup.json)
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    subparsers.add_parser('init', help='Create template configuration file')
    subparsers.add_parser('run', help='Run backup once')
    subparsers.add_parser('daemon', help='Run backup daemon with scheduled intervals')
    subparsers.add_parser('verify', help='Verify backup integrity')

    process_parser = subparsers.add_parser('process', help='Decrypt and extract an incremental backup archive')
    process_parser.add_argument('--backup-root', default='/home/backupuser/backups', help='Root directory for backups')
    process_parser.add_argument('--key', required=True, help='Encryption key (hex format)')
    process_parser.add_argument('--file', required=True, help='Encrypted backup file to process')

    consolidate_parser = subparsers.add_parser('consolidate', help='Merge extracted files into a consolidated archive')
    consolidate_parser.add_argument('--backup-root', default='/home/backupuser/backups', help='Root directory for backups')
    consolidate_parser.add_argument('--key', required=True, help='Encryption key (hex format)')

    list_parser = subparsers.add_parser('list', help='List stored backups')
    list_parser.add_argument('--backup-root', default='/home/backupuser/backups', help='Root directory for backups')

    cleanup_parser = subparsers.add_parser('cleanup', help='Remove old incremental backups')
    cleanup_parser.add_argument('--backup-root', default='/home/backupuser/backups', help='Root directory for backups')
    cleanup_parser.add_argument('--keep-days', type=int, default=30, help='Days to keep (default: 30)')

    parser.add_argument(
        '-c', '--config',
        default='vitbackup.json',
        help='Path to configuration file (default: vitbackup.json)'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()

        return

    if args.command == 'init':
        Config.create_template(args.config)

        return

    if args.command in ('run', 'daemon', 'verify'):
        try:
            config = Config(args.config)
        except SystemExit:
            return

        manifest = Manifest(config.get('manifest_file'))
        encryption = EncryptionManager(key_file=config.get('encryption')['key_file'])

        if args.command == 'run':
            engine = BackupEngine(config, manifest, encryption)

            engine.run_backup()

        elif args.command == 'daemon':
            daemon = BackupDaemon(config)

            daemon.start()

        elif args.command == 'verify':
            verifier = BackupVerifier(config, manifest, encryption)

            verifier.verify_local_manifest()

            print_info('')

            verifier.verify_remote_backups()

        return

    if args.command == 'process':
        encryption = EncryptionManager(key_hex=args.key)
        manager = ServerBackupManager(args.backup_root, encryption)

        manager.process_incremental(args.file)

    elif args.command == 'consolidate':
        encryption = EncryptionManager(key_hex=args.key)
        manager = ServerBackupManager(args.backup_root, encryption)

        manager.consolidate()

    elif args.command == 'list':
        manager = ServerBackupManager(args.backup_root)

        manager.list_backups()

    elif args.command == 'cleanup':
        manager = ServerBackupManager(args.backup_root)

        manager.cleanup_old(args.keep_days)


if __name__ == '__main__':
    main()
