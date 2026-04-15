#!/usr/bin/env python3
"""
Lightweight Python reimplementation of the ps3netsrv netiso protocol (initial, read-only focused).

Features implemented (minimal set to make webMAN list files and open/read them):
- Listen TCP on port 38008 (default)
- OPEN_FILE, OPEN_DIR, READ_DIR, READ_FILE, READ_FILE_CRITICAL, READ_CD_2048_CRITICAL, STAT_FILE
- Uses ./files as the default root directory (can be passed on CLI)

This is an initial reimplementation for debugging and compatibility with webMAN.
Extensive debug logs are emitted to help trace the protocol flow.

NOTE: This is not a complete port of the original C server but implements the commands typically
used by webMAN to enumerate directories and read ISO files.
"""

import os
import socket
import struct
import threading
import logging
import sys
from pathlib import Path
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import json
import requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
import time
import tempfile
import shutil
import time
import queue

# Constants (follow original header order; first value explicitly set in C header)
NETISO_PORT = 38008
NETISO_CMD_OPEN_FILE = 0x1224
NETISO_CMD_READ_FILE_CRITICAL = NETISO_CMD_OPEN_FILE + 1
NETISO_CMD_READ_CD_2048_CRITICAL = NETISO_CMD_OPEN_FILE + 2
NETISO_CMD_READ_FILE = NETISO_CMD_OPEN_FILE + 3
NETISO_CMD_CREATE_FILE = NETISO_CMD_OPEN_FILE + 4
NETISO_CMD_WRITE_FILE = NETISO_CMD_OPEN_FILE + 5
NETISO_CMD_OPEN_DIR = NETISO_CMD_OPEN_FILE + 6
NETISO_CMD_READ_DIR_ENTRY = NETISO_CMD_OPEN_FILE + 7
NETISO_CMD_DELETE_FILE = NETISO_CMD_OPEN_FILE + 8
NETISO_CMD_MKDIR = NETISO_CMD_OPEN_FILE + 9
NETISO_CMD_RMDIR = NETISO_CMD_OPEN_FILE + 10
NETISO_CMD_READ_DIR_ENTRY_V2 = NETISO_CMD_OPEN_FILE + 11
NETISO_CMD_STAT_FILE = NETISO_CMD_OPEN_FILE + 12
NETISO_CMD_GET_DIR_SIZE = NETISO_CMD_OPEN_FILE + 13
NETISO_CMD_READ_DIR = NETISO_CMD_OPEN_FILE + 14

# Sizes from C structs
NETISO_CMD_SIZE = 16

# Protocol constants
BUFFER_SIZE = 4 * 1024 * 1024  # 4MB buffer like ps3netsrv original
CACHE_CHUNK_SIZE = 8 * 1024 * 1024  # 8MB cache chunks
INITIAL_CACHE_SIZE = 1024 * 1024 * 1024  # 1024MB initial cache (128 chunks of 8MB)
MAX_NAME = 512
MAX_FILE_LEN = 255

# ISO Sector constants (from ps3netsrv original)
ISO_SECTOR_SIZE = 2352  # Standard ISO sector size
ISO_SECTOR_MASK = ISO_SECTOR_SIZE - 1  # For alignment

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('ps3netsrv-py')


class DirectDriveManager:
    """Gerenciador de conexões diretas persistentes com Google Drive"""
    
    def __init__(self, gdrive_manager):
        self.gdrive_manager = gdrive_manager
        self.persistent_connections = {}  # file_id -> session_info
        self.connection_lock = threading.Lock()
    
    def get_persistent_session(self, file_id: str):
        """Obtém ou cria uma sessão persistente para o arquivo"""
        with self.connection_lock:
            if file_id not in self.persistent_connections:
                # Criar nova sessão persistente
                session = requests.Session()
                
                # Configurar headers persistentes
                credentials = self.gdrive_manager.service._http.credentials
                if credentials and credentials.token:
                    session.headers.update({
                        'Authorization': f'Bearer {credentials.token}',
                        'Connection': 'keep-alive',
                        'Accept-Encoding': 'identity',
                        'User-Agent': 'ps3netsrv-py-direct/1.0'
                    })
                
                self.persistent_connections[file_id] = {
                    'session': session,
                    'last_used': time.time(),
                    'url': f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
                }
                
                #logger.debug('Created persistent session for file %s', file_id)
            
            # Atualizar timestamp de uso
            self.persistent_connections[file_id]['last_used'] = time.time()
            return self.persistent_connections[file_id]
    
    def download_chunk_persistent(self, file_id: str, offset: int, size: int) -> bytes:
        """Download usando conexão persistente"""
        try:
            session_info = self.get_persistent_session(file_id)
            session = session_info['session']
            url = session_info['url']
            
            # Fazer requisição Range com conexão persistente
            headers = {
                'Range': f'bytes={offset}-{offset + size - 1}'
            }
            
            response = session.get(
                url,
                headers=headers,
                timeout=10,
                stream=True,
                verify=True
            )
            response.raise_for_status()
            
            data = response.content
            #logger.debug('Direct download: %d bytes from offset %d', len(data), offset)
            return data
            
        except Exception as e:
            logger.error('Persistent download failed: %s', e)
            # Em caso de erro, remover conexão problemática
            with self.connection_lock:
                if file_id in self.persistent_connections:
                    try:
                        self.persistent_connections[file_id]['session'].close()
                    except Exception:
                        pass
                    del self.persistent_connections[file_id]
            return b''
    
    def cleanup_old_connections(self, max_age: float = 300.0):
        """Limpa conexões antigas (5 minutos por padrão)"""
        current_time = time.time()
        with self.connection_lock:
            to_remove = []
            for file_id, session_info in self.persistent_connections.items():
                if current_time - session_info['last_used'] > max_age:
                    to_remove.append(file_id)
            
            for file_id in to_remove:
                try:
                    self.persistent_connections[file_id]['session'].close()
                except Exception:
                    pass
                del self.persistent_connections[file_id]
                #logger.debug('Cleaned up old connection for file %s', file_id)
    
    def close_all_connections(self):
        """Fecha todas as conexões persistentes"""
        with self.connection_lock:
            for file_id, session_info in self.persistent_connections.items():
                try:
                    session_info['session'].close()
                except Exception:
                    pass
            self.persistent_connections.clear()
            #logger.info('Closed all persistent connections')


class SequentialDownloadManager:
    """Gerenciador de downloads sequenciais para evitar erros SSL"""
    
    def __init__(self):
        self.download_lock = threading.Lock()
        self.download_queue = queue.Queue()
        self.current_download = None
        self.download_thread = None
        self.stop_event = threading.Event()
        
        # Iniciar thread de processamento de downloads
        self.download_thread = threading.Thread(target=self._process_downloads, daemon=True)
        self.download_thread.start()
    
    def add_download_request(self, gdrive_manager, file_id: str, offset: int, size: int, callback):
        """Adiciona request de download à fila sequencial"""
        request = {
            'gdrive_manager': gdrive_manager,
            'file_id': file_id,
            'offset': offset,
            'size': size,
            'callback': callback,
            'timestamp': time.time()
        }
        
        self.download_queue.put(request)
    
    def _process_downloads(self):
        """Processa downloads sequencialmente respeitando ordem de chegada"""
        
        while not self.stop_event.is_set():
            try:
                # Pegar próximo request da fila (bloqueia até ter um)
                try:
                    request = self.download_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                with self.download_lock:
                    self.current_download = request
                
                try:
                    # logger.debug('Processing download request: %s offset=%d size=%d', 
                    #            request['file_id'], request['offset'], request['size'])
                    
                    # Executar download sequencial (sem paralelismo)
                    result = request['gdrive_manager'].download_file_chunk_direct(
                        request['file_id'], 
                        request['offset'], 
                        request['size']
                    )
                    
                    # Chamar callback com resultado
                    if request['callback']:
                        request['callback'](result)
                        
                    # logger.debug('Download completed: %s offset=%d', 
                    #            request['file_id'], request['offset'])
                    
                except Exception as e:
                    logger.error('Download error: %s', e)
                    if request['callback']:
                        request['callback'](None)
                
                finally:
                    with self.download_lock:
                        self.current_download = None
                    self.download_queue.task_done()
                    
            except Exception as e:
                logger.error('Error in download processor: %s', e)
                time.sleep(1)
        
        #logger.info('Download processor thread stopped')
    
    def get_queue_status(self):
        """Retorna status da fila de downloads"""
        with self.download_lock:
            return {
                'queue_size': self.download_queue.qsize(),
                'current_download': self.current_download['file_id'] if self.current_download else None
            }
    
    def stop(self):
        """Para o gerenciador de downloads"""
        self.stop_event.set()
        if self.download_thread and self.download_thread.is_alive():
            self.download_thread.join(timeout=5)


class BackgroundDownloadManager:
    """Gerencia download em background de ISOs completas"""
    
    def __init__(self):
        self.cache_dir = Path("./ps3netsrv_cache/cached_isos")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.downloading_files = {}  # file_id -> download_info
        self.download_lock = threading.Lock()
        self.pause_events = {}  # file_id -> threading.Event para pausar downloads
        self.resume_events = {}  # file_id -> threading.Event para retomar downloads
        
        # Verificar e limpar ISOs corrompidas/incompletas
        self._verify_and_clean_existing_isos()
        
    
    def _verify_and_clean_existing_isos(self):
        """Verifica e limpa ISOs corrompidas/incompletas ao inicializar"""
        
        # Limpar arquivos temporários órfãos
        temp_files = list(self.cache_dir.glob("*.tmp"))
        for temp_file in temp_files:
            try:
                temp_file.unlink()
            except Exception as e:
                logger.warning('Failed to remove temp file %s: %s', temp_file.name, e)
        
        # Verificar ISOs existentes silenciosamente
        existing_isos = list(self.cache_dir.glob("*.iso"))
    
    def get_iso_path(self, file_id: str, filename: str) -> Path:
        """Retorna o caminho do arquivo ISO local"""
        safe_filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.')).rstrip()
        return self.cache_dir / f"{file_id}_{safe_filename}"
    
    def is_iso_cached(self, file_id: str, filename: str, expected_size: int = None) -> bool:
        """Verifica se a ISO está completamente baixada"""
        iso_path = self.get_iso_path(file_id, filename)
        
        if not iso_path.exists():
            return False
        
        try:
            actual_size = iso_path.stat().st_size
            
            # Se não foi especificado tamanho esperado, considerar válido se > 0
            if expected_size is None:
                return actual_size > 0
            
            # Verificar se o tamanho está correto (com tolerância de 1MB para diferenças menores)
            size_diff = abs(actual_size - expected_size)
            if size_diff <= 1024 * 1024:  # 1MB de tolerância
                #logger.debug('ISO %s is complete: %d bytes (expected: %d)', filename, actual_size, expected_size)
                return True
            else:
                logger.warning('ISO %s is incomplete: %d bytes (expected: %d, diff: %d MB)', 
                             filename, actual_size, expected_size, size_diff // (1024*1024))
                return False
                
        except Exception as e:
            logger.error('Error checking ISO file %s: %s', filename, e)
            return False
    
    def is_downloading(self, file_id: str) -> bool:
        """Verifica se a ISO está sendo baixada"""
        with self.download_lock:
            return file_id in self.downloading_files
    
    def pause_download(self, file_id: str):
        """Pausa o download em background para priorizar requisições em tempo real"""
        with self.download_lock:
            if file_id in self.downloading_files:
                if file_id not in self.pause_events:
                    self.pause_events[file_id] = threading.Event()
                self.pause_events[file_id].set()
    
    def resume_download(self, file_id: str):
        """Retoma o download em background após requisições em tempo real"""
        with self.download_lock:
            if file_id in self.downloading_files:
                if file_id not in self.resume_events:
                    self.resume_events[file_id] = threading.Event()
                self.resume_events[file_id].set()
    
    def pause_download_temporarily(self, file_id: str, duration: float = 5.0):
        """Pausa temporariamente o download por um período específico"""
        with self.download_lock:
            if file_id in self.downloading_files:
                if file_id not in self.pause_events:
                    self.pause_events[file_id] = threading.Event()
                self.pause_events[file_id].set()
                
                # Agendar retomada automática
                def auto_resume():
                    time.sleep(duration)
                    self.resume_download(file_id)
                
                resume_thread = threading.Thread(target=auto_resume, daemon=True)
                resume_thread.start()
    
    def is_download_paused(self, file_id: str) -> bool:
        """Verifica se o download está pausado"""
        with self.download_lock:
            if file_id in self.pause_events:
                return self.pause_events[file_id].is_set()
            return False
    
    def start_background_download(self, gdrive_manager, file_id: str, filename: str, file_size: int):
        """Inicia download em background da ISO completa"""
        with self.download_lock:
            if file_id in self.downloading_files:
                #logger.debug('Download already in progress for file %s', file_id)
                return
            
            # Verificar se já existe arquivo parcial para retomar download
            iso_path = self.get_iso_path(file_id, filename)
            temp_path = iso_path.with_suffix('.tmp')
            downloaded_bytes = 0
            
            if temp_path.exists():
                try:
                    downloaded_bytes = temp_path.stat().st_size
                    #logger.info('Resuming download for %s from %d bytes', filename, downloaded_bytes)
                except Exception as e:
                    logger.warning('Error checking temp file for %s: %s', filename, e)
                    downloaded_bytes = 0
            
            # Inicializar eventos de pausa/resumo
            if file_id not in self.pause_events:
                self.pause_events[file_id] = threading.Event()
            if file_id not in self.resume_events:
                self.resume_events[file_id] = threading.Event()
            
            # Marcar como baixando
            self.downloading_files[file_id] = {
                'filename': filename,
                'file_size': file_size,
                'downloaded_bytes': downloaded_bytes,
                'start_time': time.time()
            }
        
        # Iniciar thread de download COMPLETAMENTE INDEPENDENTE
        # Usar daemon=False para que continue mesmo após fechamento de conexões
        download_thread = threading.Thread(
            target=self._download_iso_background,
            args=(gdrive_manager, file_id, filename, file_size, downloaded_bytes),
            daemon=False,  # IMPORTANTE: Não é daemon para continuar independente
            name=f"ISO-Download-{file_id[:8]}"
        )
        download_thread.start()
        
        if downloaded_bytes > 0:
            # logger.info('Resumed background download for %s (%d MB) from %d MB', 
            #            filename, file_size // (1024*1024), downloaded_bytes // (1024*1024))
            pass
        else:
            # logger.info('Started background download for %s (%d MB)', filename, file_size // (1024*1024))
            pass
    
    def _download_iso_background(self, gdrive_manager, file_id: str, filename: str, file_size: int, start_offset: int = 0):
        """Thread de download em background com suporte a pausa/resumo"""
        iso_path = self.get_iso_path(file_id, filename)
        temp_path = iso_path.with_suffix('.tmp')
        
        try:
            if start_offset > 0:
                # logger.info('Background download resumed: %s from offset %d', filename, start_offset)
                pass
            else:
                # logger.info('Background download started: %s', filename)
                pass
            
            # Download em chunks maiores para melhor performance
            chunk_size = 16 * 1024 * 1024  # 16MB para velocidade máxima
            downloaded_bytes = start_offset
            
            # Usar arquivo temporário com buffer otimizado para escrita instantânea
            mode = 'ab' if start_offset > 0 else 'wb'
            with open(temp_path, mode, buffering=0) as f:  # Sem buffering para escrita instantânea
                if start_offset > 0:
                    f.seek(start_offset)
                
                while downloaded_bytes < file_size:
                    # Verificar se deve pausar o download
                    with self.download_lock:
                        if file_id in self.pause_events and self.pause_events[file_id].is_set():
                            self.pause_events[file_id].clear()
                            
                            # Aguardar sinal de retomada
                            if file_id in self.resume_events:
                                self.resume_events[file_id].wait(timeout=30)
                                self.resume_events[file_id].clear()
                    
                    remaining = file_size - downloaded_bytes
                    current_chunk_size = min(chunk_size, remaining)
                    
                    # DOWNLOAD DIRETO DO GOOGLE DRIVE - SEM USAR SequentialDownloadManager
                    chunk_data = self._download_chunk_direct(gdrive_manager, file_id, downloaded_bytes, current_chunk_size)
                    
                    if not chunk_data or len(chunk_data) == 0:
                        logger.error('Failed to download chunk at offset %d', downloaded_bytes)
                        time.sleep(0.5)  # Pausa menor para retry mais rápido
                        continue
                    
                    # Escrever chunk instantaneamente no arquivo
                    f.write(chunk_data)
                    f.flush()  # Forçar escrita imediata
                    os.fsync(f.fileno())  # Garantir que dados foram escritos no disco
                    
                    downloaded_bytes += len(chunk_data)
                    
                    # Atualizar progresso
                    with self.download_lock:
                        if file_id in self.downloading_files:
                            self.downloading_files[file_id]['downloaded_bytes'] = downloaded_bytes
                    
                    # Log de progresso a cada 200MB (reduzido para menos overhead)
                    if downloaded_bytes % (200 * 1024 * 1024) == 0:
                        progress = (downloaded_bytes / file_size) * 100
                        # logger.info('Background download progress: %.1f%% (%d MB / %d MB)', 
                        #            progress, downloaded_bytes // (1024*1024), file_size // (1024*1024))
            
            # Download completo - mover arquivo temporário para destino final
            if downloaded_bytes == file_size:
                temp_path.replace(iso_path)
                # logger.info('Background download completed: %s (%d MB)', filename, file_size // (1024*1024))
            else:
                logger.error('Background download incomplete: %s (%d/%d bytes)', filename, downloaded_bytes, file_size)
                # Não remover arquivo temporário se incompleto - pode ser retomado depois
            
            # Download completo
            with self.download_lock:
                if file_id in self.downloading_files:
                    del self.downloading_files[file_id]
                # Limpar eventos de pausa/resumo
                if file_id in self.pause_events:
                    del self.pause_events[file_id]
                if file_id in self.resume_events:
                    del self.resume_events[file_id]
            
        except Exception as e:
            logger.error('Background download failed for %s: %s', filename, e)
            with self.download_lock:
                if file_id in self.downloading_files:
                    del self.downloading_files[file_id]
                # Limpar eventos de pausa/resumo
                if file_id in self.pause_events:
                    del self.pause_events[file_id]
                if file_id in self.resume_events:
                    del self.resume_events[file_id]
            # Não remover arquivo temporário em caso de erro - pode ser retomado depois
    
    def _download_chunk_direct(self, gdrive_manager, file_id: str, offset: int, size: int) -> bytes:
        """Download direto do Google Drive com otimizações de velocidade"""
        try:
            if not gdrive_manager.service:
                return b''
            
            # Usar requests com sessão persistente para melhor performance
            import requests
            
            # Obter token de acesso
            credentials = gdrive_manager.service._http.credentials
            if not credentials or not credentials.token:
                logger.error('No valid credentials for direct download')
                return b''
            
            # Fazer requisição HTTP Range com otimizações
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
            headers = {
                'Authorization': f'Bearer {credentials.token}',
                'Range': f'bytes={offset}-{offset + size - 1}',
                'Connection': 'keep-alive',  # Manter conexão viva
                'Accept-Encoding': 'identity',  # Sem compressão para velocidade
                'User-Agent': 'ps3netsrv-py/1.0'  # User agent otimizado
            }
            
            # Usar timeout menor e configurações otimizadas
            response = requests.get(
                url, 
                headers=headers, 
                timeout=10,  # Timeout reduzido
                stream=True,  # Stream para melhor performance
                verify=True
            )
            response.raise_for_status()
            
            # Ler dados diretamente sem buffering extra
            data = response.content
            return data
            
        except Exception as e:
            logger.error('Direct download failed: %s', e)
            return b''
    
    def get_downloaded_bytes(self, file_id: str) -> int:
        """Retorna quantos bytes foram baixados"""
        with self.download_lock:
            if file_id in self.downloading_files:
                return self.downloading_files[file_id]['downloaded_bytes']
        return 0
    
    def read_from_cached_iso(self, file_id: str, filename: str, offset: int, size: int) -> bytes:
        """Lê dados do arquivo ISO local (se disponível) - inclui arquivo temporário durante download"""
        iso_path = self.get_iso_path(file_id, filename)
        temp_path = iso_path.with_suffix('.tmp')
        
        # Primeiro tentar arquivo final (download completo)
        if iso_path.exists():
            try:
                with open(iso_path, 'rb') as f:
                    f.seek(offset)
                    data = f.read(size)
                    return data if len(data) > 0 else None
            except Exception as e:
                #logger.debug('Error reading from cached ISO: %s', e)
                return None
        
        # Se não existe arquivo final, tentar arquivo temporário (download em progresso)
        if temp_path.exists():
            try:
                with open(temp_path, 'rb') as f:
                    f.seek(offset)
                    data = f.read(size)
                    return data if len(data) > 0 else None
            except Exception as e:
                #logger.debug('Error reading from temp ISO: %s', e)
                return None
        
        return None



def recv_all(conn: socket.socket, size: int) -> bytes:
    """Receive exactly `size` bytes or return fewer if the connection closed."""
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


class PS3Decryptor:
    """PS3 ISO decryption implementation"""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.is_encrypted = False
        self.decryptor = None
        self._check_encryption()
    
    def _check_encryption(self):
        """Check if file is encrypted and initialize decryptor"""
        try:
            with open(self.file_path, 'rb') as f:
                # Read first 16 bytes to check for encryption header
                header = f.read(16)
                
                # Check for PS3 encryption signature
                if header[:4] == b'PS3\x00':
                    self.is_encrypted = True
                    #logger.info('Detected encrypted PS3 ISO: %s', self.file_path)
                    self._init_decryptor()
                else:
                    self.is_encrypted = False
        except Exception as e:
            #logger.debug('Error checking encryption: %s', e)
            self.is_encrypted = False
    
    def _init_decryptor(self):
        """Initialize AES decryptor for PS3 ISOs"""
        try:
            # PS3 uses AES-128-CBC with a fixed key
            # This is a simplified implementation - real PS3 keys would be more complex
            key = b'\x00' * 16  # Placeholder key
            iv = b'\x00' * 16   # Placeholder IV
            
            self.decryptor = AES.new(key, AES.MODE_CBC, iv)
            #logger.debug('Initialized PS3 decryptor')
        except Exception as e:
            logger.error('Failed to initialize decryptor: %s', e)
            self.decryptor = None
    
    def decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data using PS3 decryption"""
        if not self.is_encrypted or not self.decryptor:
            return data
        
        try:
            # Decrypt in 16-byte blocks
            decrypted = b''
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                if len(block) == 16:
                    decrypted += self.decryptor.decrypt(block)
                else:
                    decrypted += block
            
            return decrypted
        except Exception as e:
            logger.error('Decryption error: %s', e)
            return data
    
    def read_and_decrypt(self, offset: int, size: int) -> bytes:
        """Read and decrypt data from file"""
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(size)
                
                if self.is_encrypted:
                    return self.decrypt_data(data)
                else:
                    return data
        except Exception as e:
            logger.error('Read/decrypt error: %s', e)
            return b''


class VirtualISO:
    """Virtual ISO implementation for folder-to-ISO conversion"""
    
    def __init__(self, folder_path: Path):
        self.folder_path = folder_path
        self.sector_size = 2352
        self.total_sectors = 0
        self.file_map = {}  # sector -> (file_path, offset_in_file)
        self._build_file_map()
    
    def _build_file_map(self):
        """Build mapping of sectors to files"""
        current_sector = 0
        
        # Add ISO9660 header sectors (first 16 sectors)
        for i in range(16):
            self.file_map[current_sector] = (None, 0)  # Will be generated
            current_sector += 1
        
        # Add file data sectors
        for root, dirs, files in os.walk(self.folder_path):
            for file in sorted(files):
                file_path = Path(root) / file
                try:
                    file_size = file_path.stat().st_size
                    sectors_needed = (file_size + self.sector_size - 1) // self.sector_size
                    
                    for i in range(sectors_needed):
                        self.file_map[current_sector] = (file_path, i * self.sector_size)
                        current_sector += 1
                except Exception:
                    continue
        
        self.total_sectors = current_sector
        #logger.debug('Virtual ISO: %d sectors, %d files', self.total_sectors, len(self.file_map))
    
    def read_sector(self, sector: int) -> bytes:
        """Read a single sector"""
        if sector >= self.total_sectors:
            return b'\x00' * self.sector_size
        
        if sector not in self.file_map:
            return b'\x00' * self.sector_size
        
        file_path, offset = self.file_map[sector]
        
        if file_path is None:
            # Generate ISO9660 header sector
            return self._generate_header_sector(sector)
        
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(self.sector_size)
                if len(data) < self.sector_size:
                    data += b'\x00' * (self.sector_size - len(data))
                return data
        except Exception:
            return b'\x00' * self.sector_size
    
    def _generate_header_sector(self, sector: int) -> bytes:
        """Generate ISO9660 header sector"""
        if sector == 16:  # Primary Volume Descriptor
            return self._generate_pvd()
        elif sector == 17:  # Volume Descriptor Set Terminator
            return self._generate_vdst()
        else:
            return b'\x00' * self.sector_size
    
    def _generate_pvd(self) -> bytes:
        """Generate Primary Volume Descriptor"""
        pvd = bytearray(2352)
        pvd[0] = 0x01  # Type code
        pvd[1:6] = b"CD001"  # Standard identifier
        pvd[6] = 0x01  # Version
        
        # Volume identifier (32 bytes)
        vol_id = "VIRTUAL_ISO"
        pvd[40:40+len(vol_id)] = vol_id.encode('ascii')
        
        # Volume set size (2 bytes)
        pvd[120:122] = struct.pack('<H', 1)
        
        # Volume sequence number (2 bytes)
        pvd[124:126] = struct.pack('<H', 1)
        
        # Logical block size (2 bytes)
        pvd[128:130] = struct.pack('<H', 2048)
        
        # Path table size (4 bytes)
        pvd[132:136] = struct.pack('<L', 0)
        
        # Location of occurrence of type L path table (4 bytes)
        pvd[140:144] = struct.pack('<L', 0)
        
        # Location of occurrence of type M path table (4 bytes)
        pvd[144:148] = struct.pack('<L', 0)
        
        # Root directory record (34 bytes)
        root_dir = pvd[156:190]
        root_dir[0] = 0x22  # Length of directory record
        root_dir[2:10] = struct.pack('<L', 0)  # Location of extent
        root_dir[10:18] = struct.pack('<L', 0)  # Data length
        root_dir[25] = 0x02  # Flags (directory)
        
        return bytes(pvd)
    
    def _generate_vdst(self) -> bytes:
        """Generate Volume Descriptor Set Terminator"""
        vdst = bytearray(2352)
        vdst[0] = 0xFF  # Type code
        vdst[1:6] = b"CD001"  # Standard identifier
        vdst[6] = 0x01  # Version
        return bytes(vdst)
    
    def get_total_size(self) -> int:
        """Get total size in bytes"""
        return self.total_sectors * self.sector_size


class VirtualFileSystem:
    """Pre-processed virtual file system for Google Drive"""
    
    def __init__(self):
        self.structure = {
            'PS3ISO': {},  # file_name -> file_info
            'PKG': {},     # file_name -> file_info  
            'GAMES': {}    # folder_name -> folder_info
        }
        self.file_cache = {}  # file_id -> file_info
        self.processed = False
    
    def add_file(self, category: str, name: str, file_info: dict):
        """Add file to virtual structure"""
        if category in self.structure:
            self.structure[category][name] = file_info
    
    def get_file(self, category: str, name: str):
        """Get file from virtual structure"""
        if category in self.structure:
            return self.structure[category].get(name)
        return None
    
    def list_directory(self, path: str):
        """List directory contents from pre-processed structure"""
        #logger.debug('VirtualFileSystem.list_directory called with path: %s', path)
        
        # Normalize path like ps3netsrv does
        normalized_path = path.replace('\\', '/')
        # Remove trailing slashes
        while normalized_path.endswith('/') and len(normalized_path) > 1:
            normalized_path = normalized_path[:-1]
        
        #logger.debug('Normalized path: %s', normalized_path)
        
        path_parts = normalized_path.lstrip('/').split('/')
        # Filter out empty parts (from double slashes)
        path_parts = [part for part in path_parts if part]
        #logger.debug('Path parts: %s', path_parts)
        
        # Handle root directory cases
        if (not path_parts or 
            normalized_path == '/' or normalized_path == '/.' or
            (len(path_parts) == 1 and path_parts[0] in ['PS3ISO', 'PKG', 'GAMES'])):
            # Root directory or virtual directory - return virtual directories
            if path_parts and path_parts[0] in ['PS3ISO', 'PKG', 'GAMES']:
                # Virtual directory - return files from that category
                category = path_parts[0]
                #logger.debug('Listing virtual directory: %s', category)
                entries = []
                
                for name, file_info in self.structure[category].items():
                    if category == 'GAMES':
                        # Folders
                        entries.append((
                            name,
                            0,  # size
                            int(time.mktime(time.strptime(file_info['modifiedTime'], '%Y-%m-%dT%H:%M:%S.%fZ'))),
                            1   # is_dir
                        ))
                    else:
                        # Files
                        entries.append((
                            name,
                            int(file_info.get('size', 0)),
                            int(time.mktime(time.strptime(file_info['modifiedTime'], '%Y-%m-%dT%H:%M:%S.%fZ'))),
                            0   # is_dir
                        ))
                
                #logger.debug('Returning %d entries for %s', len(entries), category)
                return sorted(entries, key=lambda x: x[0])
            else:
                # Root directory - return virtual directories
                #logger.debug('Listing root directory - returning 3 virtual directories')
                return [
                    ('PS3ISO', 0, int(time.time()), 1),  # name, size, mtime, is_dir
                    ('PKG', 0, int(time.time()), 1),
                    ('GAMES', 0, int(time.time()), 1)
                ]
        
        #logger.debug('No matching directory found, returning empty list')
        return []
    
    def get_file_by_path(self, path: str):
        """Get file from virtual structure by path"""
        # Normalize path like ps3netsrv does
        normalized_path = path.replace('\\', '/')
        # Remove trailing slashes
        while normalized_path.endswith('/') and len(normalized_path) > 1:
            normalized_path = normalized_path[:-1]
        
        path_parts = normalized_path.lstrip('/').split('/')
        # Filter out empty parts (from double slashes)
        path_parts = [part for part in path_parts if part]
        
        if len(path_parts) >= 2:
            category = path_parts[0]
            filename = path_parts[-1]
            
            if category in ['PS3ISO', 'PKG', 'GAMES']:
                # Check if this is a virtual file inside an ISO
                if category == 'PS3ISO' and self._is_virtual_iso_file(filename):
                    return self._get_virtual_iso_file(path_parts)
                
                file_info = self.get_file(category, filename)
                if file_info:
                    return file_info['id'], file_info
        
        return None
    
    def _is_virtual_iso_file(self, filename: str) -> bool:
        """Check if filename is a virtual file inside ISO (like STORE.SFO, STORE.PNG)"""
        virtual_extensions = ['.PNG', '.JPG', '.png', '.jpg', '.SFO']
        return any(filename.endswith(ext) for ext in virtual_extensions)
    
    def _get_virtual_iso_file(self, path_parts: list):
        """Get virtual file inside ISO (like STORE.SFO, STORE.PNG)"""
        if len(path_parts) < 2:
            return None
        
        iso_name = path_parts[1]  # The ISO file name
        virtual_filename = path_parts[-1]  # The virtual file (STORE.SFO, etc.)
        
        # Get the ISO file info
        iso_info = self.get_file('PS3ISO', iso_name)
        if not iso_info:
            return None
        
        # Create virtual file info for the file inside the ISO
        virtual_file_info = {
            'id': f"virtual_{iso_info['id']}_{virtual_filename}",
            'name': virtual_filename,
            'mimeType': 'application/octet-stream',
            'size': self._get_virtual_file_size(virtual_filename),
            'modifiedTime': iso_info['modifiedTime'],
            'isVirtual': True,
            'parentIso': iso_info['id'],
            'parentIsoName': iso_name
        }
        
        return virtual_file_info['id'], virtual_file_info
    
    def _get_virtual_file_size(self, filename: str) -> int:
        """Get estimated size for virtual files inside ISOs"""
        if filename.endswith('.SFO'):
            return 8192  # Typical PARAM.SFO size
        elif filename.endswith(('.PNG', '.png')):
            return 1024 * 1024  # 1MB for PNG images
        elif filename.endswith(('.JPG', '.jpg')):
            return 512 * 1024  # 512KB for JPG images
        else:
            return 1024  # Default 1KB
    
    def is_virtual_directory(self, path: str) -> bool:
        """Check if path is a virtual directory"""
        # Normalize path like ps3netsrv does
        normalized_path = path.replace('\\', '/')
        # Remove trailing slashes
        while normalized_path.endswith('/') and len(normalized_path) > 1:
            normalized_path = normalized_path[:-1]
        
        path_parts = normalized_path.lstrip('/').split('/')
        # Filter out empty parts (from double slashes)
        path_parts = [part for part in path_parts if part]
        
        if len(path_parts) == 1 and path_parts[0] in ['PS3ISO', 'PKG', 'GAMES']:
            return True
        
        return False


class GoogleDriveManager:
    """Google Drive API integration for ps3netsrv"""
    
    def __init__(self, direct_mode: bool = False):
        self.service = None
        self.folder_id = "17NfSGk5zmvXTZbV5I5hCJOs0nJI-_0rY"
        self.credentials_url = "https://infinitykkj.shop/classickkj/P2P%20SERVER%20BASE/credentials.json"
        self.vfs = VirtualFileSystem()  # Pre-processed virtual file system
        self.direct_mode = direct_mode
        
        if direct_mode:
            # Modo direto - apenas conexões persistentes
            self.direct_manager = None  # Será inicializado após _init_service
            # logger.info('GoogleDriveManager initialized in DIRECT mode')
        else:

            # Modo cache - downloads sequenciais e background

            self.download_manager = SequentialDownloadManager()  # Downloads sequenciais
        self.background_downloader = BackgroundDownloadManager()  # Download em background de ISOs
            # logger.info('GoogleDriveManager initialized in CACHE mode')
        
        self._init_service()
        self._preprocess_structure()
        
        # Inicializar DirectDriveManager após ter o service
        if direct_mode:
            self.direct_manager = DirectDriveManager(self)
    
    def _preprocess_structure(self):
        """Pre-process entire Google Drive structure into virtual file system"""
        if not self.service:
            logger.error('Google Drive service not available for preprocessing')
            return
        
        #logger.info('Starting Google Drive structure preprocessing...')
        
        try:
            # Get all files from the folder
            results = self.service.files().list(
                q=f"'{self.folder_id}' in parents",
                fields="files(id,name,mimeType,size,modifiedTime,shortcutDetails)",
                pageSize=1000  # Get more files per request
            ).execute()
            
            files = results.get('files', [])
            #logger.info('Found %d files/folders in Google Drive', len(files))
            
            # Process each file/folder
            for file in files:
                self._process_file(file)
            
            # Handle pagination if needed
            while 'nextPageToken' in results:
                results = self.service.files().list(
                    q=f"'{self.folder_id}' in parents",
                    fields="files(id,name,mimeType,size,modifiedTime,shortcutDetails)",
                    pageSize=1000,
                    pageToken=results['nextPageToken']
                ).execute()
                
                files = results.get('files', [])
                for file in files:
                    self._process_file(file)
            
            self.vfs.processed = True
            print('LISTA DE CONTEUDOS SINCRONIZADA')
            
        except Exception as e:
            logger.error('Failed to preprocess Google Drive structure: %s', e)
    
    def _process_file(self, file: dict):
        """Process a single file/folder and add to virtual structure"""
        file_id = file['id']
        file_name = file['name']
        
        # Resolve shortcuts
        if file.get('shortcutDetails'):
            original_id = file['shortcutDetails']['targetId']
            try:
                original_file = self.service.files().get(
                    fileId=original_id,
                    fields="id,name,mimeType,size,modifiedTime"
                ).execute()
                file_id = original_id
                file_name = original_file['name']
                file.update(original_file)
            except Exception as e:
                logger.warning('Failed to resolve shortcut %s: %s', file_name, e)
                return
        
        # Store in file cache
        self.vfs.file_cache[file_id] = file
        
        # Categorize file
        if file['mimeType'] == 'application/vnd.google-apps.folder':
            # Game folder
            self.vfs.add_file('GAMES', file_name, file)
        elif file_name.lower().endswith('.pkg'):
            # PKG file
            self.vfs.add_file('PKG', file_name, file)
        elif (file_name.lower().endswith('.iso') or 
              file_name.lower().endswith('.iso.0') or 
              file_name.lower().endswith('.iso.1')):
            # ISO file (including multi-part)
            self.vfs.add_file('PS3ISO', file_name, file)
    
    def _init_service(self):
        """Initialize Google Drive service with credentials"""
        try:
            # Download credentials from URL
            response = requests.get(self.credentials_url)
            response.raise_for_status()
            credentials_info = response.json()
            
            # Create credentials object
            credentials = service_account.Credentials.from_service_account_info(
                credentials_info,
                scopes=['https://www.googleapis.com/auth/drive.readonly']
            )
            
            # Build service
            self.service = build('drive', 'v3', credentials=credentials)
            print('TOKEN GOOGLE DRIVE OBTIDO')
            
        except Exception as e:
            logger.error('Failed to initialize Google Drive service: %s', e)
            self.service = None
    
    
    def list_directory(self, path: str):
        """List directory contents for virtual paths"""
        return self.vfs.list_directory(path)
    
    def is_virtual_directory(self, path: str) -> bool:
        """Check if path is a virtual directory"""
        return self.vfs.is_virtual_directory(path)
    
    def get_file_by_path(self, path: str):
        """Get file from Google Drive by virtual path"""
        return self.vfs.get_file_by_path(path)
    
    def download_file_chunk_direct(self, file_id: str, offset: int, size: int) -> bytes:
        """Download direto do Google Drive - usa modo direto se disponível"""
        if file_id.startswith('virtual_'):
            return self._download_virtual_iso_file(file_id, offset, size)
        
        if self.direct_mode and self.direct_manager:
            # Modo direto - usar conexão persistente
            return self.direct_manager.download_chunk_persistent(file_id, offset, size)
        else:
            # Modo cache - download tradicional
        try:
            # Usar requests diretamente para melhor performance
            import requests
            
            # Obter token de acesso
            credentials = self.service._http.credentials
            if not credentials or not credentials.token:
                logger.error('No valid credentials for direct download')
                return b''
            
            # Fazer requisição HTTP Range com otimizações
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
            headers = {
                'Authorization': f'Bearer {credentials.token}',
                'Range': f'bytes={offset}-{offset + size - 1}',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'identity',  # Sem compressão
                'User-Agent': 'ps3netsrv-py/1.0'
            }
            
            # Download otimizado com timeout reduzido
            response = requests.get(
                url, 
                headers=headers, 
                timeout=5,  # Timeout muito baixo para PS3
                stream=True,
                verify=True
            )
            response.raise_for_status()
            
            # Ler dados diretamente
            data = response.content
            return data
                
        except Exception as e:
            logger.error('Error downloading chunk from Google Drive: %s', e)
            return b''
    
    def download_file_chunk(self, file_id: str, offset: int, size: int) -> bytes:
        """Download de chunk do Google Drive diretamente (sem cache)"""
        if not self.service:
            return b''
        
        try:
            # Check if this is a virtual file inside an ISO
            if file_id.startswith('virtual_'):
                return self._download_virtual_iso_file(file_id, offset, size)
            
            # Download direto do Google Drive (sem cache)
            
            # Usar sistema de fila sequencial para evitar erros SSL
            result = None
            download_complete = threading.Event()
            
            def download_callback(data):
                nonlocal result
                result = data
                download_complete.set()
            
            # Adicionar request à fila sequencial
            self.download_manager.add_download_request(
                self, file_id, offset, size, download_callback
            )
            
            # Aguardar download completar (com timeout)
            if download_complete.wait(timeout=30):  # 30 segundos timeout
                return result
            else:
                logger.error('Download timeout for file %s offset %d', file_id, offset)
                return b''
                
        except Exception as e:
            logger.error('Failed to download file chunk: %s', e)
            return b''
    
    
    def _download_virtual_iso_file(self, virtual_file_id: str, offset: int, size: int) -> bytes:
        """Download virtual file inside ISO (like STORE.SFO, STORE.PNG)"""
        try:
            # Parse virtual file ID to get parent ISO info
            parts = virtual_file_id.split('_', 2)
            if len(parts) < 3:
                return b''
            
            parent_iso_id = parts[1]
            virtual_filename = parts[2]
            
            # Get parent ISO file info
            if parent_iso_id not in self.vfs.file_cache:
                return b''
            
            parent_iso_info = self.vfs.file_cache[parent_iso_id]
            
            # Generate virtual file content based on filename
            if virtual_filename.endswith('.SFO'):
                return self._generate_sfo_content(parent_iso_info, offset, size)
            elif virtual_filename.endswith(('.PNG', '.png')):
                return self._generate_png_content(parent_iso_info, offset, size)
            elif virtual_filename.endswith(('.JPG', '.jpg')):
                return self._generate_jpg_content(parent_iso_info, offset, size)
            else:
                return b'\x00' * size
                
        except Exception as e:
            logger.error('Failed to download virtual ISO file: %s', e)
            return b''
    
    def _generate_sfo_content(self, iso_info: dict, offset: int, size: int) -> bytes:
        """Generate PARAM.SFO content for virtual file"""
        # Create a basic PARAM.SFO structure
        sfo_data = bytearray(8192)  # Standard SFO size
        
        # SFO Header
        sfo_data[0:4] = b'\x00PSF'  # Magic
        sfo_data[4:8] = struct.pack('<I', 0x101)  # Version
        sfo_data[8:12] = struct.pack('<I', 0x14)  # Key table offset
        sfo_data[12:16] = struct.pack('<I', 0x100)  # Data table offset
        sfo_data[16:20] = struct.pack('<I', 1)  # Table entries
        
        # Key table entry
        sfo_data[0x14:0x18] = struct.pack('<I', 0)  # Key offset
        sfo_data[0x18:0x1C] = struct.pack('<I', 0x100)  # Data offset
        sfo_data[0x1C:0x20] = struct.pack('<I', 0x10)  # Data size
        sfo_data[0x20:0x24] = struct.pack('<I', 0x10)  # Data capacity
        
        # Key string
        sfo_data[0x100:0x110] = b'TITLE_ID\x00\x00\x00\x00\x00\x00\x00'
        
        # Data (TITLE_ID)
        title_id = iso_info.get('name', 'UNKNOWN')[:9].ljust(9, '0')
        sfo_data[0x110:0x120] = title_id.encode('ascii')[:10].ljust(10, b'\x00')
        
        # Return requested portion
        if offset >= len(sfo_data):
            return b'\x00' * size
        if offset + size > len(sfo_data):
            size = len(sfo_data) - offset
        
        return bytes(sfo_data[offset:offset + size])
    
    def _generate_png_content(self, iso_info: dict, offset: int, size: int) -> bytes:
        """Generate PNG content for virtual file"""
        # Create a minimal PNG with game title
        title = iso_info.get('name', 'Unknown Game')
        
        # Simple 1x1 transparent PNG
        png_data = bytearray([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1 image
            0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,  # RGBA, no compression
            0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,  # IDAT chunk
            0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,  # Compressed data
            0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,  # CRC
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,  # IEND chunk
            0xAE, 0x42, 0x60, 0x82  # CRC
        ])
        
        # Pad to 1MB
        png_data.extend(b'\x00' * (1024 * 1024 - len(png_data)))
        
        # Return requested portion
        if offset >= len(png_data):
            return b'\x00' * size
        if offset + size > len(png_data):
            size = len(png_data) - offset
        
        return bytes(png_data[offset:offset + size])
    
    def _generate_jpg_content(self, iso_info: dict, offset: int, size: int) -> bytes:
        """Generate JPG content for virtual file"""
        # Create a minimal JPEG with game title
        title = iso_info.get('name', 'Unknown Game')
        
        # Simple 1x1 JPEG
        jpg_data = bytearray([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,  # JPEG signature
            0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,  # JFIF header
            0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,  # Quantization table
            0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,  # Quantization data
            0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C,
            0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
            0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D,
            0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20,
            0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
            0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27,
            0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34,
            0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,  # SOF0 segment
            0x00, 0x01, 0x03, 0x01, 0x22, 0x00, 0x02, 0x11,  # 1x1 image
            0x01, 0x03, 0x11, 0x01, 0xFF, 0xC4, 0x00, 0x14,  # Huffman table
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0xFF, 0xC4, 0x00, 0x14, 0x10,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C, 0x03,  # SOS segment
            0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F,
            0x00, 0x80, 0xFF, 0xD9  # EOI marker
        ])
        
        # Pad to 512KB
        jpg_data.extend(b'\x00' * (512 * 1024 - len(jpg_data)))
        
        # Return requested portion
        if offset >= len(jpg_data):
            return b'\x00' * size
        if offset + size > len(jpg_data):
            size = len(jpg_data) - offset
        
        return bytes(jpg_data[offset:offset + size])
    
    def get_file_size(self, file_id: str):
        """Get file size from cache"""
        # Check if this is a virtual file inside an ISO
        if file_id.startswith('virtual_'):
            parts = file_id.split('_', 2)
            if len(parts) >= 3:
                virtual_filename = parts[2]
                if virtual_filename.endswith('.SFO'):
                    return 8192
                elif virtual_filename.endswith(('.PNG', '.png')):
                    return 1024 * 1024
                elif virtual_filename.endswith(('.JPG', '.jpg')):
                    return 512 * 1024
                else:
                    return 1024
        
        if file_id in self.vfs.file_cache:
            return int(self.vfs.file_cache[file_id].get('size', 0))
        return 0
    
    def get_file_mtime(self, file_id: str):
        """Get file modification time from cache"""
        # Check if this is a virtual file inside an ISO
        if file_id.startswith('virtual_'):
            parts = file_id.split('_', 2)
            if len(parts) >= 3:
                parent_iso_id = parts[1]
                if parent_iso_id in self.vfs.file_cache:
                    try:
                        return int(time.mktime(time.strptime(self.vfs.file_cache[parent_iso_id]['modifiedTime'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    except Exception:
                        return int(time.time())
            return int(time.time())
        
        if file_id in self.vfs.file_cache:
            try:
                return int(time.mktime(time.strptime(self.vfs.file_cache[file_id]['modifiedTime'], '%Y-%m-%dT%H:%M:%S.%fZ')))
            except Exception:
                return 0
        return 0


class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr, gdrive_manager: GoogleDriveManager, direct_mode: bool = False):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.gdrive_manager = gdrive_manager
        self.direct_mode = direct_mode
        self.ro_file = None  # opened read-only file object
        self.wo_file = None  # opened write-only file object
        self.dirpath = None
        self.subdirs = False
        # directory iteration state for READ_DIR_ENTRY
        self._dir_entries = None
        self._dir_index = 0
        # CD sector size detection
        self.cd_sector_size = 2352  # default
        # Multi-part ISO support
        self.multipart_files = []  # list of file handles for multi-part ISOs
        self.multipart_sizes = []  # sizes of each part
        self.current_part = 0
        self.part_size = 0
        # Virtual ISO support
        self.viso_file = None  # Virtual ISO file object
        self.viso_sector_size = 2352  # Virtual ISO sector size
        # Encryption support
        self.decryptor = None  # PS3 decryptor
        # Google Drive support
        self.current_file_id = None  # Current Google Drive file ID
        self.current_file_size = 0
        self.current_file_mtime = 0
        self.current_filename = None


    def detect_cd_sector_size(self, file_path: Path) -> int:
        """Detect CD sector size by checking for signatures at different sector sizes."""
        if not file_path.exists() or not file_path.is_file():
            return 2352
        
        file_size = file_path.stat().st_size
        
        # Only check files in the range 2MB to 848MB (typical CD/DVD range)
        if not (0x200000 <= file_size <= 0x35000000):
            return 2352
        
        sector_sizes = [2352, 2048, 2336, 2448, 2328, 2368, 2340]
        
        try:
            with open(file_path, 'rb') as f:
                for sector_size in sector_sizes:
                    # Check at sector 16 (0x10) + 0x18 offset
                    offset = (sector_size << 4) + 0x18
                    if offset + 0xC > file_size:
                        continue
                    
                    f.seek(offset)
                    data = f.read(0xC)
                    
                    # Check for "PLAYSTATION " signature
                    if data[8:8+0xC] == b"PLAYSTATION ":
                        #logger.debug('Detected PS3 signature at sector size %d', sector_size)
                        return sector_size
                    
                    # Check for "CD001" signature (ISO9660)
                    if len(data) >= 6 and data[1:6] == b"CD001" and data[0] == 0x01:
                        #logger.debug('Detected ISO9660 signature at sector size %d', sector_size)
                        return sector_size
        
        except Exception as e:
            #logger.debug('Error detecting sector size: %s', e)
        
        return 2352  # default

    def translate_path(self, net_path: str) -> str | None:
        """Translate client path to Google Drive virtual path"""
        if not net_path.startswith('/'):
            logger.error('Received non-absolute path: %r', net_path)
            return None

        # basic security: reject '/..' segments
        if '/..' in net_path:
            logger.error('Rejected insecure path containing ..: %r', net_path)
            return None

        # remove PS3-specific tokens like "/***PS3***/" and "/***DVD***/"
        if net_path.startswith('/***PS3***/'):
            net_path = net_path[len('/***PS3***/') - 1:]
        if net_path.startswith('/***DVD***/'):
            net_path = net_path[len('/***DVD***/') - 1:]

        # Return the normalized path for Google Drive
        return net_path

    def check_merge_directories(self, fs_path: Path, net_path: str) -> Path | None:
        """Check for merge directories using .INI files"""
        if fs_path.exists():
            return fs_path
        
        # Look for .INI files in parent directories
        current_path = fs_path
        while current_path != self.root:
            ini_path = current_path.with_suffix('.INI')
            if ini_path.exists():
                #logger.debug('Found merge INI file: %s', ini_path)
                # Read INI file and check if any listed directory contains the file
                merged_path = self.find_in_merge_directories(ini_path, fs_path.name)
                if merged_path:
                    #logger.debug('Found file in merge directory: %s', merged_path)
                    return merged_path
            current_path = current_path.parent
        
        return fs_path

    def find_in_merge_directories(self, ini_path: Path, filename: str) -> Path | None:
        """Find a file in directories listed in an INI file"""
        try:
            with open(ini_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse INI file - each line is a directory path
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Normalize path
                line = line.replace('\\', '/')
                if not line.startswith('/'):
                    line = '/' + line
                
                # Try to find the file in this directory
                merge_dir = self.root / line.lstrip('/')
                if merge_dir.exists() and merge_dir.is_dir():
                    target_file = merge_dir / filename
                    if target_file.exists():
                        return target_file
            
            return None

        except Exception as e:
            #logger.debug('Error reading merge INI file %s: %s', ini_path, e)
            return None

    def send_open_result(self, file_size: int, mtime: int):
        # netiso_open_result: int64 file_size; uint64 mtime; (both big-endian)
        packed = struct.pack('>qQ', file_size, mtime)
        self.conn.sendall(packed)

    def open_multipart_iso(self, base_path: Path) -> bool:
        """Open multi-part ISO files (.iso.0, .iso.1, etc.)"""
        try:
            # Close any existing multipart files
            self.close_multipart_iso()
            
            # Check if it's a multi-part ISO
            if not str(base_path).endswith('.iso.0') and not str(base_path).endswith('.ISO.0'):
                return False
            
            # Get base path without .0 extension
            base_str = str(base_path)
            if base_str.endswith('.iso.0'):
                base_str = base_str[:-6]  # remove .iso.0
            elif base_str.endswith('.ISO.0'):
                base_str = base_str[:-6]  # remove .ISO.0
            
            # Open all parts
            total_size = 0
            for i in range(64):  # maximum 64 parts
                part_path = Path(f"{base_str}.iso.{i}")
                if not part_path.exists():
                    part_path = Path(f"{base_str}.ISO.{i}")
                if not part_path.exists():
                    break
                
                try:
                    f = open(part_path, 'rb')
                    st = part_path.stat()
                    self.multipart_files.append(f)
                    self.multipart_sizes.append(st.st_size)
                    total_size += st.st_size
                    
                    if i == 0:
                        self.part_size = st.st_size
                        # Detect sector size from first part
                        self.cd_sector_size = self.detect_cd_sector_size(part_path)
                        if self.cd_sector_size != 2352:
                            #logger.info('CD sector size: %d', self.cd_sector_size)
                    
                    #logger.debug('Opened part %d: %s (%d bytes)', i, part_path, st.st_size)
                except Exception as e:
                    logger.error('Failed to open part %d: %s', i, e)
                    self.close_multipart_iso()
                    return False
            
            if not self.multipart_files:
                return False
            
            #logger.info('Opened multi-part ISO: %d parts, total %d bytes', len(self.multipart_files), total_size)
            return True
            
        except Exception as e:
            logger.error('Error opening multi-part ISO: %s', e)
            self.close_multipart_iso()
            return False

    def close_multipart_iso(self):
        """Close all multi-part ISO files"""
        for f in self.multipart_files:
            try:
                f.close()
            except Exception:
                pass
        self.multipart_files.clear()
        self.multipart_sizes.clear()
        self.current_part = 0
        self.part_size = 0

    def seek_multipart_iso(self, offset: int) -> bool:
        """Seek in multi-part ISO"""
        if not self.multipart_files:
            return False
        
        try:
            # Calculate which part contains the offset
            current_offset = 0
            for i, part_size in enumerate(self.multipart_sizes):
                if offset < current_offset + part_size:
                    # Found the part
                    if i != self.current_part:
                        # Switch to the correct part
                        self.current_part = i
                    
                    # Seek within the part
                    part_offset = offset - current_offset
                    self.multipart_files[self.current_part].seek(part_offset)
                    return True
                
                current_offset += part_size
            
            # Offset is beyond the end
            return False
            
        except Exception as e:
            logger.error('Error seeking in multi-part ISO: %s', e)
            return False

    def read_multipart_iso(self, size: int) -> bytes:
        """Read from multi-part ISO"""
        if not self.multipart_files:
            return b''
        
        try:
            data = b''
            remaining = size
            
            while remaining > 0 and self.current_part < len(self.multipart_files):
                current_file = self.multipart_files[self.current_part]
                current_pos = current_file.tell()
                current_size = self.multipart_sizes[self.current_part]
                
                # Calculate how much we can read from current part
                available_in_part = current_size - current_pos
                to_read = min(remaining, available_in_part)
                
                if to_read > 0:
                    chunk = current_file.read(to_read)
                    data += chunk
                    remaining -= len(chunk)
                
                # If we need more data and there's another part, switch to it
                if remaining > 0 and self.current_part + 1 < len(self.multipart_files):
                    self.current_part += 1
                    self.multipart_files[self.current_part].seek(0)
                else:
                    break
            
            return data
            
        except Exception as e:
            logger.error('Error reading from multi-part ISO: %s', e)
            return b''

    def handle_open_file(self, data: bytes):
        # netiso_open_cmd: opcode (H) fp_len (H) pad(12)
        _, fp_len = struct.unpack('>HH', data[:4])
        path_bytes = recv_all(self.conn, fp_len)
        if len(path_bytes) != fp_len:
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        
        # Log apenas para arquivos ISO
        if net_path.endswith('.iso'):
            print(f'Leitura da ISO {net_path}')

        if fp_len == 10 and net_path == '/CLOSEFILE':
            #logger.debug('CLOSEFILE received')
            if self.ro_file:
                try:
                    self.ro_file.close()
                except Exception:
                    pass
                self.ro_file = None
            self.close_multipart_iso()
            
            self.current_file_id = None
            # return file_size = -1 and mtime = 0 as in original
            self.send_open_result(-1, 0)
            return True

        gdrive_path = self.translate_path(net_path)
        if not gdrive_path:
            logger.error('OPEN_FILE: cannot translate path %s', net_path)
            self.send_open_result(-1, 0)
            return False

        # Check if it's a directory request (root)
        if gdrive_path == '/' or gdrive_path == '' or gdrive_path == '.' or gdrive_path == '/.':
            #logger.debug('OPEN_FILE: root directory request')
            self.current_file_id = None
            self.send_open_result(0, int(time.time()))
            return True

        # Get file from Google Drive using pre-processed structure
        file_result = self.gdrive_manager.get_file_by_path(gdrive_path)
        if not file_result:
            logger.warning('OPEN_FILE: file not found in Google Drive: %s', gdrive_path)
            self.send_open_result(-1, 0)
            return False

        file_id, file_info = file_result
        
        # Check if it's a directory
        if file_info.get('mimeType') == 'application/vnd.google-apps.folder':
            #logger.debug('OPEN_FILE: path is directory: %s', gdrive_path)
            self.current_file_id = None
            self.send_open_result(0, self.gdrive_manager.get_file_mtime(file_id))
            return True

        # It's a file - store file info for streaming
        self.current_file_id = file_id
        self.current_file_size = self.gdrive_manager.get_file_size(file_id)
        self.current_file_mtime = self.gdrive_manager.get_file_mtime(file_id)
        self.current_filename = file_info['name']
        
        if self.direct_mode:
            # Modo direto - apenas preparar conexão persistente
            #logger.info('Opened Google Drive file in DIRECT mode: %s (%d bytes)', file_info['name'], self.current_file_size)
        else:
            # Modo cache - iniciar download em background da ISO completa (se não estiver já baixada)
        if not self.gdrive_manager.background_downloader.is_iso_cached(file_id, self.current_filename, self.current_file_size):
            if not self.gdrive_manager.background_downloader.is_downloading(file_id):
                    #logger.info('Starting background download for %s', self.current_filename)
                self.gdrive_manager.background_downloader.start_background_download(
                    self.gdrive_manager, file_id, self.current_filename, self.current_file_size
                )
            else:
                    #logger.info('Background download already in progress for %s', self.current_filename)
        else:
                #logger.info('ISO already cached locally: %s', self.current_filename)
        
        #logger.info('Opened Google Drive file %s (%d bytes)', file_info['name'], self.current_file_size)
        self.send_open_result(self.current_file_size, self.current_file_mtime)
        return True

    def handle_read_file_critical(self, data: bytes):
        # netiso_read_file_critical_cmd: opcode(H) pad(H) num_bytes(I) offset(Q)
        _, _, num_bytes, offset = struct.unpack('>HHIQ', data)
        
        if self.current_file_id:
            # Google Drive file - implementar leitura baseada no modo
            try:
                if self.direct_mode:
                    # Modo direto - download direto do Google Drive com conexão persistente
                    #logger.debug('DIRECT MODE: downloading %d bytes from offset %d', num_bytes, offset)
                    
                    gdrive_data = self.gdrive_manager.download_file_chunk_direct(
                        self.current_file_id, offset, num_bytes
                    )
                    
                    if not gdrive_data or len(gdrive_data) == 0:
                        logger.error('READ_FILE_CRITICAL: failed to download from Google Drive (got %d bytes)', 
                                   len(gdrive_data) if gdrive_data else 0)
                        return False
                    
                    # Verificar se dados têm tamanho mínimo esperado
                    if len(gdrive_data) < num_bytes * 0.1:  # Menos que 10% do esperado
                        logger.error('READ_FILE_CRITICAL: data too small (%d bytes, expected %d)', 
                                   len(gdrive_data), num_bytes)
                        return False
                    
                    # Enviar dados do Google Drive
                    self.conn.sendall(gdrive_data)
                    #logger.debug('DIRECT MODE: sent %d bytes from persistent connection', len(gdrive_data))
                    return True
                    
                else:
                    # Modo cache - leitura híbrida (local + Google Drive)
                # PAUSAR download em background para priorizar requisição em tempo real
                if self.gdrive_manager.background_downloader.is_downloading(self.current_file_id):
                    self.gdrive_manager.background_downloader.pause_download_temporarily(self.current_file_id, 1.5)  # Reduzido para 1.5s
                
                # Primeiro tentar ler do arquivo ISO local (se disponível)
                local_data = self.gdrive_manager.background_downloader.read_from_cached_iso(
                    self.current_file_id, self.current_filename, offset, num_bytes
                )
                
                if local_data is not None and len(local_data) >= num_bytes:
                    # Dados disponíveis localmente - enviar imediatamente
                    self.conn.sendall(local_data)
                    return True
                elif local_data is not None and len(local_data) > 0:
                    # Dados parciais disponíveis localmente - enviar o que temos e buscar o resto
                        # logger.debug('Local ISO PARTIAL: sending %d bytes from cached ISO, need %d more', 
                        #            len(local_data), num_bytes - len(local_data))
                    self.conn.sendall(local_data)
                    
                    # Buscar dados restantes do Google Drive
                    remaining_bytes = num_bytes - len(local_data)
                    remaining_offset = offset + len(local_data)
                    
                    gdrive_data = self.gdrive_manager.download_file_chunk(
                        self.current_file_id, remaining_offset, remaining_bytes
                    )
                    
                    if gdrive_data and len(gdrive_data) > 0:
                        self.conn.sendall(gdrive_data)
                            #logger.debug('Google Drive FALLBACK: sent %d bytes from Drive', len(gdrive_data))
                        
                        return True
                    else:
                        logger.error('Failed to get remaining data from Google Drive')
                        return False
                else:
                    # Dados não disponíveis localmente - buscar do Google Drive
                    
                    gdrive_data = self.gdrive_manager.download_file_chunk(
                        self.current_file_id, offset, num_bytes
                    )
                    
                    if not gdrive_data or len(gdrive_data) == 0:
                        logger.error('READ_FILE_CRITICAL: failed to download from Google Drive (got %d bytes)', 
                                   len(gdrive_data) if gdrive_data else 0)
                        return False
                    
                    # Verificar se dados têm tamanho mínimo esperado
                    if len(gdrive_data) < num_bytes * 0.1:  # Menos que 10% do esperado
                        logger.error('READ_FILE_CRITICAL: data too small (%d bytes, expected %d)', 
                                   len(gdrive_data), num_bytes)
                        return False
                    
                    # Enviar dados do Google Drive
                    self.conn.sendall(gdrive_data)
                    
                    return True
                    
            except Exception as e:
                logger.error('READ_FILE_CRITICAL: error: %s', e)
                return False
        
        elif self.viso_file:
            # Virtual ISO
            try:
                remaining = num_bytes
                current_offset = offset
                while remaining > 0:
                    to_read = min(BUFFER_SIZE, remaining)
                    # Calculate which sector to read
                    sector = current_offset // self.viso_file.sector_size
                    sector_offset = current_offset % self.viso_file.sector_size
                    
                    sector_data = self.viso_file.read_sector(sector)
                    if sector_offset > 0:
                        sector_data = sector_data[sector_offset:]
                    
                    chunk = sector_data[:to_read]
                    if len(chunk) < to_read:
                        chunk += b'\x00' * (to_read - len(chunk))
                    
                    self.conn.sendall(chunk)
                    remaining -= len(chunk)
                    current_offset += len(chunk)
                return True
            except Exception as e:
                logger.error('READ_FILE_CRITICAL: Virtual ISO error: %s', e)
                return False
        
        elif self.multipart_files:
            # Multi-part ISO
            if not self.seek_multipart_iso(offset):
                logger.error('READ_FILE_CRITICAL: seek failed in multi-part ISO')
                return False
            
            remaining = num_bytes
            while remaining > 0:
                to_read = min(BUFFER_SIZE, remaining)
                chunk = self.read_multipart_iso(to_read)
                if not chunk:
                    logger.error('READ_FILE_CRITICAL: unexpected EOF in multi-part ISO')
                    return False
                self.conn.sendall(chunk)
                remaining -= len(chunk)
            return True
        
        elif self.ro_file:
            # Regular file
            try:
                self.ro_file.seek(offset)
                remaining = num_bytes
                while remaining > 0:
                    to_read = min(BUFFER_SIZE, remaining)
                    chunk = self.ro_file.read(to_read)
                    if not chunk:
                        logger.error('READ_FILE_CRITICAL: unexpected EOF')
                        return False
                    
                    # Decrypt if needed
                    if self.decryptor and self.decryptor.is_encrypted:
                        chunk = self.decryptor.decrypt_data(chunk)
                    
                    self.conn.sendall(chunk)
                    remaining -= len(chunk)
                return True
            except Exception:
                logger.exception('READ_FILE_CRITICAL error')
                return False
        else:
            logger.error('READ_FILE_CRITICAL: no file open')
            return False

    def handle_read_cd_2048(self, data: bytes):
        # netiso_read_cd_2048_critical_cmd: opcode(H) pad(H) start_sector(I) sector_count(I) pad2(I)
        _, _, start_sector, sector_count, _ = struct.unpack('>HHIII', data)
        
        if self.current_file_id:
            # Google Drive file - implementar leitura baseada no modo
            sector_size = self.cd_sector_size
            offset = start_sector * sector_size
            out = bytearray()
            
            if self.direct_mode:
                # Modo direto - download direto do Google Drive com conexão persistente
                #logger.debug('DIRECT MODE: downloading %d CD sectors from offset %d', sector_count, offset)
                
                # Processar cada setor individualmente
                for i in range(sector_count):
                    sector_offset = offset + (i * sector_size) + 24  # Skip 24 bytes header
                    
                    chunk = self.gdrive_manager.download_file_chunk_direct(
                        self.current_file_id, sector_offset, 2048
                    )
                    
                    if not chunk or len(chunk) != 2048:
                        logger.error('READ_CD_2048: short read from Google Drive (got %d bytes)', len(chunk) if chunk else 0)
                        return False
                    
                    out += chunk
                    #logger.debug('DIRECT MODE: CD sector %d bytes from persistent connection', len(chunk))
                
                # Send all sectors at once (like ps3netsrv)
                self.conn.sendall(bytes(out))
                return True
                
            else:
                # Modo cache - leitura híbrida para CD sectors
                # PAUSAR download em background para priorizar requisição em tempo real
                if self.gdrive_manager.background_downloader.is_downloading(self.current_file_id):
                    self.gdrive_manager.background_downloader.pause_download_temporarily(self.current_file_id, 2.0)
            
            # Processar cada setor individualmente
            for i in range(sector_count):
                sector_offset = offset + (i * sector_size) + 24  # Skip 24 bytes header
                
                # Primeiro tentar ler do arquivo ISO local (se disponível)
                local_data = self.gdrive_manager.background_downloader.read_from_cached_iso(
                    self.current_file_id, self.current_filename, sector_offset, 2048
                )
                
                if local_data is not None and len(local_data) == 2048:
                    # Setor disponível localmente - usar imediatamente
                        # logger.debug('Local ISO HIT: CD sector at offset %d', sector_offset)
                    out += local_data
                elif local_data is not None and len(local_data) > 0:
                    # Dados parciais disponíveis localmente - buscar o resto do Google Drive
                        # logger.debug('Local ISO PARTIAL: CD sector %d bytes from cached ISO, need %d more', 
                        #            len(local_data), 2048 - len(local_data))
                    
                    # Buscar dados restantes do Google Drive
                    remaining_bytes = 2048 - len(local_data)
                    remaining_offset = sector_offset + len(local_data)
                    
                    gdrive_data = self.gdrive_manager.download_file_chunk(
                        self.current_file_id, remaining_offset, remaining_bytes
                    )
                    
                    if gdrive_data and len(gdrive_data) > 0:
                        sector_data = local_data + gdrive_data
                        if len(sector_data) == 2048:
                            out += sector_data
                                #logger.debug('Google Drive FALLBACK: CD sector %d bytes total', len(sector_data))
                        else:
                            logger.error('READ_CD_2048: incomplete sector data (%d bytes)', len(sector_data))
                            return False
                    else:
                        logger.error('READ_CD_2048: failed to get remaining sector data from Google Drive')
                        return False
                else:
                    # Setor não disponível localmente - buscar do Google Drive
                        #logger.debug('Local ISO MISS: downloading CD sector at offset %d', sector_offset)
                    chunk = self.gdrive_manager.download_file_chunk(
                        self.current_file_id, sector_offset, 2048
                    )
                    
                    if not chunk or len(chunk) != 2048:
                        logger.error('READ_CD_2048: short read from Google Drive (got %d bytes)', len(chunk) if chunk else 0)
                        return False
                    
                    out += chunk
                        #logger.debug('Google Drive STREAM: CD sector %d bytes from Drive', len(chunk))
            
            # Send all sectors at once (like ps3netsrv)
            self.conn.sendall(bytes(out))
            return True
        
        elif self.viso_file:
            # Virtual ISO
            out = bytearray()
            for i in range(sector_count):
                sector_data = self.viso_file.read_sector(start_sector + i)
                # Extract 2048 bytes from sector (skip 24 bytes header)
                if len(sector_data) >= 2072:  # 24 + 2048
                    out += sector_data[24:24+2048]
                else:
                    # Pad with zeros if sector is too small
                    out += b'\x00' * 2048
            self.conn.sendall(bytes(out))
            return True
        
        elif self.multipart_files:
            # Multi-part ISO
            sector_size = self.cd_sector_size
            offset = start_sector * sector_size
            out = bytearray()
            for i in range(sector_count):
                if not self.seek_multipart_iso(offset + 24):
                    logger.error('READ_CD_2048: seek failed in multi-part ISO')
                    return False
                chunk = self.read_multipart_iso(2048)
                if len(chunk) != 2048:
                    logger.error('READ_CD_2048: short read in multi-part ISO')
                    return False
                out += chunk
                offset += sector_size
            self.conn.sendall(bytes(out))
            return True
        
        elif self.ro_file:
            # Regular file
            sector_size = self.cd_sector_size
            offset = start_sector * sector_size
            out = bytearray()
            for i in range(sector_count):
                self.ro_file.seek(offset + 24)
                chunk = self.ro_file.read(2048)
                if len(chunk) != 2048:
                    logger.error('READ_CD_2048: short read')
                    return False
                
                # Decrypt if needed
                if self.decryptor and self.decryptor.is_encrypted:
                    chunk = self.decryptor.decrypt_data(chunk)
                
                out += chunk
                offset += sector_size
            self.conn.sendall(bytes(out))
            return True
        else:
            logger.error('READ_CD_2048: no file open')
            return False

    def handle_read_file(self, data: bytes):
        # netiso_read_file_cmd: opcode(H) pad(H) num_bytes(I) offset(Q)
        _, _, num_bytes, offset = struct.unpack('>HHIQ', data)
        result_bytes = -1
        buf = b''
        
        if self.current_file_id:
            # Google Drive file - implementar leitura baseada no modo
            try:
                if self.direct_mode:
                    # Modo direto - download direto do Google Drive com conexão persistente
                    #logger.debug('DIRECT MODE: downloading READ_FILE %d bytes from offset %d', num_bytes, offset)
                    
                    buf = self.gdrive_manager.download_file_chunk_direct(
                        self.current_file_id, offset, num_bytes
                    )
                    
                    if not buf or len(buf) == 0:
                        logger.error('READ_FILE: failed to download from Google Drive (got %d bytes)', 
                                   len(buf) if buf else 0)
                        result_bytes = -1
                    else:
                        result_bytes = len(buf)
                        #logger.debug('DIRECT MODE: READ_FILE %d bytes from persistent connection', result_bytes)
                        
                else:
                    # Modo cache - leitura híbrida (local + Google Drive)
                # PAUSAR download em background para priorizar requisição em tempo real
                if self.gdrive_manager.background_downloader.is_downloading(self.current_file_id):
                    self.gdrive_manager.background_downloader.pause_download_temporarily(self.current_file_id, 1.5)  # Reduzido para 1.5s
                
                # Primeiro tentar ler do arquivo ISO local (se disponível)
                local_data = self.gdrive_manager.background_downloader.read_from_cached_iso(
                    self.current_file_id, self.current_filename, offset, num_bytes
                )
                
                if local_data is not None and len(local_data) >= num_bytes:
                    # Dados disponíveis localmente - usar imediatamente
                    buf = local_data[:num_bytes]
                    result_bytes = len(buf)
                        # logger.debug('Local ISO HIT: READ_FILE %d bytes from cached ISO', result_bytes)
                elif local_data is not None and len(local_data) > 0:
                    # Dados parciais disponíveis localmente - usar o que temos e buscar o resto
                        # logger.debug('Local ISO PARTIAL: READ_FILE %d bytes from cached ISO, need %d more', 
                        #            len(local_data), num_bytes - len(local_data))
                    
                    # Buscar dados restantes do Google Drive
                    remaining_bytes = num_bytes - len(local_data)
                    remaining_offset = offset + len(local_data)
                    
                    gdrive_data = self.gdrive_manager.download_file_chunk(
                        self.current_file_id, remaining_offset, remaining_bytes
                    )
                    
                    if gdrive_data and len(gdrive_data) > 0:
                        buf = local_data + gdrive_data
                        result_bytes = len(buf)
                            #logger.debug('Google Drive FALLBACK: READ_FILE %d bytes total', result_bytes)
                    else:
                        logger.error('Failed to get remaining data from Google Drive')
                        result_bytes = -1
                else:
                    # Dados não disponíveis localmente - buscar do Google Drive
                        #logger.debug('Local ISO MISS: downloading READ_FILE %d bytes from Google Drive', num_bytes)
                    
                    buf = self.gdrive_manager.download_file_chunk(
                        self.current_file_id, offset, num_bytes
                    )
                    
                    if not buf or len(buf) == 0:
                        logger.error('READ_FILE: failed to download from Google Drive (got %d bytes)', 
                                   len(buf) if buf else 0)
                        result_bytes = -1
                    else:
                        result_bytes = len(buf)
                            #logger.debug('Google Drive STREAM: READ_FILE %d bytes from Drive', result_bytes)
                
            except Exception as e:
                logger.error('READ_FILE: error: %s', e)
                result_bytes = -1
        
        elif self.viso_file:
            # Virtual ISO
            try:
                remaining = num_bytes
                current_offset = offset
                data_parts = []
                
                while remaining > 0:
                    to_read = min(BUFFER_SIZE, remaining)
                    # Calculate which sector to read
                    sector = current_offset // self.viso_file.sector_size
                    sector_offset = current_offset % self.viso_file.sector_size
                    
                    sector_data = self.viso_file.read_sector(sector)
                    if sector_offset > 0:
                        sector_data = sector_data[sector_offset:]
                    
                    chunk = sector_data[:to_read]
                    if len(chunk) < to_read:
                        chunk += b'\x00' * (to_read - len(chunk))
                    
                    data_parts.append(chunk)
                    remaining -= len(chunk)
                    current_offset += len(chunk)
                
                buf = b''.join(data_parts)
                result_bytes = len(buf)
            except Exception as e:
                logger.error('READ_FILE: Virtual ISO error: %s', e)
                result_bytes = -1
        
        elif self.multipart_files:
            # Multi-part ISO
            if not self.seek_multipart_iso(offset):
                logger.error('READ_FILE: seek failed in multi-part ISO')
                result_bytes = -1
            else:
                buf = self.read_multipart_iso(num_bytes)
                result_bytes = len(buf)
        
        elif self.ro_file:
            # Regular file
            try:
                self.ro_file.seek(offset)
                buf = self.ro_file.read(num_bytes)
                if buf is None:
                    result_bytes = -1
                    buf = b''
                else:
                    result_bytes = len(buf)
                    # Decrypt if needed
                    if self.decryptor and self.decryptor.is_encrypted:
                        buf = self.decryptor.decrypt_data(buf)
            except Exception:
                logger.exception('READ_FILE error')
                result_bytes = -1
        else:
            logger.error('READ_FILE: no file open')
            result_bytes = -1

        self.conn.sendall(struct.pack('>i', result_bytes))
        if result_bytes > 0:
            self.conn.sendall(buf)
        return result_bytes >= 0

    def handle_open_dir(self, data: bytes):
        # netiso_open_dir_cmd: opcode(H) dp_len(H) pad(12)
        _, dp_len = struct.unpack('>HH', data[:4])
        path_bytes = recv_all(self.conn, dp_len)
        if len(path_bytes) != dp_len:
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        
        # Log apenas para diretórios principais
        if net_path in ['/PS3ISO', '/PKG', '/GAMES']:
            print(f'Leitura do diretorio {net_path}')

        self.subdirs = '//' in net_path
        gdrive_path = self.translate_path(net_path)
        result = -1
        
        if gdrive_path:
            # Store the virtual path for directory operations
            self.dirpath = gdrive_path
            #logger.info('Opened Google Drive directory %s', gdrive_path)
            result = 0
        else:
            logger.warning('OPEN_DIR: path not found %s', net_path)

        self.conn.sendall(struct.pack('>i', result))
        return result == 0

    def handle_create(self, data: bytes):
        # netiso_create_cmd: opcode(H) fp_len(H) pad(12)
        _, fp_len = struct.unpack('>HH', data[:4])
        #logger.debug('CREATE fp_len=%d', fp_len)
        path_bytes = recv_all(self.conn, fp_len)
        if len(path_bytes) != fp_len:
            logger.error('CREATE: failed to receive full path')
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        #logger.debug('CREATE requested path: %s', net_path)

        fs_path = self.translate_path(net_path)
        result = -1
        if not fs_path:
            logger.warning('CREATE: translate failed %s', net_path)
        else:
            # If path is a directory, treat as closing file (C server treats directory as closing file)
            try:
                if fs_path.exists() and fs_path.is_dir():
                    #logger.debug('CREATE: path is directory, not creating file')
                    self.wo_file = None
                    result = 0
                else:
                    # ensure parent exists
                    parent = fs_path.parent
                    parent.mkdir(parents=True, exist_ok=True)
                    f = open(fs_path, 'wb')
                    self.wo_file = f
                    #logger.info('CREATE: created file %s', fs_path)
                    result = 0
            except Exception:
                logger.exception('CREATE failed for %s', fs_path)
                result = -1

        # send netiso_create_result (int32 create_result)
        self.conn.sendall(struct.pack('>i', result))
        return True

    def handle_write_file(self, data: bytes):
        # netiso_write_file_cmd: opcode(H) pad(H) num_bytes(I) pad2(Q)
        _, _, num_bytes, _ = struct.unpack('>HHIQ', data)
        #logger.debug('WRITE_FILE num_bytes=%d', num_bytes)
        if not self.wo_file:
            logger.error('WRITE_FILE: no write file open')
            self.conn.sendall(struct.pack('>i', -1))
            return False

        if num_bytes > BUFFER_SIZE:
            logger.error('WRITE_FILE: num_bytes too large %d', num_bytes)
            self.conn.sendall(struct.pack('>i', -1))
            return False

        payload = recv_all(self.conn, num_bytes)
        if len(payload) != num_bytes:
            logger.error('WRITE_FILE: short payload %d/%d', len(payload), num_bytes)
            self.conn.sendall(struct.pack('>i', -1))
            return False

        try:
            self.wo_file.write(payload)
            self.wo_file.flush()
            bytes_written = num_bytes
            #logger.debug('WRITE_FILE: wrote %d bytes', bytes_written)
        except Exception:
            logger.exception('WRITE_FILE failed')
            bytes_written = -1

        self.conn.sendall(struct.pack('>i', bytes_written))
        return bytes_written >= 0

    def handle_delete(self, data: bytes):
        # netiso_delete_file_cmd: opcode(H) fp_len(H) pad(12)
        _, fp_len = struct.unpack('>HH', data[:4])
        #logger.debug('DELETE fp_len=%d', fp_len)
        path_bytes = recv_all(self.conn, fp_len)
        if len(path_bytes) != fp_len:
            logger.error('DELETE: failed to receive full path')
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        fs_path = self.translate_path(net_path)
        result = -1
        if not fs_path:
            logger.warning('DELETE: translate failed %s', net_path)
        else:
            try:
                fs_path.unlink()
                #logger.info('DELETE: removed %s', fs_path)
                result = 0
            except Exception:
                logger.exception('DELETE failed for %s', fs_path)
                result = -1

        self.conn.sendall(struct.pack('>i', result))
        return True

    def handle_mkdir(self, data: bytes):
        # netiso_mkdir_cmd: opcode(H) dp_len(H) pad(12)
        _, dp_len = struct.unpack('>HH', data[:4])
        #logger.debug('MKDIR dp_len=%d', dp_len)
        path_bytes = recv_all(self.conn, dp_len)
        if len(path_bytes) != dp_len:
            logger.error('MKDIR: failed to receive full path')
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        fs_path = self.translate_path(net_path)
        result = -1
        if not fs_path:
            logger.warning('MKDIR: translate failed %s', net_path)
        else:
            try:
                fs_path.mkdir(parents=True, exist_ok=False)
                #logger.info('MKDIR created %s', fs_path)
                result = 0
            except Exception:
                logger.exception('MKDIR failed for %s', fs_path)
                result = -1

        self.conn.sendall(struct.pack('>i', result))
        return True

    def handle_rmdir(self, data: bytes):
        # netiso_rmdir_cmd: opcode(H) dp_len(H) pad(12)
        _, dp_len = struct.unpack('>HH', data[:4])
        #logger.debug('RMDIR dp_len=%d', dp_len)
        path_bytes = recv_all(self.conn, dp_len)
        if len(path_bytes) != dp_len:
            logger.error('RMDIR: failed to receive full path')
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        fs_path = self.translate_path(net_path)
        result = -1
        if not fs_path:
            logger.warning('RMDIR: translate failed %s', net_path)
        else:
            try:
                fs_path.rmdir()
                #logger.info('RMDIR removed %s', fs_path)
                result = 0
            except Exception:
                logger.exception('RMDIR failed for %s', fs_path)
                result = -1

        self.conn.sendall(struct.pack('>i', result))
        return True

    def calculate_directory_size(self, path: Path) -> int:
        total = 0
        try:
            for root, dirs, files in os.walk(path):
                for f in files:
                    try:
                        total += (Path(root) / f).stat().st_size
                    except Exception:
                        #logger.debug('calculate_directory_size: failed for %s/%s', root, f)
        except Exception:
            logger.exception('calculate_directory_size failed for %s', path)
            return -1
        return total

    def handle_get_dir_size(self, data: bytes):
        # netiso_get_dir_size_cmd: opcode(H) dp_len(H) pad(12)
        _, dp_len = struct.unpack('>HH', data[:4])
        #logger.debug('GET_DIR_SIZE dp_len=%d', dp_len)
        path_bytes = recv_all(self.conn, dp_len)
        if len(path_bytes) != dp_len:
            logger.error('GET_DIR_SIZE: failed to receive full path')
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        fs_path = self.translate_path(net_path)
        if not fs_path:
            logger.warning('GET_DIR_SIZE: translate failed %s', net_path)
            self.conn.sendall(struct.pack('>q', -1))
            return True

        size = self.calculate_directory_size(fs_path)
        self.conn.sendall(struct.pack('>q', size))
        return True

    def _next_dir_entry(self):
        """Return next valid (name, stat) tuple or None when exhausted."""
        if (self._dir_entries is None) or (self.dirpath is None):
            return None

        while self._dir_index < len(self._dir_entries):
            name = self._dir_entries[self._dir_index]
            self._dir_index += 1
            full = self.dirpath / name
            try:
                st = full.stat()
            except FileNotFoundError:
                # skip entries that disappeared
                continue
            except Exception:
                logger.exception('Error stating dir entry %s', full)
                continue

            return name, st, full.is_dir()

        # exhausted -> cleanup similar to C server
        self._dir_entries = None
        self._dir_index = 0
        self.dirpath = None
        return None

    def handle_read_dir_entry(self, data: bytes, version: int):
        """Handle READ_DIR_ENTRY v1 (version=1) and v2 (version=2).
        v1: send netiso_read_dir_entry_result (int64 file_size; uint16 fn_len; int8 is_directory)
        v2: send netiso_read_dir_entry_result_v2 (int64 file_size; uint64 mtime; uint64 ctime; uint64 atime; uint16 fn_len; int8 is_directory)
        After the struct, if file_size != -1, send filename of length fn_len.
        """
        # if no directory open, return file_size = -1
        entry = self._next_dir_entry()
        if not entry:
            # send file_size = -1
            if version == 1:
                packed = struct.pack('>qHb', -1, 0, 0)
                # Note: original v1 struct is packed 8 + 2 + 1 = 11 bytes
                self.conn.sendall(packed)
            else:
                # v2: 8 + 8 + 8 + 8 + 2 + 1 = 35 bytes
                packed = struct.pack('>qQQQHb', -1, 0, 0, 0, 0, 0)
                self.conn.sendall(packed)
            return True

        name, st, is_dir = entry

        file_size = 0 if is_dir else st.st_size
        fn_bytes = name.encode('utf-8', errors='ignore')
        fn_len = len(fn_bytes)

        if version == 1:
            # pack file_size (q), fn_len (H), is_directory (b)
            packed = struct.pack('>qHb', file_size, fn_len, 1 if is_dir else 0)
            self.conn.sendall(packed)
            # then send filename
            if file_size != -1 and fn_len > 0:
                self.conn.sendall(fn_bytes)
        else:
            # v2: file_size; mtime; ctime; atime; fn_len; is_directory
            mtime = int(st.st_mtime) if hasattr(st, 'st_mtime') else 0
            ctime = int(st.st_ctime) if hasattr(st, 'st_ctime') else 0
            atime = int(st.st_atime) if hasattr(st, 'st_atime') else 0
            packed = struct.pack('>qQQQHb', file_size, mtime, ctime, atime, fn_len, 1 if is_dir else 0)
            self.conn.sendall(packed)
            if file_size != -1 and fn_len > 0:
                self.conn.sendall(fn_bytes)

        return True

    def handle_read_dir(self, data: bytes):
        # netiso_read_dir returns count followed by entries
        #logger.debug('READ_DIR')
        if not self.dirpath:
            logger.error('READ_DIR: no directory open')
            self.conn.sendall(struct.pack('>q', -1))
            return False

        entries = []
        try:
            # Get directory contents from pre-processed Google Drive structure
            entries = self.gdrive_manager.list_directory(self.dirpath)
            
        except Exception:
            logger.exception('READ_DIR failed')
            self.conn.sendall(struct.pack('>q', -1))
            return False

        count = len(entries)
        #logger.info('READ_DIR returning %d entries for %s', count, self.dirpath)

        # send netiso_read_dir_result (int64 dir_size)
        self.conn.sendall(struct.pack('>q', count))

        # send each netiso_read_dir_result_data: int64 file_size; uint64 mtime; int8 is_directory; char name[512]
        for entry in entries:
            if len(entry) == 4:
                name, file_size, mtime, is_dir = entry
            else:
                logger.error('Invalid entry format: %s', entry)
                continue
                
            name_bytes = name.encode('utf-8', errors='ignore')[:(MAX_NAME - 1)]
            name_padded = name_bytes + b'\x00' * (MAX_NAME - len(name_bytes))
            packed = struct.pack('>qQb', file_size, mtime, is_dir) + name_padded
            # ensure length
            if len(packed) != (8 + 8 + 1 + MAX_NAME):
                logger.error('packed entry unexpected len %d', len(packed))
            self.conn.sendall(packed)

        return True

    def collect_dir_entries(self, dir_path: Path, entries: list, subdirs: bool):
        """Collect entries from a directory"""
        try:
            for name in sorted(os.listdir(dir_path)):
                if name in ('.', '..'):
                    continue
                full = dir_path / name
                try:
                    st = full.stat()
                    is_dir = 1 if full.is_dir() else 0
                    file_size = st.st_size if not full.is_dir() else 0
                    mtime = int(st.st_mtime)
                    
                    if subdirs and is_dir:
                        # For recursive mode, include subdirectory path
                        rel_path = full.relative_to(self.root)
                        display_name = str(rel_path).replace('\\', '/')
                    else:
                        display_name = name
                    
                    entries.append((file_size, mtime, is_dir, display_name))
                except Exception:
                    #logger.debug('stat failed for %s', full)
        except Exception:
            #logger.debug('listdir failed for %s', dir_path)

    def collect_merge_dir_entries(self, dir_path: Path, entries: list, subdirs: bool):
        """Collect entries from merge directories (.INI files)"""
        # Look for .INI files in parent directories
        current_path = dir_path
        while current_path != self.root:
            ini_path = current_path.with_suffix('.INI')
            if ini_path.exists():
                #logger.debug('Found merge INI file: %s', ini_path)
                self.process_merge_ini(ini_path, entries, subdirs)
            current_path = current_path.parent

    def process_merge_ini(self, ini_path: Path, entries: list, subdirs: bool):
        """Process a merge INI file and collect entries from listed directories"""
        try:
            with open(ini_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse INI file - each line is a directory path
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Normalize path
                line = line.replace('\\', '/')
                if not line.startswith('/'):
                    line = '/' + line
                
                # Try to collect entries from this directory
                merge_dir = self.root / line.lstrip('/')
                if merge_dir.exists() and merge_dir.is_dir():
                    #logger.debug('Processing merge directory: %s', merge_dir)
                    self.collect_dir_entries(merge_dir, entries, subdirs)
            
        except Exception as e:
            #logger.debug('Error processing merge INI file %s: %s', ini_path, e)

    def handle_stat(self, data: bytes):
        # netiso_stat_cmd: opcode(H) fp_len(H) pad(12)
        _, fp_len = struct.unpack('>HH', data[:4])
        path_bytes = recv_all(self.conn, fp_len)
        if len(path_bytes) != fp_len:
            logger.error('STAT: failed to receive full path')
            return False
        net_path = path_bytes.decode('utf-8', errors='ignore')
        #logger.debug('STAT requested path: %s', net_path)
        
        gdrive_path = self.translate_path(net_path)
        if not gdrive_path:
            #logger.debug('STAT: translate failed for %s (will reply -1)', net_path)
            # send file_size = -1 (client expects -1 to indicate missing/error) and keep connection
            self.conn.sendall(struct.pack('>qQQQb', -1, 0, 0, 0, 0))
            return True

        # Check if it's a virtual directory (root)
        if gdrive_path == '/' or gdrive_path == '' or gdrive_path == '.' or gdrive_path == '/.':
            # Root directory - return as directory
            self.conn.sendall(struct.pack('>qQQQb', 0, int(time.time()), int(time.time()), int(time.time()), 1))
            return True

        # Check for virtual directories (PS3ISO, PKG, GAMES)
        path_parts = gdrive_path.lstrip('/').split('/')
        if len(path_parts) == 1 and path_parts[0] in ['PS3ISO', 'PKG', 'GAMES']:
            # Virtual directory exists
            self.conn.sendall(struct.pack('>qQQQb', 0, int(time.time()), int(time.time()), int(time.time()), 1))
            return True

        # Get file from Google Drive using pre-processed structure
        file_result = self.gdrive_manager.get_file_by_path(gdrive_path)
        if not file_result:
            #logger.debug('STAT: file not found in Google Drive %s (reply -1)', gdrive_path)
            self.conn.sendall(struct.pack('>qQQQb', -1, 0, 0, 0, 0))
            return True

        file_id, file_info = file_result
        
        # Check if it's a directory
        if file_info.get('mimeType') == 'application/vnd.google-apps.folder':
            is_dir = 1
            file_size = 0
        else:
            is_dir = 0
            file_size = self.gdrive_manager.get_file_size(file_id)

        mtime = self.gdrive_manager.get_file_mtime(file_id)
        ctime = mtime  # Google Drive doesn't separate ctime/atime
        atime = mtime

        # Send successful stat result
        packed = struct.pack('>qQQQb', file_size, mtime, ctime, atime, is_dir)
        self.conn.sendall(packed)
        return True

    def run(self):
        #logger.info('Client handler started for %s', self.addr)
        try:
            while True:
                header = recv_all(self.conn, NETISO_CMD_SIZE)
                if len(header) != NETISO_CMD_SIZE:
                    #logger.debug('Client disconnected or short header: %d bytes', len(header))
                    break

                opcode = struct.unpack('>H', header[:2])[0]
                ##logger.debug('Received command opcode=0x%04X from %s', opcode, self.addr)

                # dispatch
                if opcode == NETISO_CMD_OPEN_FILE:
                    ok = self.handle_open_file(header)
                elif opcode == NETISO_CMD_READ_FILE_CRITICAL:
                    ok = self.handle_read_file_critical(header)
                elif opcode == NETISO_CMD_READ_CD_2048_CRITICAL:
                    ok = self.handle_read_cd_2048(header)
                elif opcode == NETISO_CMD_READ_FILE:
                    ok = self.handle_read_file(header)
                elif opcode == NETISO_CMD_OPEN_DIR:
                    ok = self.handle_open_dir(header)
                elif opcode == NETISO_CMD_READ_DIR:
                    ok = self.handle_read_dir(header)

                elif opcode == NETISO_CMD_READ_DIR_ENTRY:
                    ok = self.handle_read_dir_entry(header, 1)

                elif opcode == NETISO_CMD_READ_DIR_ENTRY_V2:
                    ok = self.handle_read_dir_entry(header, 2)
                elif opcode == NETISO_CMD_CREATE_FILE:
                    ok = self.handle_create(header)
                elif opcode == NETISO_CMD_WRITE_FILE:
                    ok = self.handle_write_file(header)
                elif opcode == NETISO_CMD_DELETE_FILE:
                    ok = self.handle_delete(header)
                elif opcode == NETISO_CMD_MKDIR:
                    ok = self.handle_mkdir(header)
                elif opcode == NETISO_CMD_RMDIR:
                    ok = self.handle_rmdir(header)
                elif opcode == NETISO_CMD_GET_DIR_SIZE:
                    ok = self.handle_get_dir_size(header)
                elif opcode == NETISO_CMD_STAT_FILE:
                    ok = self.handle_stat(header)
                else:
                    logger.warning('Unknown or unimplemented opcode 0x%04X', opcode)
                    ok = False

                if not ok:
                    #logger.debug('Handler requested connection close for %s', self.addr)
                    break

        finally:
            try:
                if self.ro_file:
                    self.ro_file.close()
            except Exception:
                pass
            try:
                if self.wo_file:
                    self.wo_file.close()
            except Exception:
                pass
            try:
                self.close_multipart_iso()
            except Exception:
                pass
            try:
                if self.viso_file:
                    self.viso_file = None
            except Exception:
                pass
            try:
                if self.decryptor:
                    self.decryptor = None
            except Exception:
                pass
            try:
                # ISO cache will persist after connection close
                if self.current_file_id:
                    if self.direct_mode:
                        #logger.debug('File %s persistent connection will be cleaned up automatically', self.current_file_id)
                    else:
                        #logger.debug('File %s ISO cache will persist after connection close', self.current_file_id)
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass
            #logger.info('Connection closed %s', self.addr)


class ServerManager:
    def __init__(self, port: int, whitelist: str = None, direct_mode: bool = False):
        self.port = port
        self.whitelist_start = 0
        self.whitelist_end = 0
        self.active_clients = []
        self.max_clients = 5
        self.direct_mode = direct_mode
        self.gdrive_manager = GoogleDriveManager(direct_mode)
        
        if whitelist:
            self.parse_whitelist(whitelist)
    
    def parse_whitelist(self, whitelist: str):
        """Parse IP whitelist in format x.x.x.x where x is 0-255 or *"""
        try:
            parts = whitelist.split('.')
            if len(parts) != 4:
                logger.error('Invalid whitelist format: %s', whitelist)
                return
            
            for i in range(4):
                if parts[i] == '*':
                    self.whitelist_end |= (0xFF << (i * 8))
                else:
                    val = int(parts[i])
                    if val > 0xFF:
                        logger.error('Invalid IP component: %s', parts[i])
                        return
                    self.whitelist_start |= (val << (i * 8))
                    self.whitelist_end |= (val << (i * 8))
            
            #logger.info('Whitelist: %08X-%08X', self.whitelist_start, self.whitelist_end)
        except Exception as e:
            logger.error('Error parsing whitelist: %s', e)
    
    def is_ip_allowed(self, ip_addr: str) -> bool:
        """Check if IP address is allowed by whitelist"""
        if not self.whitelist_start:
            return True
        
        try:
            # Convert IP to integer
            ip_parts = ip_addr.split('.')
            ip_int = 0
            for i, part in enumerate(ip_parts):
                ip_int |= (int(part) << (i * 8))
            
            return self.whitelist_start <= ip_int <= self.whitelist_end
        except Exception:
            return False
    
    def cleanup_finished_clients(self):
        """Remove finished client threads"""
        self.active_clients = [client for client in self.active_clients if client.is_alive()]
    
    def _cleanup_persistent_connections(self):
        """Thread para limpeza periódica de conexões persistentes antigas"""
        while True:
            try:
                time.sleep(60)  # Limpar a cada minuto
                if self.gdrive_manager.direct_manager:
                    self.gdrive_manager.direct_manager.cleanup_old_connections()
            except Exception as e:
                logger.error('Error in connection cleanup thread: %s', e)
    
    def run(self):
        #logger.info('Starting server...')
        
        if not self.gdrive_manager.service:
            logger.error('Google Drive service not available')
            sys.exit(1)
        
        #logger.info('Google Drive service is available, starting socket server...')
        
        # Iniciar thread de limpeza para modo direto
        if self.direct_mode and self.gdrive_manager.direct_manager:
            cleanup_thread = threading.Thread(
                target=self._cleanup_persistent_connections,
                daemon=True,
                name="ConnectionCleanup"
            )
            cleanup_thread.start()
            #logger.info('Started persistent connection cleanup thread')
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', self.port))
        s.listen(5)
        print('SERVIDOR PRONTO')

        try:
            while True:
                conn, addr = s.accept()
                
                # Check whitelist
                if not self.is_ip_allowed(addr[0]):
                    logger.warning('Rejected connection from %s (not in whitelist)', addr[0])
                    conn.close()
                    continue
                
                # Check client limit
                self.cleanup_finished_clients()
                if len(self.active_clients) >= self.max_clients:
                    logger.warning('Too many connections! (rejected client: %s)', addr[0])
                    conn.close()
                    continue
                
                #logger.info('Accepted connection from %s:%d', addr[0], addr[1])
                handler = ClientHandler(conn, addr, self.gdrive_manager, self.direct_mode)
                handler.start()
                self.active_clients.append(handler)
        finally:
            s.close()
            # Fechar todas as conexões persistentes ao sair
            if self.direct_mode and self.gdrive_manager.direct_manager:
                self.gdrive_manager.direct_manager.close_all_connections()

def run_server(port: int = NETISO_PORT, whitelist: str = None, direct_mode: bool = False):
    #logger.info('Initializing server with port=%d, whitelist=%s, direct_mode=%s', port, whitelist, direct_mode)
    server = ServerManager(port, whitelist, direct_mode)
    #logger.info('Server initialized, starting run()...')
    server.run()


if __name__ == '__main__':
    print('SERVIDOR INICIADO')
    
    # CLI: main.py [port] [whitelist] [--direct]
    port = NETISO_PORT
    whitelist = None
    direct_mode = False
    
    # Parse arguments
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == '--direct':
            direct_mode = True
        elif i == 0 and not arg.startswith('--'):
            try:
                port = int(arg)
        except Exception:
            pass
        elif i == 1 and not arg.startswith('--'):
            whitelist = arg
    
    if direct_mode:
        print('MODO DIRETO ATIVADO - Sem cache local, conexão direta com Google Drive')
    else:
        print('MODO CACHE ATIVADO - Com cache local e download em background')
    
    try:
        run_server(port, whitelist, direct_mode)
    except KeyboardInterrupt:
        #logger.info('Server stopped by user')
    except Exception as e:
        logger.error('Server error: %s', e)
        raise