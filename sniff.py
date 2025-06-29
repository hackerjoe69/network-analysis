from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from colorama import Fore, Style
import matplotlib
import matplotlib.pyplot as plt
matplotlib.use("TkAgg")
import requests
import threading
import time
import re

# Configurations
INTERFACE = "wlan0"          # default interface
PCAP_FILE = "capture.pcap"  # store all packets
LOG_FILE = "packet_log.txt"
ABUSEIPDB_KEY = "your ABUSEIPDB api key here"  # get a free key

# Threat & stats
suspicious_ports = {4444, 6666, 31337, 1337}
packet_counts = {"TCP":0, "UDP":0, "ICMP":0, "OTHER":0}
lock = threading.Lock()
captured_pkts = []

def log_packet(info):
    with open(LOG_FILE, "a") as f:
        f.write(f"{info}\n")

def analyze_payload(payload):
    if not payload:
        return ""
    s = payload.decode(errors="ignore")
    creds = re.findall(r"(username|user|login|password|pass)=\w+", s, re.IGNORECASE)
    if creds:
        print(Fore.RED + "[!] Credential Leak: " + ", ".join(creds) + Style.RESET_ALL)
    return s

def check_abuseip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    headers = { "Key": ABUSEIPDB_KEY, "Accept": "application/json" }
    try:
        r = requests.get(url, headers=headers, params=params, timeout=3)
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        if score > 50:
            print(Fore.RED + f"[!] IP {ip} flagged by AbuseIPDB: score={score}" + Style.RESET_ALL)
            log_packet(f"AbuseIPDB threat: {ip} score={score}")
    except Exception as e:
        print(Fore.YELLOW + f"[!] Threat check failed for {ip}: {e}" + Style.RESET_ALL)

def detect_threat(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        if TCP in pkt:
            ports = (pkt[TCP].sport, pkt[TCP].dport)
            if set(ports) & suspicious_ports:
                print(Fore.YELLOW + f"[!] Suspicious port used: {ports}" + Style.RESET_ALL)
                log_packet(f"Suspicious port {ports} from {ip_src}")

        if pkt[IP].src not in seen_ips:
            seen_ips.add(pkt[IP].src)
            threading.Thread(target=check_abuseip, args=(pkt[IP].src,), daemon=True).start()

def parse_packet(pkt):
    global captured_pkts
    proto = "OTHER"
    if IP in pkt:
        if TCP in pkt: proto = "TCP"
        elif UDP in pkt: proto = "UDP"
        elif ICMP in pkt: proto = "ICMP"
    
    with lock:
        packet_counts[proto] = packet_counts.get(proto,0) + 1
        captured_pkts.append(pkt)

    # Extract details
    ip_layer = pkt[IP] if IP in pkt else None
    payload = pkt[Raw].load if Raw in pkt else None
    parsed_payload = analyze_payload(payload)
    detect_threat(pkt)

    info = f"{proto}: {ip_layer.src if ip_layer else 'N/A'} -> {ip_layer.dst if ip_layer else 'N/A'} | {parsed_payload[:50]}"
    print(info)
    log_packet(info)

def save_pcap():
    while True:
        time.sleep(30)
        with lock:
            if captured_pkts:
                wrpcap(PCAP_FILE, captured_pkts)
                captured_pkts.clear()
                print(Fore.CYAN + "[*] PCAP file updated." + Style.RESET_ALL)

def plot_stats():
    plt.ion()
    fig, ax = plt.subplots()
    protocols = list(packet_counts.keys())
    while True:
        time.sleep(5)
        with lock:
            counts = [packet_counts.get(p,0) for p in protocols]
        ax.clear()
        ax.bar(protocols, counts, color=['blue','green','orange','gray'])
        ax.set_ylabel("Packet Count")
        ax.set_title("Live Network Protocol Distribution")
        plt.draw()
        plt.pause(0.01)

if __name__ == "__main__":
    if ABUSEIPDB_KEY == "YOUR_ABUSEIPDB_API_KEY":
        print(Fore.YELLOW + "[!] Set your AbuseIPDB API key to enable threat checks." + Style.RESET_ALL)

    seen_ips = set()
    iface = input(f"Interface [{INTERFACE}]: ") or INTERFACE

    threading.Thread(target=save_pcap, daemon=True).start()
    threading.Thread(target=plot_stats, daemon=True).start()

    print(Fore.GREEN + f"[*] Sniffing on {iface}, saving to {PCAP_FILE}, logging to {LOG_FILE}" + Style.RESET_ALL)
    sniff(iface=iface, prn=parse_packet, store=False)
