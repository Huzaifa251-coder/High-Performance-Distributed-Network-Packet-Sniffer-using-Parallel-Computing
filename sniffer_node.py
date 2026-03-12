import socket
import json
import time
import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
BATCH_SIZE = 10  # Send packets in batches to reduce socket overhead
BATCH_TIMEOUT = 0.2
packet_batch = []
last_batch_time = 0

def send_packet_to_server(packet_data):
    """Sends a simplified packet JSON object to the Analysis Server."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_IP, SERVER_PORT))
            s.sendall(json.dumps(packet_data).encode('utf-8') + b'\n')
    except ConnectionRefusedError:
        print(f"[!] Connection failed: Is the Analysis Server running on {SERVER_IP}:{SERVER_PORT}?")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

def process_packet(packet):
    global packet_batch, last_batch_time
    # print(f"[debug] Pkt: {packet.summary()}") # Debug print
    
    if IP in packet:
        packet_info = {
            "time": float(packet.time),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "len": len(packet),
            "payload": str(packet[IP].payload)
        }
        
        # Add protocol specific info
        if TCP in packet:
            packet_info["sport"] = packet[TCP].sport
            packet_info["dport"] = packet[TCP].dport
            packet_info["proto_name"] = "TCP"
        elif UDP in packet:
            packet_info["sport"] = packet[UDP].sport
            packet_info["dport"] = packet[UDP].dport
            packet_info["proto_name"] = "UDP"
        elif ICMP in packet:
            packet_info["proto_name"] = "ICMP"
        else:
            packet_info["proto_name"] = "Other"

        # --- BATCHING LOGIC ---
        packet_batch.append(packet_info)
        current_time = time.time()
        
        if len(packet_batch) >= BATCH_SIZE or (current_time - last_batch_time > BATCH_TIMEOUT):
            if packet_batch:
                send_packet_to_server(packet_batch)
                packet_batch = []
                last_batch_time = current_time

def main():
    global last_batch_time
    last_batch_time = time.time()
    print(f"[*] Starting Distributed Sniffer Node...")
    print(f"[*] Target Server: {SERVER_IP}:{SERVER_PORT}")
    print("[*] Waiting for packets...")
    
    # Sniff packets and process them
    # store=0 to avoid memory leak
    try:
        sniff(filter="ip", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping Sniffer Node.")

if __name__ == "__main__":
    main()
