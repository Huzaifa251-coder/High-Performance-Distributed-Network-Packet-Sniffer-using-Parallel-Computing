from flask import Flask, render_template, jsonify, request, send_file
import threading
import multiprocessing
from collections import deque, Counter
import datetime
import csv
import json
import socket
import math
import re
import subprocess
import sys
import time
import os
from collections import Counter

# Flask app initialization
app = Flask(__name__)

# Global variables for UI (Consumer Thread updates these)
captured_packets = []
packet_stats = Counter()
alerts = []
filter_settings = {"protocol": "", "src_ip": "", "dst_ip": ""}

# Thread/Process control
server_thread = None
collector_thread = None
server_running = False
packet_queue = multiprocessing.Queue(maxsize=1000) # Backpressure: Limit queue size
result_queue = multiprocessing.Queue()
STOP_EVENT = threading.Event() # Clean Shutdown Control

# Log file path
LOG_FILE = "captured_packets_log.csv"
REPORT_FILE = "packet_report.csv"
PERFORMANCE_LOG_FILE = "performance_log.csv"

import argparse

# --- CONFIGURATION & GLOBAL STATE ---
CONFIG = {
    "THRESHOLD_PACKET_SIZE": 1500,
    "SUSPICIOUS_IPS": ["192.168.1.3", "10.0.0.200"],
    "SERVER_PORT": 9999,
    "MODE": "PARALLEL", # Default
    "WORKERS": multiprocessing.cpu_count(),
    "START_TIME": 0
}

perf_stats = {
    "total_packets": 0,
    "total_latency": 0.0,
    "start_time": 0
}

def parse_arguments():
    global CONFIG
    parser = argparse.ArgumentParser(description="PDC Network Packet Analyser")
    parser.add_argument("--mode", choices=["PARALLEL", "SEQUENTIAL"], default="PARALLEL", help="Execution Mode")
    parser.add_argument("--workers", type=int, default=multiprocessing.cpu_count(), help="Number of Worker Processes (Parallel Mode only)")
    parser.add_argument("--port", type=int, default=9999, help="Analysis Server Port")
    
    args = parser.parse_args()
    CONFIG["MODE"] = args.mode
    CONFIG["WORKERS"] = args.workers
    CONFIG["SERVER_PORT"] = args.port
    
    print(f"[*] Configuration Loaded: Mode={CONFIG['MODE']}, Workers={CONFIG['WORKERS']}, Port={CONFIG['SERVER_PORT']}")

# --- CORE ANALYSIS LOGIC (CPU INTENSIVE) ---
def calculate_entropy(data):
    """Calculates the Shannon entropy of the data."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def perform_analysis(packet_data):
    """Performs the CPU heavy DPI tasks."""
    start_ts = time.time()
    
    # Deep Packet Inspection (DPI)
    payload = packet_data.get("payload", "")
    entropy = calculate_entropy(payload)
    
    # PII Detection (Parallel Task)
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    pii_found = "No"
    if email_pattern.search(payload):
        pii_found = "Email Detected"

    # Threat Detection (Parallel Task)
    threat_alert = None
    if len(payload) > CONFIG["THRESHOLD_PACKET_SIZE"]:
        threat_alert = f"Large Payload: {len(payload)} bytes"
    elif entropy > 7.5: # Encrypted or Compressed
        threat_alert = "High Entropy (Potential Encryption/Malware)"
        
    # Enrich packet data
    packet_data["entropy"] = round(entropy, 2)
    packet_data["pii_status"] = pii_found
    if threat_alert:
        packet_data["alert"] = threat_alert
        
    end_ts = time.time()
    packet_data["latency"] = (end_ts - start_ts) * 1000 # Latency in ms
    
    return packet_data

# --- PDC WORKER PROCESS ---
def analyze_packet_worker(input_queue, output_queue):
    """Worker process that consumes packets and performs DPI."""
    while True:
        try:
            task_data = input_queue.get()
            if task_data == "STOP":
                break
            
            # Handle Batch or Single
            packets = task_data if isinstance(task_data, list) else [task_data]
            
            for packet_data in packets:
                result = perform_analysis(packet_data)
                output_queue.put(result)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Worker Error: {e}")

# --- SERVER THREAD (Distributed Ingestion) ---
def start_socket_server():
    global server_running
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", CONFIG["SERVER_PORT"]))
    server_socket.listen(5)
    server_running = True
    print(f"[*] Analysis Node Listening on Port {CONFIG['SERVER_PORT']}")
    
    while server_running:
        try:
            server_socket.settimeout(1.0)
            client_sock, addr = server_socket.accept()
            
            buffer = ""
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                buffer += data.decode('utf-8', errors='ignore')
                
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    if not message.strip():
                        continue
                        
                    try:
                        pkt = json.loads(message)
                        
                        # --- PDC CORE LOGIC: MODE SELECTION ---
                        # Handle Batching (List of packets) or Single Packet
                        packets_to_process = pkt if isinstance(pkt, list) else [pkt]
                        
                        # print(f"[debug] App received batch of {len(packets_to_process)}") # Uncomment for verbose debug
                        
                        if CONFIG["MODE"] == "PARALLEL":
                            # Non-Blocking: Push to Queue for Workers (True PDC)
                            try:
                                # We can push the whole batch to reduce queue contention
                                packet_queue.put(packets_to_process, block=False)
                            except multiprocessing.queues.Full:
                                print(f"[!] Queue Full! Dropping batch of {len(packets_to_process)}")
                        else:
                            # SEQUENTIAL BASELINE: Process inline (Blocking)
                            # This halts the listener thread until analysis is done
                            for p in packets_to_process:
                                res = perform_analysis(p)
                                result_queue.put(res)
                            
                    except json.JSONDecodeError as e:
                        print(f"Socket JSON Error: {e}")
                    except Exception as e:
                        print(f"Socket Msg Error: {e}")

            client_sock.close()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Server Error: {e}")

# --- RESULT COLLECTOR THREAD ---
def result_collector():
    global captured_packets, packet_stats, alerts
    
    
    # Initialize Performance Logging (Append Mode to preserve history)
    file_exists = os.path.isfile(PERFORMANCE_LOG_FILE)
    with open(PERFORMANCE_LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "PPS", "Avg_Latency_ms", "Mode", "Workers"])
        
    # Stateful IDS Tracking
    packet_window = deque() # Stores (timestamp, src_ip)
    alert_history = {} # Stores {src_ip: last_alert_time}
    FLOOD_THRESHOLD = 50 # Packets per 10 seconds
    ALERT_COOLDOWN = 5 # Seconds between identical alerts
    
    perf_stats["start_time"] = time.time()
    packets_this_second = 0
    last_tick = time.time()

    print("[*] Result Collector Thread Started")
    while not STOP_EVENT.is_set():
        try:
            result = result_queue.get(timeout=0.1) # Faster polling
            # print(f"[debug] Collector got result: {result.get('src')}")
            
            # --- ADVANCED IDS: TIME-WINDOW ANALYSIS ---
            current_time = time.time()
            src_ip = result.get("src")
            
            if src_ip and src_ip != "N/A":
                # window_counts tracks counts for IPs currently in packet_window for O(1) access
                if 'window_counts' not in locals():
                    window_counts = Counter()

                # 1. Add to sliding window & update counts
                packet_window.append((current_time, src_ip))
                window_counts[src_ip] += 1
                
                # 2. Prune old packets (> 10s) & update counts
                while packet_window and packet_window[0][0] < current_time - 10:
                    old_ts, old_ip = packet_window.popleft()
                    window_counts[old_ip] -= 1
                    if window_counts[old_ip] <= 0:
                        del window_counts[old_ip]
                    
                # 3. Authentic DoS Detection (Statistical Anomaly + Minimum Floor)
                # "Authentic" means distinguishing normal high load from attacks.
                
                # A. Minimum Traffic Floor (e.g., 100 pkts/10s = 10 PPS) 
                # Normal web browsing can easily hit 50-80 pkts/10s. We raise this.
                MIN_DOS_FLOOR = 100 
                HARD_LIMIT_SINGLE_USER = 300 # If only 1 user, limit is higher
                
                count = window_counts[src_ip]
                
                is_anomaly = False
                
                if count > MIN_DOS_FLOOR:
                    # Calculate Stats for Context
                    active_counts = list(window_counts.values())
                    n = len(active_counts)
                    
                    if n > 2:
                        # Statistical Mode: Calculate Z-Score
                        mean = sum(active_counts) / n
                        variance = sum((x - mean) ** 2 for x in active_counts) / n
                        std_dev = math.sqrt(variance)
                        
                        # Threshold: 3 Sigma (99.7% confidence it's an outlier)
                        if std_dev > 0 and count > (mean + 3 * std_dev):
                            is_anomaly = True
                    else:
                        # Fallback Mode (Not enough data for stats): Pure Volumetric
                        if count > HARD_LIMIT_SINGLE_USER:
                            is_anomaly = True

                if is_anomaly:
                    # 4. False Positive Reduction (De-duplication)
                    last_alert = alert_history.get(src_ip, 0)
                    if current_time - last_alert > ALERT_COOLDOWN:
                        flood_alert = f"DoS Alert (Anomaly): {count} pkts/10s (Z-Score flagged)"
                        result["alert"] = flood_alert # Inject alert into result
                        alert_history[src_ip] = current_time

            # --- METRICS COLLECTION ---
            perf_stats["total_packets"] += 1
            perf_stats["total_latency"] += result.get("latency", 0)
            packets_this_second += 1
            
            # Periodic Metric Logging (every 1 second)
            current_time = time.time()
            if current_time - last_tick >= 1.0:
                pps = packets_this_second / (current_time - last_tick)
                avg_lat = perf_stats["total_latency"] / perf_stats["total_packets"] if perf_stats["total_packets"] else 0
                
                
                # Update Global Real-Time Metrics for API
                active_workers = 1 if CONFIG["MODE"] == "SEQUENTIAL" else CONFIG["WORKERS"]
                
                perf_stats["current_pps"] = round(pps, 2)
                perf_stats["avg_latency"] = round(avg_lat, 4)
                perf_stats["mode"] = CONFIG["MODE"]
                perf_stats["workers"] = active_workers

                with open(PERFORMANCE_LOG_FILE, mode="a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.datetime.now().strftime('%H:%M:%S'),
                        f"{pps:.2f}",
                        f"{avg_lat:.4f}",
                        CONFIG["MODE"],
                        active_workers
                    ])
                
                packets_this_second = 0
                last_tick = current_time

            timestamp = datetime.datetime.fromtimestamp(result["time"]).strftime('%Y-%m-%d %H:%M:%S')
            
            packet_display = {
                "Timestamp": timestamp,
                "Source IP": result.get("src", "N/A"),
                "Destination IP": result.get("dst", "N/A"),
                "Protocol": result.get("proto_name", "Unknown"),
                "Details": f"{result.get('pii_status')} | Ent: {result.get('entropy')} | Lat: {result.get('latency', 0):.2f}ms",
                "Alert": result.get("alert", "")
            }
            
            if filter_settings["protocol"] and packet_display["Protocol"].lower() != filter_settings["protocol"].lower():
                continue
            if filter_settings["src_ip"] and packet_display["Source IP"] != filter_settings["src_ip"]:
                continue
            
            captured_packets.append(packet_display)
            packet_stats[packet_display["Protocol"]] += 1
            
            if result.get("alert"):
                alerts.append(f"{timestamp}: {result['alert']} from {result.get('src')}")
                
            with open(LOG_FILE, mode="a", newline="") as log_file:
                writer = csv.DictWriter(log_file, fieldnames=packet_display.keys())
                if log_file.tell() == 0:
                    writer.writeheader()
                writer.writerow(packet_display)
                
        except multiprocessing.queues.Empty:
            continue
        except Exception as e:
            print(f"[!] Collector Critical Error: {e}") # Reveal the bug!



# Flask Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/dashboard', methods=['GET'])
def dashboard_data():
    # print(f"[debug] Serving {len(captured_packets)} packets to dashboard")
    return jsonify({
        "packets": captured_packets[-50:],
        "stats": dict(packet_stats),
        "alerts": alerts[-10:],
        "performance": perf_stats
    })

@app.route('/api/filters', methods=['POST'])
def set_filters():
    global filter_settings
    filter_settings["protocol"] = request.json.get("protocol", "").strip()
    filter_settings["src_ip"] = request.json.get("src_ip", "").strip()
    filter_settings["dst_ip"] = request.json.get("dst_ip", "").strip()
    return jsonify({"message": "Filters updated", "filters": filter_settings})

@app.route('/api/sniffing/start', methods=['POST'])
def api_start_sniffing():
    # In Distributed mode, "Start" means "Prepare to Receive"
    # The Sniffer Node must be started manually or we can trigger it if we had a control channel.
    # For this assignment, we assume the server is always "Listening" once the app starts? 
    # Or we can toggle the Listener.
    global server_thread
    if server_thread is None or not server_thread.is_alive():
        server_thread = threading.Thread(target=start_socket_server)
        server_thread.daemon = True
        server_thread.start()
    return jsonify({"message": "Analysis Server Listening for Packets..."})

@app.route('/api/sniffing/stop', methods=['POST'])
def api_stop_sniffing():
    global server_running
    server_running = False
    return jsonify({"message": "Analysis Server Stopped."})

@app.route('/api/report', methods=['GET'])
def download_report():
    return send_file(LOG_FILE, as_attachment=True) # Send the log file directly

def main():
    parse_arguments()
    
    # Start Worker Pool (Only if Parallel)
    workers = []
    if CONFIG["MODE"] == "PARALLEL":
        print(f"[*] Starting {CONFIG['WORKERS']} Worker Processes for DPI...")
        for _ in range(CONFIG["WORKERS"]):
            p = multiprocessing.Process(target=analyze_packet_worker, args=(packet_queue, result_queue))
            p.start()
            workers.append(p)
    else:
        print("[*] Running in SEQUENTIAL Mode (Single-Threaded)")
        
    # Start Result Collector Thread
    global collector_thread
    collector_thread = threading.Thread(target=result_collector)
    collector_thread.daemon = True
    collector_thread.start()



    # Start Socket Server (Analysis Node Listener)
    # Auto-start this so the sniffer can connect immediately
    global server_thread
    print("[*] Starting Analysis Server (Socket Listener)...")
    server_thread = threading.Thread(target=start_socket_server)
    server_thread.daemon = True
    server_thread.start()

    # Auto-launch Sniffer Node (Distributed Component)
    print("[*] Auto-launching Sniffer Node (Distributed Component)...")
    sniffer_process = None
    try:
        # Launch sniffer_node.py using the same python interpreter
        sniffer_process = subprocess.Popen([sys.executable, "sniffer_node.py"])
    except Exception as e:
        print(f"[!] Failed to launch sniffer node: {e}")

    print("Starting Flask server...")
    try:
        app.run(debug=True, port=5000, use_reloader=False) # use_reloader=False to avoid dup processes
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
    finally:
        print("Shutting down...")
        
        # Signal Threads to Stop
        server_running = False
        STOP_EVENT.set()
        if collector_thread and collector_thread.is_alive():
            collector_thread.join(timeout=2.0)
            
        # Terminate Sniffer Node
        if sniffer_process:
            print("[*] Terminating Sniffer Node...")
            sniffer_process.terminate()
            sniffer_process.wait()
            
        if CONFIG["MODE"] == "PARALLEL":
            for _ in range(CONFIG["WORKERS"]):
                packet_queue.put("STOP")
            for p in workers:
                p.join()

if __name__ == "__main__":
    main()
