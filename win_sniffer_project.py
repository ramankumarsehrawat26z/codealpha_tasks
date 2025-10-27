"""
win_sniffer_project.py

Windows-friendly network sniffer (scapy) with:
 - optional pcap saving
 - CSV logging
 - periodic "top talkers" (by source IP)
 - CLI arguments for interface, filter, and files

Run (Admin PowerShell):
python win_sniffer_project.py --iface "Ethernet" --pcap capture.pcap --csv log.csv --interval 10

Notes:
 - Must run as Administrator on Windows.
 - Use double quotes for interface names with spaces.
 - Use bpf filter like "tcp port 80" if you want.
"""

import argparse
import csv
import signal
import sys
import threading
import time
from collections import Counter, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

# -------------------------
# Configuration / Defaults
# -------------------------
DEFAULT_BPF = "ip"
DEFAULT_PCAP_FILENAME = "capture.pcap"
DEFAULT_CSV_FILENAME = "capture_log.csv"
DEFAULT_STATS_INTERVAL = 10  # seconds
MAX_PAYLOAD_DISPLAY = 200

# -------------------------
# Runtime state
# -------------------------
captured_packets_for_pcap = []  # store for optional pcap saving
csv_lock = threading.Lock()
pcap_lock = threading.Lock()
counters_lock = threading.Lock()

# Counters and recent history
protocol_counter = Counter()
top_src_counter = Counter()
packet_history = deque(maxlen=1000)  # keep summary of recent N packets

stop_sniff_event = threading.Event()

# -------------------------
# Helpers
# -------------------------
def safe_str_payload(payload_bytes):
    if not payload_bytes:
        return ""
    try:
        text = payload_bytes[:MAX_PAYLOAD_DISPLAY].decode("utf-8", errors="replace")
        return text.replace("\n", "\\n").replace("\r", "\\r")
    except Exception:
        return payload_bytes[:MAX_PAYLOAD_DISPLAY].hex()

def summarize_packet(pkt):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    src = dst = "-"
    sport = dport = ""
    proto = "OTHER"
    payload = b""

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto_layer = None
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto_layer = pkt[TCP]
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto_layer = pkt[UDP]
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = str(ip.proto)

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)

    payload_str = safe_str_payload(payload)
    return {
        "timestamp": ts,
        "proto": proto,
        "src": src,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "payload_len": len(payload),
        "payload": payload_str,
    }

# -------------------------
# Packet processing
# -------------------------
def packet_callback(pkt, csv_writer=None, save_pcap=False):
    summary = summarize_packet(pkt)

    # print a short line
    short_line = f"[{summary['timestamp']}] {summary['proto']:4} {summary['src']}:{summary['sport']} -> {summary['dst']}:{summary['dport']} len={summary['payload_len']}"
    print(short_line)

    # update counters
    with counters_lock:
        protocol_counter.update([summary["proto"]])
        if summary["src"]:
            top_src_counter.update([summary["src"]])
        # add to recent history
        packet_history.append(summary)

    # write to CSV (thread-safe)
    if csv_writer is not None:
        with csv_lock:
            try:
                csv_writer.writerow([
                    summary["timestamp"], summary["proto"],
                    summary["src"], summary["sport"],
                    summary["dst"], summary["dport"],
                    summary["payload_len"], summary["payload"]
                ])
            except Exception as e:
                # keep sniffer running even if CSV write fails
                print("CSV write error:", e)

    # store for pcap saving
    if save_pcap:
        with pcap_lock:
            captured_packets_for_pcap.append(pkt)

# -------------------------
# Periodic stats thread
# -------------------------
def stats_worker(interval):
    while not stop_sniff_event.wait(interval):
        with counters_lock:
            total_seen = sum(protocol_counter.values())
            top_protocols = protocol_counter.most_common(5)
            top_src = top_src_counter.most_common(10)

        print("\n=== STAT SNAPSHOT ===")
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"Total captured (by protocol counts sum): {total_seen}")
        print("Top protocols:")
        for proto, cnt in top_protocols:
            print(f"  {proto:6} : {cnt}")
        print("Top source IPs:")
        for ip, cnt in top_src:
            print(f"  {ip:15} : {cnt}")
        print("=====================\n")

# -------------------------
# Graceful shutdown
# -------------------------
def shutdown_and_save(args):
    print("\nShutting down sniffing...")

    # signal the stats thread to stop
    stop_sniff_event.set()

    # save pcap if requested
    if args.pcap and captured_packets_for_pcap:
        try:
            print(f"Saving {len(captured_packets_for_pcap)} packets to PCAP: {args.pcap}")
            wrpcap(args.pcap, captured_packets_for_pcap)
            print("PCAP saved.")
        except Exception as e:
            print("Failed to save pcap:", e)

    # close CSV is handled by context manager in main
    print("Shutdown complete. Goodbye.")

# -------------------------
# Main CLI and runner
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Windows network sniffer project (Scapy)")
    parser.add_argument("--iface", "-i", type=str, default=None, help="Interface name (Windows) or leave empty for default")
    parser.add_argument("--filter", "-f", type=str, default=DEFAULT_BPF, help='BPF filter string, e.g. "tcp port 80"')
    parser.add_argument("--pcap", type=str, default=None, help=f"Save captured packets to pcap file (optional). e.g. {DEFAULT_PCAP_FILENAME}")
    parser.add_argument("--csv", type=str, default=None, help=f"Log packet summaries to CSV (optional). e.g. {DEFAULT_CSV_FILENAME}")
    parser.add_argument("--interval", type=int, default=DEFAULT_STATS_INTERVAL, help="Statistics print interval seconds")
    args = parser.parse_args()

    # prepare CSV writer if requested
    csv_file = None
    csv_writer = None
    if args.csv:
        try:
            csv_file = open(args.csv, "a", newline="", encoding="utf-8")
            csv_writer = csv.writer(csv_file)
            # write header if file was empty
            if csv_file.tell() == 0:
                csv_writer.writerow(["timestamp","proto","src","sport","dst","dport","payload_len","payload_preview"])
        except Exception as e:
            print("Failed to open CSV file:", e)
            csv_file = None
            csv_writer = None

    # start stats thread
    stats_thread = threading.Thread(target=stats_worker, args=(args.interval,), daemon=True)
    stats_thread.start()

    # set up signal handlers for graceful shutdown
    def handle_sigint(sig, frame):
        shutdown_and_save(args)
        # close csv file gracefully
        if csv_file:
            csv_file.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    # Windows: SIGTERM may not be available in same way, SIGINT via Ctrl+C is main path.

    print("Starting sniffing (Press Ctrl+C to stop).")
    print(f"Interface: {args.iface or 'default'}, Filter: {args.filter}")
    print(f"Save PCAP: {bool(args.pcap)}, CSV log: {bool(args.csv)}, Stats interval: {args.interval}s")

    # sniff - pass packet_callback with partials to include csv_writer and pcap flag
    try:
        sniff(prn=lambda pkt: packet_callback(pkt, csv_writer=csv_writer, save_pcap=bool(args.pcap)),
              filter=args.filter, iface=args.iface, store=False)
    except PermissionError:
        print("PermissionError: Run PowerShell as Administrator and ensure Npcap is installed.")
    except Exception as e:
        print("Sniffer error:", e)
    finally:
        # ensure cleanup on exit
        if csv_file:
            csv_file.close()
        shutdown_and_save(args)

if __name__ == "__main__":
    main()
