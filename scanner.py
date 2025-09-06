import os
import socket
import subprocess
import json
import time
from threading import Thread
from queue import Queue
from colorama import Fore, init
from tqdm import tqdm
from prettytable import PrettyTable

init(autoreset=True)

BANNER = Fore.MAGENTA + r"""
  ██████╗  █████╗ ██████╗ ██╗  ██╗
  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝
  ██████╔╝███████║██████╔╝█████╔╝ 
  ██╔═══╝ ██╔══██║██╔═══╝ ██╔═██╗ 
  ██║     ██║  ██║██║     ██║  ██╗
  ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
     DARK SCANNER v4.0
      By Amit @ DARK
"""

def clear_screen():
    os.system("clear")

def print_banner():
    clear_screen()
    print(BANNER)
    print(Fore.CYAN + "Non-Rooted Recon Tool | Powered by DARK\n")


def ping_device(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "1 packets received" in result.stdout:
            ttl = None
            for line in result.stdout.splitlines():
                if "ttl=" in line:
                    ttl = int(line.split("ttl=")[1].split()[0])
            os_guess = "Linux/Unix" if ttl and ttl > 64 else "Windows" if ttl and ttl <= 64 else "Unknown"
            return {"ip": ip, "os_guess": os_guess, "timestamp": time.ctime()}
    except Exception:
        pass
    return None

def network_scan(base_ip):
    print(Fore.YELLOW + "[*] Scanning network for active devices...\n")
    devices = []
    for i in tqdm(range(1, 255), desc="Pinging"):
        ip = f"{base_ip}.{i}"
        device = ping_device(ip)
        if device:
            devices.append(device)
    return devices


def scan_port(ip, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex((ip, port)) == 0:
            results.append(port)
        sock.close()
    except:
        pass

def port_scan(ip, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 8080, 3389]
    
    print(Fore.YELLOW + f"[*] Starting port scan on {ip}...\n")
    threads = []
    results = []
    q = Queue()

    for port in ports:
        q.put(port)

    def worker():
        while not q.empty():
            p = q.get()
            scan_port(ip, p, results)
            q.task_done()

    for _ in range(30):  
        t = Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return sorted(results)


def save_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(Fore.GREEN + f"\n[+] Results saved to {filename}")

def save_html(devices, filename="dark_scan_report.html"):
    with open(filename, "w") as f:
        f.write("<html><head><title>Dark Scan Report</title></head><body>")
        f.write("<h1>Dark Scanner v4.0 Report</h1>")
        f.write("<table border='1'><tr><th>IP</th><th>OS Guess</th><th>Timestamp</th></tr>")
        for d in devices:
            f.write(f"<tr><td>{d['ip']}</td><td>{d['os_guess']}</td><td>{d['timestamp']}</td></tr>")
        f.write("</table></body></html>")
    print(Fore.GREEN + f"[+] HTML report saved to {filename}")

# --- UI ---
def main_menu():
    print_banner()
    print(Fore.CYAN + "[1] Network Scan (Non-root)")
    print(Fore.CYAN + "[2] Port Scan (Advanced)")
    print(Fore.CYAN + "[3] Exit\n")
    choice = input(Fore.WHITE + "Choose an option: ")

    if choice == "1":
        base_ip = input(Fore.WHITE + "Enter base IP (e.g., 192.168.1): ")
        devices = network_scan(base_ip)

        table = PrettyTable()
        table.field_names = ["IP Address", "OS Guess", "Timestamp"]
        for d in devices:
            table.add_row([d['ip'], d['os_guess'], d['timestamp']])
        
        print(Fore.GREEN + "\n[+] Active Devices Found:\n")
        print(table)

        save_json(devices, "dark_network_scan.json")
        save_html(devices)

    elif choice == "2":
        target_ip = input(Fore.WHITE + "Enter target IP: ")
        open_ports = port_scan(target_ip)

        if open_ports:
            print(Fore.GREEN + "\n[+] Open Ports Found:\n")
            for port in open_ports:
                print(Fore.CYAN + f"Port {port} - OPEN")
            save_json({"target_ip": target_ip, "open_ports": open_ports}, f"dark_ports_{target_ip}.json")
        else:
            print(Fore.RED + "\n[-] No open ports found.")

    elif choice == "3":
        print(Fore.MAGENTA + "\nExiting Dark Scanner. Stay in the shadows. 🌑")
        exit()
    else:
        print(Fore.RED + "\nInvalid choice! Try again.")
        time.sleep(1)
        main_menu()

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted. Exiting safely...")
