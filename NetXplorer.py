import argparse
import csv
import json
import netifaces
import ipaddress
import requests
import threading
from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table

console = Console()

def list_network_interfaces():
    """Lists all active network interfaces."""
    interfaces = netifaces.interfaces()
    valid_interfaces = []

    console.print("\n[bold cyan]Available Network Interfaces:[/bold cyan]")
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info.get("addr", "Unknown")
            netmask = ip_info.get("netmask", "Unknown")

            if not ip.startswith("127."):  # Ignore loopback
                valid_interfaces.append((iface, ip, netmask))

    if not valid_interfaces:
        console.print("[!] No active network interfaces found.", style="bold red")
        return None

    for i, (iface, ip, netmask) in enumerate(valid_interfaces):
        console.print(f"[{i}] {iface} - IP: {ip} - Netmask: {netmask}")

    return valid_interfaces

def get_network_from_interface(iface, ip, netmask):
    """Gets the network subnet from the selected interface."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except ValueError:
        return None

def get_mac_vendor(mac_address):
    """Gets the vendor name for a given MAC address using an online API."""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown"

def scan_ip(ip, results):
    """Scans a single IP address using ARP."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    for _, received in answered:
        vendor = get_mac_vendor(received.hwsrc)
        results.append({"IP Address": received.psrc, "MAC Address": received.hwsrc, "Vendor": vendor})

def scan_network(network):
    """Scans the entire subnet using multithreading."""
    console.print(f"[*] Scanning network: {network}", style="bold green")

    network_obj = ipaddress.IPv4Network(network, strict=False)
    results = []
    threads = []

    for ip in network_obj.hosts():
        thread = threading.Thread(target=scan_ip, args=(str(ip), results))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
    return results

def save_results(devices, filename="scan_results"):
    """Saves scan results to CSV and JSON files."""
    csv_filename = f"{filename}.csv"
    json_filename = f"{filename}.json"

    with open(csv_filename, "w", newline="") as csvfile:
        fieldnames = ["IP Address", "MAC Address", "Vendor"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(devices)  # ✅ FIXED: Matches field names correctly

    with open(json_filename, "w") as jsonfile:
        json.dump(devices, jsonfile, indent=4)

    console.print(f"[*] Results saved to {csv_filename} and {json_filename}", style="bold cyan")

def display_results(devices):
    """Displays the scan results in a table."""
    table = Table(title="Network Scan Results")
    table.add_column("IP Address", justify="left", style="cyan", no_wrap=True)
    table.add_column("MAC Address", justify="left", style="magenta")
    table.add_column("Vendor", justify="left", style="yellow")

    for device in devices:
        table.add_row(device["IP Address"], device["MAC Address"], device["Vendor"])
    
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Discovery Tool")
    parser.add_argument("-t", "--target", help="Target subnet (e.g., 192.168.1.0/24)", default=None)
    args = parser.parse_args()

    if not args.target:
        interfaces = list_network_interfaces()
        if not interfaces:
            return

        while True:
            try:
                choice = int(input("\nEnter the number of the interface you want to scan: "))
                if 0 <= choice < len(interfaces):
                    selected_iface, ip, netmask = interfaces[choice]
                    break
                else:
                    console.print("[!] Invalid selection. Try again.", style="bold red")
            except ValueError:
                console.print("[!] Please enter a valid number.", style="bold red")

        network = get_network_from_interface(selected_iface, ip, netmask)
        if not network:
            console.print("[!] Could not determine the network for the selected interface.", style="bold red")
            return
    else:
        network = args.target

    devices = scan_network(network)

    if devices:
        display_results(devices)
        save_results(devices)
    else:
        console.print("[!] No active devices found.", style="bold red")

if __name__ == "__main__":
    main()
