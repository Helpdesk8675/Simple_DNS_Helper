# Note: To use this functionality, you'll need to download the GeoLite2-City database from MaxMind's website.
# You'll need to create a free account and place the database file in the same directory as your script.


import datetime
import io
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import importlib.util
import sys
import subprocess
import threading
import logging
import ipaddress
import re
import dns.resolver
import dns.exception
import dns.query
import dns.zone
import dns.reversename
import whois
from tabulate import tabulate
import idna

# Configure logging
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def check_and_install_packages():
    # Add to the required_packages dictionary in check_and_install_packages()
    required_packages = {
        'dns': 'dnspython',
        'whois': 'python-whois',
        'tabulate': 'tabulate',
        'idna': 'idna',
        'geoip2': 'geoip2'
    }

    missing_packages = []

    for import_name, package_name in required_packages.items():
        if importlib.util.find_spec(import_name) is None:
            missing_packages.append(package_name)

    if missing_packages:
        print("Missing required packages:", ", ".join(missing_packages))
        install = input("Would you like to install them now? (y/n): ").lower()

        if install == 'y':
            try:
                for package in missing_packages:
                    print(f"Installing {package}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print("All required packages installed successfully!")
                print("Please restart the script.")
                sys.exit(0)
            except subprocess.CalledProcessError as e:
                print(f"Error installing packages: {e}")
                sys.exit(1)
        else:
            print("Required packages must be installed to run this script.")
            sys.exit(1)

def is_valid_domain(domain):
    """
    Validate the given domain name using IDNA encoding and a basic regex.
    """
    try:
        domain = idna.encode(domain).decode("utf-8")
        domain_regex = re.compile(
            r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$"
        )
        return bool(domain_regex.match(domain))
    except idna.IDNAError:
        return False

def is_valid_ip(ip_address):
    """
    Validate the given IP address using the ipaddress module.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def print_table(data, headers):
    """
    Print a table using the provided data and headers.
    """
    if data:
        print(tabulate(data, headers=headers, tablefmt="pretty"))
    else:
        print("No data available.")

def dns_lookup(domain):
    """
    Perform a DNS A record lookup.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'A')
        data = [(rdata.address,) for rdata in answers]
        print_table(data, ["IP Address"])
    except dns.resolver.NoAnswer:
        print(f"No A records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during A record lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during A record lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def mx_lookup(domain):
    """
    Perform an MX record DNS lookup.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        data = [(rdata.preference, rdata.exchange.to_text()) for rdata in answers]
        data.sort()
        print_table(data, ["Preference", "Mail Server"])
    except dns.resolver.NoAnswer:
        print(f"No MX records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during MX lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during MX lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def ns_lookup(domain):
    """
    Perform an NS record DNS lookup.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        data = [(rdata.target.to_text(),) for rdata in answers]
        print_table(data, ["Name Server"])
    except dns.resolver.NoAnswer:
        print(f"No NS records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during NS lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during NS lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def soa_lookup(domain):
    """
    Perform an SOA record DNS lookup.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        data = [
            (rdata.mname.to_text(), rdata.rname.to_text(), rdata.serial,
             rdata.refresh, rdata.retry, rdata.expire, rdata.minimum)
            for rdata in answers
        ]
        headers = ["Primary Name Server", "Responsible Person", "Serial Number",
                   "Refresh Interval", "Retry Interval", "Expire Limit", "Minimum TTL"]
        print_table(data, headers)
    except dns.resolver.NoAnswer:
        print(f"No SOA records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during SOA lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during SOA lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def reverse_lookup(ip_address):
    """
    Perform a reverse DNS lookup on the specified IP address.
    """
    if not is_valid_ip(ip_address):
        print(f"Invalid IP address: {ip_address}")
        return
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        data = [(rdata.target.to_text(),) for rdata in answers]
        print_table(data, ["Domain Name"])
    except dns.resolver.NoAnswer:
        print(f"No PTR records found for {ip_address}.")
    except dns.resolver.NXDOMAIN:
        print(f"No reverse DNS record exists for {ip_address}.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during reverse lookup for {ip_address}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during reverse lookup for {ip_address}: {e}")
        print("An unexpected error occurred.")

def whois_lookup(domain):
    """
    Perform a WHOIS lookup for the specified domain.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        w = whois.whois(domain)
        data = [
            ("Domain Name", w.get('domain_name')),
            ("Registrar", w.get('registrar')),
            ("Creation Date", w.get('creation_date')),
            ("Expiration Date", w.get('expiration_date')),
            ("Name Servers", w.get('name_servers'))
        ]
        data = [(key, value) for key, value in data if value is not None]
        print_table(data, ["Field", "Value"])
    except Exception as e:
        logging.error(f"WHOIS lookup error for {domain}: {e}")
        print("WHOIS lookup error occurred.")

def get_all_information(domain):
    """
    Retrieve and display comprehensive DNS and WHOIS information about the domain.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    print(f"Getting all information for domain: {domain}")
    print("-" * 30)

    # DNS A Lookup
    print("DNS Lookup:")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [rdata.address for rdata in answers]
        print_table([(ip,) for ip in ip_addresses], ["IP Address"])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        ip_addresses = []
        print(f"No A records found for {domain}.")
    except dns.exception.DNSException as e:
        ip_addresses = []
        logging.error(f"DNS error during get_all_information (A records) for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        ip_addresses = []
        logging.error(f"Unexpected error during get_all_information (A records) for {domain}: {e}")
        print("An unexpected error occurred.")

    print("\nMX Lookup:")
    mx_lookup(domain)

    print("\nNS Lookup:")
    ns_lookup(domain)

    print("\nSOA Lookup:")
    soa_lookup(domain)

    # Reverse DNS Lookup (if we have at least one IP)
    if ip_addresses:
        print("\nReverse DNS Lookup (first IP):")
        reverse_lookup(ip_addresses[0])
    else:
        print("\nNo IP addresses available for reverse lookup.")

    print("\nWHOIS Lookup:")
    whois_lookup(domain)

def zone_transfer(domain):
    """
    Attempt a DNS zone transfer from the domain's name servers.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        # Try each name server for a zone transfer until one succeeds or all fail
        for ns_record in ns_records:
            ns_server = str(ns_record.target).rstrip('.')
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=5))
                if zone:
                    print(f"Zone transfer results for domain: {domain}")
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            print(zone.origin.to_text(), name.to_text(), rdataset.to_text())
                    return
            except dns.exception.DNSException as e:
                logging.info(f"Zone transfer failed at {ns_server} for {domain}: {e}")
        print("Zone transfer did not succeed with any name server.")
    except dns.resolver.NoAnswer:
        print(f"No NS records found for {domain}, cannot attempt zone transfer.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during zone transfer for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during zone transfer for {domain}: {e}")
        print("An unexpected error occurred.")

def geoip_lookup(ip_address):
    if not is_valid_ip(ip_address):
        print(f"Invalid IP address: {ip_address}")
        return
    
    try:
        import geoip2.database
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip_address)
        
        data = [
            ("Country", response.country.name),
            ("City", response.city.name),
            ("Latitude", response.location.latitude),
            ("Longitude", response.location.longitude),
            ("Time Zone", response.location.time_zone)
        ]
        print_table(data, ["Field", "Value"])
        reader.close()
    except FileNotFoundError:
        print("GeoIP database file not found. Please download the GeoLite2-City database from MaxMind.")
    except Exception as e:
        logging.error(f"GeoIP lookup error for {ip_address}: {e}")
        print("Error during GeoIP lookup.")



class DNSToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Helper")
        self.root.geometry("800x600")

        # Output folder
        self.output_folder = tk.StringVar()

        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create and pack widgets
        self.create_widgets()

    def create_widgets(self):
        # Output folder selection
        ttk.Label(self.main_frame, text="Output Folder:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self.main_frame, textvariable=self.output_folder, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(self.main_frame, text="Browse", command=self.browse_folder).grid(row=0, column=2)

        # Domain/IP input
        ttk.Label(self.main_frame, text="Domain/IP:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.input_entry = ttk.Entry(self.main_frame, width=50)
        self.input_entry.grid(row=1, column=1, padx=5)

        # Output text area
        self.output_text = tk.Text(self.main_frame, height=20, width=80)
        self.output_text.grid(row=2, column=0, columnspan=3, pady=10)

        # Scrollbar for output
        scrollbar = ttk.Scrollbar(self.main_frame, orient='vertical', command=self.output_text.yview)
        scrollbar.grid(row=2, column=3, sticky=(tk.N, tk.S))
        self.output_text['yscrollcommand'] = scrollbar.set

        # Buttons frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)

        # DNS lookup buttons
        buttons = [
            ("DNS Lookup", self.run_dns_lookup),
            ("MX Lookup", self.run_mx_lookup),
            ("NS Lookup", self.run_ns_lookup),
            ("SOA Lookup", self.run_soa_lookup),
            ("Reverse Lookup", self.run_reverse_lookup),
            ("WHOIS Lookup", self.run_whois_lookup),
            ("All Information", self.run_get_all_information),
            ("Zone Transfer", self.run_zone_transfer),
            ("GeoLookup IP", self.run_geoip_lookup),
        ]

        for i, (text, command) in enumerate(buttons):
            ttk.Button(button_frame, text=text, command=command).grid(row=i // 4, column=i % 4, padx=5, pady=5)

        # Save button
        ttk.Button(self.main_frame, text="Save Output", command=self.save_output).grid(row=4, column=0, columnspan=3, pady=10)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.output_folder.set(folder)

    def save_output(self):
        if not self.output_folder.get():
            messagebox.showerror("Error", "Please select an output folder first!")
            return

        output = self.output_text.get("1.0", tk.END)
        if output.strip():
            filename = f"dns_lookup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join(self.output_folder.get(), filename)
            try:
                with open(filepath, 'w') as f:
                    f.write(output)
                messagebox.showinfo("Success", f"Output saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
        else:
            messagebox.showwarning("Warning", "No output to save!")

    def update_output(self, text):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)

    def run_command(self, command_func, *args):
        """
        Helper to run a command and display its output in the GUI.
        """
        def target():
            try:
                output = io.StringIO()
                sys.stdout = output
                command_func(*args)
                sys.stdout = sys.__stdout__
                self.update_output(output.getvalue())
            except Exception as e:
                logging.error(f"Error: {e}")
                self.update_output(f"An error occurred: {e}")
            finally:
                sys.stdout = sys.__stdout__

        # Run in a separate thread to prevent GUI freezing
        threading.Thread(target=target).start()

    # Command bindings
    def run_dns_lookup(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(dns_lookup, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")

    def run_mx_lookup(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(mx_lookup, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")

    def run_ns_lookup(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(ns_lookup, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")

    def run_soa_lookup(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(soa_lookup, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")

    def run_reverse_lookup(self):
        ip_address = self.input_entry.get().strip()
        if is_valid_ip(ip_address):
            self.run_command(reverse_lookup, ip_address)
        else:
            messagebox.showerror("Error", "Invalid IP address!")

    def run_whois_lookup(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(whois_lookup, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")

    def run_get_all_information(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(get_all_information, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")

    def run_zone_transfer(self):
        domain = self.input_entry.get().strip()
        if is_valid_domain(domain):
            self.run_command(zone_transfer, domain)
        else:
            messagebox.showerror("Error", "Invalid domain name!")
          
    def run_geoip_lookup(self):
        ip_address = self.input_entry.get().strip()
        if is_valid_ip(ip_address):
            self.run_command(geoip_lookup, ip_address)
        else:
            messagebox.showerror("Error", "Invalid IP address!")


def main():
    check_and_install_packages()
    root = tk.Tk()
    app = DNSToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
