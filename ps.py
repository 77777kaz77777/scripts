import os
import socket
import concurrent.futures
import logging
import csv
import nmap 
from datetime import datetime
import ipaddress

# Commonly used ports for quick scans
COMMON_PORTS = [80, 443, 22, 21, 25]

# Ports considered as security issues
SECURITY_PORTS = [23]  # Telnet port

# Set of reserved ports (adjust as needed)
RESERVED_PORTS = set(range(0, 1024))

# Function to scan a specific port on a target
def scan_port(target, port, filter_mode, allow_reserved_ports):
    try:
        if port in RESERVED_PORTS and not allow_reserved_ports:
            return port, "skipped (User skipped Reserved Ports)"

        with socket.create_connection((target, port), timeout=1) as sock:
            if port in SECURITY_PORTS:
                return port, "open (Security Issue - Telnet detected)"
            else:
                # Identify service and protocol for open ports
                service, protocol = identify_service(target, port)
                status = f"open ({service} service, {protocol} protocol)"
                if filter_mode == 'open' and 'open' not in status:
                    status = 'filtered'
                elif filter_mode == 'closed' and 'closed' not in status:
                    status = 'filtered'
                return port, status
    except ConnectionRefusedError:
        return port, "closed (Connection Refused)"
    except socket.timeout:
        return port, "closed (Timeout - Network Issue)"
    except Exception as e:
        return port, f"error: {e}"

# Function to identify the service running on a specific port
def identify_service(target, port):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, str(port))

        if nm[target].has_tcp(port) and nm[target]['tcp'][port]['state'] == 'open':
            service = nm[target]['tcp'][port]['name']
            product = nm[target]['tcp'][port]['product']
            version = nm[target]['tcp'][port]['version']
            cpe = nm[target]['tcp'][port]['cpe']

            if cpe:
                return f"{service} ({cpe})", "TCP"
            else:
                return f"{service} ({product} {version})", "TCP"
        else:
            return "Unknown", "Unknown"
    except Exception as e:
        return "Unknown", "Unknown"

# Function to check security issues on a specific port
def check_security_issues(target, port):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=f'-p {port} --script vulners,vulscan')

        issues = []

        if target in nm.all_hosts() and 'tcp' in nm[target]:
            for script_id, output in nm[target]['tcp'][port]['script'].items():
                if 'VULNERABILITY' in output:
                    vulnerabilities = output['VULNERABILITY']
                    for vulnerability in vulnerabilities:
                        issues.append((port, vulnerability['id'], vulnerability['output']))

        return issues
    except Exception as e:
        return [(port, f"Error during security check for {target}:{port}: {e}")]

# Function to filter ports based on a specified mode (open/closed/all)
def filter_ports(results, filter_mode):
    if filter_mode == 'all':
        return results
    else:
        return [(port, status) for port, status in results if filter_mode in status.lower()]

# Function to perform port scanning on a list of ports for a target
def scan_ports(target, ports, filter_mode, allow_reserved_ports):
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        args_list = [(target, port, filter_mode, allow_reserved_ports) for port in ports]
        results = list(executor.map(scan_port_wrapper, args_list))
    return results

# Wrapper function for scan_port to be used with ThreadPoolExecutor
def scan_port_wrapper(args):
    return scan_port(*args)

# Function to validate user input for port numbers
def validate_port_input(port_input):
    try:
        port = int(port_input)
        if 0 < port <= 65535:
            return port
    except ValueError:
        pass
    print("Invalid port number. Please enter a valid port.")
    return None

# Function to get target IP addresses or hostnames from user input
def get_targets():
    while True:
        target_input = input("\nEnter target IP addresses or hostnames (separated by space): ")
        targets = target_input.split()

        validated_targets = []
        invalid_targets = []

        for target in targets:
            if validate_ip(target) or validate_hostname(target):
                validated_targets.append(target)
            else:
                invalid_targets.append(target)

        if invalid_targets:
            print(f"\nInvalid target(s): {', '.join(invalid_targets)}. Please enter valid IP addresses or hostnames.")
        else:
            break
    return validated_targets

# Function to validate an IP address
def validate_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

# Function to validate a hostname
def validate_hostname(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

# Function to get user-defined custom ports for scanning
def get_custom_ports():
    custom_ports = input("\nEnter custom ports (separated by space): ").split()
    return [validate_port_input(port) for port in custom_ports if validate_port_input(port)]

# Function to get scan options from the user
def get_scan_options():
    print("\nChoose the type of scan:")
    print("  (s) Standard Scan: Scan a specific range of ports.")
    print("  (c) Custom Scan: Scan user-defined custom ports.")
    print("  (q) Quick Scan: Scan common ports.")
    print("  (t) Thorough Scan: Scan all ports (1-65535).")

    while True:
        scan_type = input("Enter your choice (s/c/q/t): ").lower()

        if scan_type == 's':
            start_port = validate_port_input(input("Enter starting port: "))
            end_port = validate_port_input(input("Enter ending port: "))
            if start_port and end_port:
                return range(start_port, end_port + 1), None
        elif scan_type == 'c':
            custom_ports = get_custom_ports()
            return custom_ports, custom_ports
        elif scan_type == 'q':
            return COMMON_PORTS, None
        elif scan_type == 't':
            return range(1, 65536), None

        print("Invalid choice. Please enter 's' for Standard Scan, 'c' for Custom Scan, 'q' for Quick Scan, or 't' for Thorough Scan.")

# Function to get filter mode from the user (open/closed/all)
def get_filter_mode():
    while True:
        filter_mode = input("\nFilter scan results by (open/closed/all)? ").lower()
        if filter_mode in ['open', 'closed', 'all']:
            return filter_mode
        print("Invalid filter mode. Please enter 'open', 'closed', or 'all'.")

# Function to get user's choice for exporting results to a CSV file
def get_output_options():
    export_csv = input("\nExport results to a CSV file? (y/n): ").lower() == 'y'
    return export_csv

# Function to get user's choice for performing a security scan
def get_security_scan_option():
    security_scan = input("\nPerform a security scan? (y/n): ").lower() == 'y'
    return security_scan

# Function to configure the logger for logging scan results
def configure_logger(log_filename):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(message)s')

    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

# Function to print the program banner
def print_banner():
    print("\n" + "=" * 40)
    print("        Python Port Scanner")
    print("=" * 40)

# Function to save scan results to a CSV file
def save_to_file(results, filename):
    with open(filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Target', 'Port', 'Status'])
        csv_writer.writerows(results)

# Function to perform service detection on open ports
def perform_service_detection(target, open_ports):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV')

        detected_services = []
        for port in open_ports:
            if nm[target].has_tcp(port) and nm[target]['tcp'][port]['state'] == 'open':
                service_name = nm[target]['tcp'][port]['name']
                product = nm[target]['tcp'][port]['product']
                version = nm[target]['tcp'][port]['version']
                cpe = nm[target]['tcp'][port]['cpe']

                if cpe:
                    detected_services.append((port, f"{service_name} ({cpe})"))
                else:
                    detected_services.append((port, f"{service_name} ({product} {version})"))

        return detected_services
    except Exception as e:
        return [(port, f"Error during service detection: {e}") for port in open_ports]

# Function to display scan results
def display_scan_results(target, results):
    print("\nScan Results:")
    print(f"{'Target': <20}{'Port': <10}{'Status': <40}")
    print("=" * 70)
    for port, status in results:
        print(f"{target: <20}{port: <10}{status}")
        logging.info(f"Target {target} - Port {port} is {status}")

# Function to display detected services
def display_detected_services(target, detected_services):
    if detected_services:
        print("\nDetected Services:")
        print(f"{'Port': <10}{'Service': <40}")
        print("=" * 70)
        for port, service in detected_services:
            print(f"{port: <10}{service}")
    else:
        print("\nNo services detected.")

# Function to display security issues
def display_security_issues(target, security_issues):
    if security_issues:
        print("\nSecurity Issues:")
        print(f"{'Port': <10}{'Issue': <40}")
        print("=" * 70)
        for port, issue in security_issues:
            print(f"{port: <10}{issue}")
            logging.warning(f"Target {target} - Port {port} is {issue}")
    else:
        print("\nNo security issues found.")

# Main function that orchestrates the entire scanning process
def main():
    print_banner()

    targets = get_targets()
    export_csv = get_output_options()
    security_scan = get_security_scan_option()

    for target in targets:
        log_filename = f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_scan_log.txt"
        log_filepath = os.path.join(os.path.expanduser('~'), 'Downloads', log_filename)

        configure_logger(log_filepath)

        print(f"\nScanning target {target}")
        print("=" * 40)

        ports_to_scan, custom_ports = get_scan_options()
        results = []
        filter_mode = get_filter_mode()
        allow_reserved_ports = input("Allow scanning and identifying services on reserved ports? (y/n): ").lower() == 'y'

        scan_choice = input("\nChoose scanning method (t) Multithreading / (m) Multiprocessing / (Press Enter to skip): ").lower()

        if scan_choice == 't':
            print("\nPerforming multithreaded scan...")
            with concurrent.futures.ThreadPoolExecutor() as executor:
                args_list = [(target, port, filter_mode, allow_reserved_ports) for port in ports_to_scan]
                results = list(executor.map(scan_port_wrapper, args_list))
        elif scan_choice == 'm':
            print("\nPerforming multiprocessing scan...")
            with concurrent.futures.ProcessPoolExecutor() as executor:
                args_list = [(target, port, filter_mode, allow_reserved_ports) for port in ports_to_scan]
                results = list(executor.map(scan_port_wrapper, args_list))
        elif not scan_choice:
            print("\nContinuing without multithreading or multiprocessing.")
            results = [scan_port(target, port, filter_mode, allow_reserved_ports) for port in ports_to_scan]
        else:
            print("\nInvalid choice. Continuing without multithreading or multiprocessing.")

        filtered_results = filter_ports(results, filter_mode)
        if not filtered_results:
            print(f"No ports with status '{filter_mode}' found.")
        else:
            display_scan_results(target, filtered_results)

            detected_services = perform_service_detection(target, [port for port, status in filtered_results if "open" in status])
            display_detected_services(target, detected_services)

            if export_csv:
                csv_filename = f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_scan_results.csv"
                csv_filepath = os.path.join(os.path.expanduser('~'), 'Downloads', csv_filename)
                save_to_file([(target, port, status) for port, status in filtered_results], csv_filepath)
                print(f"\nScan results saved to {csv_filepath}.")

            if security_scan:
                security_issues = []
                for port, status in filtered_results:
                    if "open" in status:
                        issues = check_security_issues(target, port)
                        if issues:
                            security_issues.extend([(port, issue) for issue in issues])

                display_security_issues(target, security_issues)

        print("=" * 40)

    print("\nScan completed. Thank you for using the Python Port Scanner!")

if __name__ == "__main__":
    main()
