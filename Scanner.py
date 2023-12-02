#Scanner.py

import nmap

def discover_active_hosts(network_range):
    scanner = nmap.PortScanner()
    scan_results = scanner.scan(network_range, arguments='-sn')

    active_hosts = []
    for host in scan_results['all_hosts']:
        if host['status'] == 'up':
            active_hosts.append(host['ip_address'])

    return active_hosts

def port_scanning(host):
    scanner = nmap.PortScanner()
    scan_results = scanner.scan(host, arguments='-p-')

    open_ports = []
    for port in scan_results['all_ports']:
        if port['state'] == 'open':
            open_ports.append(port['port'])

    return open_ports

def service_version_detection(host, ports):
    scanner = nmap.PortScanner()
    scan_results = scanner.scan(host, arguments='-sV', ports=','.join(map(str, ports)))

    services = {}
    for port in scan_results['all_ports']:
        if port['state'] == 'open':
            service = scan_results['all_ports'][port]['service']
            service_version = scan_results['all_ports'][port]['version']

            services[port] = {'service': service, 'version': service_version}

    return services

def vulnerability_identification(services):
    vulnerabilities = []

    # Check services and versions against a vulnerability database
    # (e.g., NVD, CVE) and add identified vulnerabilities to the list
    # For each vulnerability, include details like affected device, open port,
    # service, and associated vulnerability information

    return vulnerabilities

def generate_report(device, open_ports, services, vulnerabilities):
    report = f"Device: {device}\n"
    report += f"Open Ports: {', '.join(map(str, open_ports))}\n"
    report += "Services:\n"

    for port, service_info in services.items():
        report += f"  - Port: {port}\n"
        report += f"    Service: {service_info['service']}\n"
        report += f"    Version: {service_info['version']}\n"

    if vulnerabilities:
        report += "\nVulnerabilities:\n"
        for vulnerability in vulnerabilities:
            report += f"  - {vulnerability}\n"

    return report

if __name__ == "__main__":
    network_range = "192.168.1.0/24"

    active_hosts = discover_active_hosts(network_range)

    for host in active_hosts:
        open_ports = port_scanning(host)
        services = service_version_detection(host, open_ports)
        vulnerabilities = vulnerability_identification(services)
        report = generate_report(host, open_ports, services, vulnerabilities)
        print(report)
