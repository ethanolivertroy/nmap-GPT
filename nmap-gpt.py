import argparse
import nmap
from openai import OpenAI
import os
import json
import csv
from datetime import datetime

# Set OpenAI client with API key from environment variable
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define the command line arguments
parser = argparse.ArgumentParser(description='Nmap Network Scanner with OpenAI Analysis for 2025')
parser.add_argument('host', type=str, help='Host or IP address to scan')
parser.add_argument('-p', '--port', type=str, help='Port or port range to scan', default='1-1024')
parser.add_argument('--output', type=str, help='Output file to save results (JSON or CSV)', default=None)
parser.add_argument('--model', type=str, help='OpenAI model to use', default='gpt-4-turbo')
parser.add_argument('--scan-type', type=str, choices=['basic', 'advanced'], help='Type of scan to perform', default='basic')

# Parse the command line arguments
args = parser.parse_args()

# Initialize Nmap
nm = nmap.PortScanner()

# Configure scan parameters based on scan type
scan_args = {}
if args.scan_type == 'advanced':
    scan_args = {
        'arguments': '-sV -sC -O --script vuln'  # Version detection, script scanning, OS detection, and vuln scripts
    }

# Perform the Nmap scan
print(f"Starting scan of {args.host} on port(s) {args.port} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
try:
    nm.scan(args.host, args.port, **scan_args)
except nmap.PortScannerError as e:
    print(f"Nmap scan error: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)

# Extract the results of the Nmap scan
scan_results = []
for host in nm.all_hosts():
    host_info = {
        'host': host,
        'hostname': nm[host].hostname(),
        'state': nm[host].state(),
        'protocols': []
    }
    
    # Add OS detection results if available
    if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
        host_info['os_detection'] = nm[host]['osmatch'][0]['name']
        print(f"OS Detection: {host_info['os_detection']}")
    
    print('Host: {} ({})'.format(host, nm[host].hostname()))
    print('State: {}'.format(nm[host].state()))
    
    for protocol in nm[host].all_protocols():
        protocol_info = {
            'protocol': protocol,
            'ports': []
        }
        print('Protocol: {}'.format(protocol))
        lport = nm[host][protocol].keys()
        lport = sorted(lport)
        for port in lport:
            port_info = {
                'port': port,
                'state': nm[host][protocol][port]['state']
            }
            
            # Add service info if available
            if 'name' in nm[host][protocol][port] and nm[host][protocol][port]['name']:
                service_name = nm[host][protocol][port]['name']
                port_info['service'] = service_name
                print(f"Port: {port}\tState: {nm[host][protocol][port]['state']}\tService: {service_name}")
            else:
                print(f"Port: {port}\tState: {nm[host][protocol][port]['state']}")

            # Add version info if available
            if 'product' in nm[host][protocol][port] and nm[host][protocol][port]['product']:
                product = nm[host][protocol][port]['product']
                version = nm[host][protocol][port].get('version', '')
                port_info['product'] = product
                port_info['version'] = version
                print(f"Product: {product} {version}")
            
            # Send a prompt to OpenAI for each open port
            if nm[host][protocol][port]['state'] == 'open':
                service_str = f"the {protocol} service"
                if 'service' in port_info:
                    service_str = f"the {port_info['service']} service"
                
                version_str = ""
                if 'product' in port_info and 'version' in port_info:
                    version_str = f" running {port_info['product']} {port_info['version']}"
                
                prompt = f"What security concerns should I be aware of given {service_str} on port {port}{version_str} for host: {host}? What are the latest security vulnerabilities in 2025 for this service?"
                
                try:
                    response = client.chat.completions.create(
                        model=args.model,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert in 2025 with knowledge of the latest vulnerabilities and attack vectors."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=800,
                        temperature=0.5,
                    )

                    # Extract the generated report from the OpenAI API response
                    text = response.choices[0].message.content
                    print("OpenAI Report:\n{}\n".format(text))
                    port_info['openai_report'] = text
                except Exception as e:
                    print(f"Error communicating with OpenAI: {e}")
                    port_info['openai_report'] = f"Error: {e}"

            protocol_info['ports'].append(port_info)
        host_info['protocols'].append(protocol_info)
    scan_results.append(host_info)

# Save results to JSON or CSV if specified
if args.output:
    if args.output.endswith('.json'):
        with open(args.output, 'w') as json_file:
            json.dump(scan_results, json_file, indent=4)
        print(f"Results saved to {args.output}")
    elif args.output.endswith('.csv'):
        with open(args.output, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['Host', 'Hostname', 'State', 'OS Detection', 'Protocol', 'Port', 'Port State', 'Service', 'Product', 'Version', 'OpenAI Report'])
            for host in scan_results:
                for protocol in host['protocols']:
                    for port in protocol['ports']:
                        csv_writer.writerow([
                            host['host'], 
                            host['hostname'], 
                            host['state'],
                            host.get('os_detection', ''),
                            protocol['protocol'], 
                            port['port'], 
                            port['state'],
                            port.get('service', ''),
                            port.get('product', ''),
                            port.get('version', ''),
                            port.get('openai_report', '')
                        ])
        print(f"Results saved to {args.output}")
    else:
        print("Unsupported output format. Please use .json or .csv as the file extension.")
