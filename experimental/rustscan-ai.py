import argparse
import subprocess
import json
import os
import csv
from openai import OpenAI
from datetime import datetime

# Set OpenAI client with API key from environment variable
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define the command line arguments
parser = argparse.ArgumentParser(description='RustScan Network Scanner with OpenAI Analysis for 2025')
parser.add_argument('host', type=str, help='Host or IP address to scan')
parser.add_argument('-p', '--port', type=str, help='Port or port range to scan', default='1-1024')
parser.add_argument('--output', type=str, help='Output file to save results (JSON or CSV)', default=None)
parser.add_argument('--model', type=str, help='OpenAI model to use', default='gpt-4-turbo')
parser.add_argument('--nmap-follow', action='store_true', help='Run nmap after RustScan for service detection')
parser.add_argument('--ulimit', type=int, help='Set ulimit for RustScan', default=5000)
parser.add_argument('--timeout', type=int, help='Set timeout for RustScan in milliseconds', default=1000)
parser.add_argument('--batch-size', type=int, help='Set batch size for RustScan', default=500)

# Parse the command line arguments
args = parser.parse_args()

print(f"Starting RustScan of {args.host} on port(s) {args.port} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Prepare RustScan command
port_arg = f"-p {args.port}" if args.port else ""
nmap_follow = "--nmap -- -sV -sC" if args.nmap_follow else ""

command = (
    f'rustscan -a {args.host} {port_arg} --ulimit {args.ulimit} --timeout {args.timeout} '
    f'--batch-size {args.batch_size} {nmap_follow} --json'
)

try:
    # Execute RustScan and capture the output
    print(f"Running command: {command}")
    output = subprocess.check_output(command, shell=True)
    
    # Parse the RustScan output
    result = json.loads(output.decode('utf-8'))
    
    # Prepare data structure for results
    scan_results = []
    
    # Process RustScan results
    for host_data in result:
        host = host_data['ip']
        hostnames = host_data.get('hostnames', [])
        hostname = ', '.join(hostnames) if hostnames else 'No hostname'
        
        host_info = {
            'host': host,
            'hostname': hostname,
            'ports': []
        }
        
        print(f'Host: {host} ({hostname})')
        
        # Process open ports
        open_ports = host_data.get('ports', [])
        for port_data in open_ports:
            port = port_data['port']
            state = port_data.get('state', 'unknown')
            service = port_data.get('service', {})
            
            service_name = service.get('name', 'unknown')
            product = service.get('product', '')
            version = service.get('version', '')
            
            port_info = {
                'port': port,
                'state': state,
                'service': service_name,
                'product': product,
                'version': version
            }
            
            # Print port information
            service_str = f"Service: {service_name}" if service_name != 'unknown' else ""
            product_str = f"Product: {product} {version}" if product else ""
            
            print(f'Port: {port}\tState: {state}\t{service_str}')
            if product_str:
                print(f'{product_str}')
            
            # Generate OpenAI report for open ports
            if state == 'open':
                # Construct service string based on available information
                service_desc = f"the {service_name} service" if service_name != 'unknown' else "a service"
                
                version_str = ""
                if product:
                    version_str = f" running {product} {version}" if version else f" running {product}"
                
                prompt = (
                    f"What security concerns should I be aware of given {service_desc} on port {port}"
                    f"{version_str} for host: {host}? What are the latest security vulnerabilities in 2025 for this service?"
                )
                
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
                    
                    # Extract the generated report
                    text = response.choices[0].message.content
                    print(f"OpenAI Report:\n{text}\n")
                    port_info['openai_report'] = text
                    
                except Exception as e:
                    error_msg = f"Error communicating with OpenAI: {e}"
                    print(error_msg)
                    port_info['openai_report'] = error_msg
            
            host_info['ports'].append(port_info)
        
        scan_results.append(host_info)
    
    # Save results to file if specified
    if args.output:
        if args.output.endswith('.json'):
            with open(args.output, 'w') as json_file:
                json.dump(scan_results, json_file, indent=4)
            print(f"Results saved to {args.output}")
            
        elif args.output.endswith('.csv'):
            with open(args.output, 'w', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)
                csv_writer.writerow(['Host', 'Hostname', 'Port', 'State', 'Service', 'Product', 'Version', 'OpenAI Report'])
                
                for host in scan_results:
                    for port in host['ports']:
                        csv_writer.writerow([
                            host['host'],
                            host['hostname'],
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

except subprocess.CalledProcessError as e:
    print(f"Error running RustScan: {e}")
    if e.output:
        print(f"Output: {e.output.decode('utf-8')}")
    print("\nMake sure RustScan is installed. You can install it with:")
    print("  cargo install rustscan")
    print("Or use a Docker container:")
    print("  docker run -it --rm --name rustscan rustscan/rustscan:latest <args>")
    exit(1)
    
except json.JSONDecodeError as e:
    print(f"Error parsing RustScan JSON output: {e}")
    exit(1)
    
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)
