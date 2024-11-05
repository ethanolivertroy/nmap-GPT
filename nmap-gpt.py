import argparse
import nmap
import openai
import os
import json
import csv

# Set OpenAI API key from environment variable
openai.api_key = os.getenv("OPENAI_API_KEY")

# Define the command line arguments
parser = argparse.ArgumentParser(description='Nmap Network Scanner with OpenAI Analysis')
parser.add_argument('host', type=str, help='Host or IP address to scan')
parser.add_argument('-p', '--port', type=str, help='Port or port range to scan', default='1-1024')
parser.add_argument('--output', type=str, help='Output file to save results (JSON or CSV)', default=None)

# Parse the command line arguments
args = parser.parse_args()

# Initialize Nmap
nm = nmap.PortScanner()

# Perform the Nmap scan
try:
    nm.scan(args.host, args.port)
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
            print('Port: {}\tState: {}'.format(port, nm[host][protocol][port]['state']))

            # Send a prompt to OpenAI for each open port
            if nm[host][protocol][port]['state'] == 'open':
                prompt = f"What security concerns should I be aware of given the {protocol} service on port {port} for host: {host}?"
                try:
                    response = openai.ChatCompletion.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=500,
                        temperature=0.5,
                    )

                    # Extract the generated report from the OpenAI API response
                    text = response['choices'][0]['message']['content']
                    print("OpenAI Report:\n{}
".format(text))
                    port_info['openai_report'] = text
                except openai.error.OpenAIError as e:
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
    elif args.output.endswith('.csv'):
        with open(args.output, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['Host', 'Hostname', 'State', 'Protocol', 'Port', 'Port State', 'OpenAI Report'])
            for host in scan_results:
                for protocol in host['protocols']:
                    for port in protocol['ports']:
                        csv_writer.writerow([host['host'], host['hostname'], host['state'], protocol['protocol'], port['port'], port['state'], port.get('openai_report', '')])
    else:
        print("Unsupported output format. Please use .json or .csv as the file extension.")
