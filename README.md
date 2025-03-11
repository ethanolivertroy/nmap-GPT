# NMAP-GPT (2025 Edition)

![nmap-gpt](https://user-images.githubusercontent.com/63926014/221396066-0ace46a1-bb97-4fc0-825c-412f4e2dbc4d.png)

This tool helps security professionals actively learn how to address security concerns associated with open ports on a network device. It works by scanning the device using Nmap or RustScan and then leveraging the OpenAI API to provide insights on specific security considerations for each open port, including the latest vulnerability information as of 2025.

## Features (2025 Edition)

- **Modern OpenAI API**: Updated to use the latest OpenAI client library and models
- **Enhanced Scanning**: Added advanced scanning options for more detailed vulnerability assessment
- **RustScan Integration**: Optional use of RustScan for faster port discovery
- **Comprehensive Reports**: Detailed reports with service version detection and OS fingerprinting
- **Export Options**: Save results in JSON or CSV format for further analysis

## Installation

1. Install required dependencies:

```bash
pip install python-nmap openai
```

2. For RustScan features, install RustScan:

```bash
# Using Cargo (Rust package manager)
cargo install rustscan

# Or using Docker
docker pull rustscan/rustscan:latest
```

3. Set your OpenAI API key:

```bash
export OPENAI_API_KEY="your-api-key-here"
```

## Usage

### Basic Nmap Scan

```bash
python3 nmap-gpt.py example.com -p 80
```

### Advanced Nmap Scan with Version Detection

```bash
python3 nmap-gpt.py example.com -p 1-1000 --scan-type advanced --output results.json
```

### Using RustScan for Faster Port Discovery

```bash
python3 experimental/rustscan-ai.py example.com -p 1-1000 --nmap-follow --output results.json
```

## Command Options

### Nmap-GPT Options

```
  host                  Host or IP address to scan
  -p PORT, --port PORT  Port or port range to scan (default: '1-1024')
  --output OUTPUT       Output file to save results (JSON or CSV)
  --model MODEL         OpenAI model to use (default: 'gpt-4-turbo')
  --scan-type {basic,advanced}
                        Type of scan to perform (default: 'basic')
```

### RustScan-AI Options

```
  host                  Host or IP address to scan
  -p PORT, --port PORT  Port or port range to scan (default: '1-1024')
  --output OUTPUT       Output file to save results (JSON or CSV)
  --model MODEL         OpenAI model to use (default: 'gpt-4-turbo')
  --nmap-follow         Run nmap after RustScan for service detection
  --ulimit ULIMIT       Set ulimit for RustScan (default: 5000)
  --timeout TIMEOUT     Set timeout for RustScan in milliseconds (default: 1000)
  --batch-size BATCH_SIZE
                        Set batch size for RustScan (default: 500)
```

## Examples 

### Basic Port Scanning

![Example of basic port scan](https://user-images.githubusercontent.com/63926014/218787405-c4fdd27d-06b6-44e6-ae97-174033dd2288.png)

### Advanced Security Analysis

![Example of advanced security analysis](https://user-images.githubusercontent.com/63926014/218797253-d5d01fed-e425-4379-9dfa-f29d862a82ec.png)

### RustScan Integration

The experimental RustScan integration provides significantly faster port discovery:

```bash
python3 experimental/rustscan-ai.py example.com --nmap-follow
```

This combines RustScan's fast port discovery with Nmap's detailed service detection, followed by OpenAI analysis of potential vulnerabilities.

## Security Notes

- This tool is intended for educational purposes and authorized security testing only
- Always ensure you have permission to scan the target systems
- The OpenAI analysis provides general security information but should not replace professional security assessments
