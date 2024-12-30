
# Vulnerability Scanning Tool using Nmap

This is a Python-based tool for performing vulnerability scans on a target system using Nmap. The tool scans open ports on a given target and identifies service details (name, product, version) and any vulnerabilities detected using Nmap scripts.

## Features

- Scans a target system for open ports.
- Detects services running on those ports.
- Displays additional information about the services (product, version, and extra info).
- Runs vulnerability scripts (`vuln`) to identify potential security issues.

## Requirements

To use this tool, you need:

- Python 3.x
- `nmap` library for Python
- Nmap installed on your system

### Installing Nmap

Make sure you have Nmap installed on your machine. You can download it from [here](https://nmap.org/download.html).

#### On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install nmap
```

#### On macOS (using Homebrew):

```bash
brew install nmap
```

### Installing Python Dependencies

You can install the required Python libraries by running:

```bash
pip install python-nmap
```

## Usage

1. Clone this repository:

   ```bash
   git clone https://github.com/Unknonhack/vulnerability-scanning-tool.git
   cd vulnerability-scanning-tool
   ```

2. Run the script:

   ```bash
   python vulnerability-scanning-tools.py
   ```

3. You will be prompted to enter a target IP address or domain for scanning.

   Example:

   ```
   Enter the target IP address or domain: 192.168.1.1
   ```

   The script will then proceed to scan the target system, identify open ports, detect services running on those ports, and display any vulnerabilities.

## Output

The script outputs detailed information about each open port:

- **Port**: The port number.
- **State**: The port state (open, closed, etc.).
- **Service**: The service running on the port.
- **Product**: The product name associated with the service.
- **Version**: The version of the service or product.
- **Extra Info**: Any additional information related to the service.
- **Vulnerabilities**: If any vulnerabilities are found, they will be listed with an output message.

### Example Output:

```
Scanning 192.168.1.1
Port: 80   State: open    Service: http   Product: Apache httpd   Version: 2.4.41   Extra Info: httpd 2.4.41 (Debian)
Vulnerability: http-methods
Output: Allowed methods: GET, POST, OPTIONS, HEAD
Port: 22   State: open    Service: ssh    Product: OpenSSH   Version: 7.6p1 Debian 4+deb9u7
Vulnerability: sshv1
Output: OpenSSH version 7.6p1
```

## Code

### `scan_ports.py`

```python
import nmap

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --script=vuln')
    
    for host in nm.all_hosts():
        print(f'Scanning {host}')
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                extrainfo = nm[host][proto][port]['extrainfo']
                print(f'Port: {port}	State: {state}	Service: {name}	Product: {product}	Version: {version}	Extra Info: {extrainfo}')
                
                if 'script' in nm[host][proto][port]:
                    for script in nm[host][proto][port]['script']:
                        print(f'Vulnerability: {script}
Output: {nm[host][proto][port]["script"][script]}')

if __name__ == "__main__":
    target = input("Enter the target IP address or domain: ")
    scan_ports(target)
```

## Contributing

Feel free to fork this repository, contribute code improvements, report issues, or suggest new features. Open a pull request or open an issue in the GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
