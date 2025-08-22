# Recon by C. Hirschauer

**Recon** is an interactive, terminal-based recon tool designed to streamline network exploration. Whether you're performing Nmap scans, capturing packets with Wireshark, or validating IP addresses, **Recon** is your go-to companion for every phase of your reconnaissance process. Built with simplicity and efficiency in mind, this script runs seamlessly on both Linux and macOS.

## Features

- **Nmap Scan**: Conduct comprehensive scans to discover open ports and services on a target IP.
- **Wireshark Packet Capture**: Capture real-time network traffic from a specified IP and port.
- **IP Validation**: Validate whether an inputted IP address is properly formatted.
- **Tool Installation**: Automatically checks for and installs necessary tools (`nmap`, `wireshark`, `figlet`) if they're not already present.

## Getting Started

### Prerequisites

Before you begin, make sure your system is equipped with the required tools. **Recon** checks and installs these automatically, but here’s a quick manual guide for setting up:

1. **Linux**:
    - Install `nmap`: `sudo apt-get install -y nmap` (or `sudo yum install -y nmap` for RPM-based systems)
    - Install `wireshark`: `sudo apt-get install -y tshark`
    - Install `figlet`: `sudo apt-get install -y figlet`
  
2. **macOS**:
    - Install `nmap`: `brew install nmap`
    - Install `wireshark`: `brew install wireshark`
    - Install `figlet`: `brew install figlet`

### Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/74Thirsty/recon.git
    cd recon
    ```

2. **Make the script executable**:

    ```bash
    chmod +x recon.sh
    ```

3. **Run the script**:

    ```bash
    ./recon.sh
    ```

## Usage

When you run the script, it will check for the required tools (`nmap`, `wireshark`, `figlet`). If any of these are missing, it will attempt to install them for you.

Upon startup, **Recon** will display a badass ASCII banner:

```bash
===============================
RECON by C. Hirschauer
===============================
````

Then, you'll be presented with an interactive menu:

```bash
===========================
  Interactive Recon Script
===========================
1) Nmap Scan
2) Wireshark Packet Capture
3) Validate IP Address
4) Exit
===========================
Choose an option: 
```

Select an option by entering the corresponding number:

1. **Nmap Scan**: Enter a target IP, and **Recon** will run an Nmap scan to identify open ports and services.
2. **Wireshark Packet Capture**: Enter a target IP and port to begin capturing packets. Type `stop` to end the capture and save the results as a `.pcap` file.
3. **Validate IP Address**: Validate any IP address to check if it follows the correct format.
4. **Exit**: Exit the script gracefully.

## Example

```bash
===============================
RECON by C. Hirschauer
===============================

===========================
  Interactive Recon Script
===========================
1) Nmap Scan
2) Wireshark Packet Capture
3) Validate IP Address
4) Exit
===========================
Choose an option: 1
Enter the target IP address to scan:
192.168.1.1
Running Nmap scan on 192.168.1.1...
Nmap scan completed. Results saved in nmap_scan_192.168.1.1.txt
```

## Contribution

We welcome contributions to **Recon**! If you have suggestions for new features or improvements, feel free to fork the repository, submit issues, or create pull requests. Here’s how you can contribute:

1. Fork the repo.
2. Clone your fork: `git clone https://github.com/yourusername/recon.git`
3. Create a feature branch: `git checkout -b feature-name`
4. Make your changes and commit them: `git commit -m 'Add feature'`
5. Push to your branch: `git push origin feature-name`
6. Create a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Recon** is your all-in-one tool for reconnaissance, whether you're a network security expert or a beginner exploring network fundamentals. It’s simple, badass, and ready to scan the world.

Happy reconning! 👊

### Key Features of This README:
1. **Badass Introduction**: It kicks off with a cool, engaging introduction to **Recon**, making it clear what the tool does and its purpose.
2. **Setup Instructions**: Clear steps to get started, including installation for both Linux and macOS.
3. **Usage and Examples**: A simple walk-through of how the tool is used, with easy-to-understand examples.
4. **Contributions**: Encourages others to contribute to the project.
5. **License**: Clear licensing information.
