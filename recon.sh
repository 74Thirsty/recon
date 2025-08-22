#!/bin/bash

# Function to check if a tool is installed
check_and_install() {
    TOOL=$1
    PACKAGE=$2

    # Check if the tool is installed
    if ! command -v $TOOL &> /dev/null; then
        echo "[ERROR] $TOOL is not installed."
        echo "Attempting to install $PACKAGE..."

        # Attempt to install the tool using package manager
        if [[ $(uname) == "Linux" ]]; then
            if command -v apt &> /dev/null; then
                sudo apt-get install -y $PACKAGE
            elif command -v yum &> /dev/null; then
                sudo yum install -y $PACKAGE
            else
                echo "[ERROR] Unsupported package manager. Please install $TOOL manually."
                exit 1
            fi
        elif [[ $(uname) == "Darwin" ]]; then
            if command -v brew &> /dev/null; then
                brew install $PACKAGE
            else
                echo "[ERROR] Homebrew is not installed. Please install $TOOL manually."
                exit 1
            fi
        else
            echo "[ERROR] Unknown operating system. Please install $TOOL manually."
            exit 1
        fi
    else
        echo "[INFO] $TOOL is already installed."
    fi
}

# Function to display the main menu
show_menu() {
    echo "==========================="
    echo "  Interactive Recon Script"
    echo "==========================="
    echo "1) Nmap Scan"
    echo "2) Wireshark Packet Capture"
    echo "3) Validate IP Address"
    echo "4) Exit"
    echo "==========================="
    echo -n "Choose an option: "
}

# Function to perform Nmap scan
perform_nmap_scan() {
    echo "Enter the target IP address to scan: "
    read target_ip

    # Validate IP
    if ! is_valid_ip $target_ip; then
        echo "[ERROR] Invalid IP address."
        return
    fi

    echo "Running Nmap scan on $target_ip..."
    nmap -sS -T4 -p- --open --reason --max-retries 3 --host-timeout 30m -oN nmap_scan_$target_ip.txt $target_ip
    echo "Nmap scan completed. Results saved in nmap_scan_$target_ip.txt"
}

# Function to perform Wireshark packet capture
perform_packet_capture() {
    echo "Enter the target IP address for packet capture: "
    read target_ip

    echo "Enter the port to capture packets from (e.g., 80 for HTTP): "
    read port

    # Validate IP and port
    if ! is_valid_ip $target_ip; then
        echo "[ERROR] Invalid IP address."
        return
    fi
    if ! is_valid_port $port; then
        echo "[ERROR] Invalid port number."
        return
    fi

    echo "Starting packet capture on $target_ip:$port..."
    capture_command="tshark -i eth0 host $target_ip and port $port -w capture_${target_ip}_${port}.pcap"
    # Run packet capture in the background
    $capture_command & 
    capture_pid=$!

    echo "Packet capture started. Type 'stop' to stop capturing packets."

    # Wait for user input to stop capture
    while true; do
        read -p "Enter 'stop' to stop packet capture: " input
        if [[ "$input" == "stop" ]]; then
            kill $capture_pid
            echo "Packet capture stopped."
            break
        fi
    done

    echo "Captured packets saved as capture_${target_ip}_${port}.pcap."
}

# Function to validate IP address
is_valid_ip() {
    local ip=$1
    local pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ $ip =~ $pattern ]]; then
        return 0  # valid IP
    else
        return 1  # invalid IP
    fi
}

# Function to validate port number
is_valid_port() {
    local port=$1
    if [[ $port -ge 1 && $port -le 65535 ]]; then
        return 0  # valid port
    else
        return 1  # invalid port
    fi
}

# Function to display cool ASCII art text on start
show_ascii_art() {
    echo ""
    echo "==============================="
    echo "RECON by C. Hirschauer"
    echo "==============================="
    echo ""
    figlet "RECON" -f slant
}

# Main program loop
while true; do
    # Show ASCII art on script start
    show_ascii_art

    # Check for required tools and install if missing
    check_and_install "nmap" "nmap"
    check_and_install "tshark" "wireshark"
    check_and_install "figlet" "figlet"

    # Display menu and handle user choice
    show_menu
    read choice

    case $choice in
        1)
            perform_nmap_scan
            ;;
        2)
            perform_packet_capture
            ;;
        3)
            echo "Enter IP address to validate: "
            read target_ip
            if is_valid_ip $target_ip; then
                echo "$target_ip is a valid IP address."
            else
                echo "$target_ip is an invalid IP address."
            fi
            ;;
        4)
            echo "Exiting the script."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
done
