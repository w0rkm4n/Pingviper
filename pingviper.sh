#!/bin/bash

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

trap ctrl_c INT

function ctrl_c() {
    echo "Interrupted by the user."
    exit 1
}

usage() {
    echo -e "${GREEN} ______ __                     __                   "
    echo "|   __ \__|.-----.-----.--.--.|__|.-----.-----.----."
    echo "|    __/  ||     |  _  |  |  ||  ||  _  |  -__|   _|"
    echo "|___|  |__||__|__|___  |\___/ |__||   __|_____|__|  "
    echo "                 |_____|          |__|              "
    echo -e "                			by w0rkm4n\n${NC}"
    echo -e "Usage: pingviper.sh [-h] [method] <Subnet> <Mask>\n"
    echo "Methods:"
    echo -e "\tsweep              Perform Ping sweep to given subnet and mask"
    echo -e "\tscan               Perform Nmap scans to file target\n"
    echo "Options:"
    echo -e "\t-h                 Show this help message and exit"
    echo -e "\t-v                 Enable verbose mode for Nmap output"
    echo -e "\t-s                 Set subnet"
    echo -e "\t-m                 Set mask"
    exit 1
}

# Function to convert an IP address to a decimal number
ip_to_dec() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$((a << 24 | b << 16 | c << 8 | d))"
}

# Function to convert a decimal number to an IP address
dec_to_ip() {
    local dec="$1"
    echo "$((dec >> 24 & 255)).$((dec >> 16 & 255)).$((dec >> 8 & 255)).$((dec & 255))"
}

# Function to calculate the network range (including broadcast IP)
calculate_range() {
    local subnet="$1"
    local mask="$2"

    # Convert subnet to decimal
    local subnet_dec=$(ip_to_dec "$subnet")

    # Calculate the number of host bits based on the mask
    local host_bits=$((32 - mask))
    
    # Calculate the total number of addresses
    local total_ips=$((1 << host_bits))

    # Calculate the start and end IP in decimal (including broadcast)
    local start_ip_dec=$((subnet_dec & ~((1 << host_bits) - 1)))
    local end_ip_dec=$((start_ip_dec + total_ips - 1))  # Include broadcast

    # Return the start and end IP addresses
    echo "$start_ip_dec" "$end_ip_dec"
}

# Ping Sweep Function
ping_sweep() {
    local start_ip_dec="$1"
    local end_ip_dec="$2"
    local subnet="$3"
    local mask="$4"
    local ip_file="$5"
    
    # Check if the IP file already exists
    if [ -f "$ip_file" ]; then
        echo -e "${YELLOW}[!]${NC} IP file ${ip_file} already exists."
        read -p "Do you want to overwrite it? [y/N]: " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            echo -e "${RED}[-]${NC} Exiting without overwriting the file."
            exit 1
        fi
    fi

    # Calculate the broadcast IP (last IP in the range)
    local broadcast_ip=$(dec_to_ip "$end_ip_dec")

    echo -e "${BLUE}[*]${NC} Running ping sweep on ${subnet}/${mask}..."
    > "$ip_file"  # Clear previous IP list

    # Use a loop to create a temporary file to store successful pings
    temp_file=$(mktemp)

    for ((ip_dec=start_ip_dec; ip_dec<=end_ip_dec; ip_dec++)); do
        ip=$(dec_to_ip "$ip_dec")

        # Run ping in the background
        {
            if [ "$ip" == "$broadcast_ip" ]; then
                ping -b -c 1 "$ip" 2>/dev/null | grep "bytes from" | awk '{print $4}' | sed 's/://' >> "$temp_file"
            else
                successful=$(ping -c 1 "$ip" 2>/dev/null | grep "bytes from" | awk '{print $4}' | sed 's/://')
                if [ -n "$successful" ]; then
                    echo "$successful" >> "$temp_file"
                    echo -e "${YELLOW}$successful${NC}"
                fi
            fi
        } &
    done

    # Wait for all background jobs to complete
    wait

    # Move successful pings to the final IP file
    cat "$temp_file" >> "$ip_file"
    rm "$temp_file"  # Remove the temporary file

    # Remove empty lines from ip_file
    sed -i '/^$/d' "$ip_file"

    # Remove duplicates from IP file
    sort "$ip_file" | uniq > ip.tmp
    mv ip.tmp "$ip_file"

    # Check the number of active IP addresses found
    IP_COUNT=$(wc -l < "$ip_file")

    if [ "$IP_COUNT" -eq 0 ]; then
        echo -e "${RED}[-]${NC} No active IP addresses found. Stopping the process."
        rm "$ip_file"
        exit 1
    fi

    echo -e "\n${GREEN}[+]${NC} Number of IP addresses found: $IP_COUNT"
    echo -e "${GREEN}[+]${NC} Ping sweep completed. Results saved to $ip_file."
}

# Scanner Function
scanner() {
    local ip_file="$1"
    local subnet_filename="$2"
    local verbosity="$3"

    PORT_SCAN_FILE="${subnet_filename}-port-scan"
    FULL_SCAN_FILE="${subnet_filename}-full-scan"

    # Run Nmap port scan on the active IP addresses
    echo -e "${BLUE}[*]${NC} Running Nmap to discover open ports on the found IP addresses..."

    if [ "$verbosity" == "true" ]; then
        nmap -iL "$ip_file" -oG "$PORT_SCAN_FILE"
    else
        nmap -iL "$ip_file" -oG "$PORT_SCAN_FILE" > /dev/null 2>&1
    fi

    input_file="${PORT_SCAN_FILE}"

    echo -e "\n${GREEN}[+]${NC} Open ports found:"

    # Loop through each unique IP address
    for ip_address in $(cat "$input_file" | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u); do
      # Extract corresponding open ports for the current IP
      ports="$(grep -A 1 "$ip_address" "$input_file" | grep -oP '\d{1,5}/open' | awk -F'/' '{print $1}' | xargs | tr ' ' ',')"

      # Print the output in the desired format
      echo -e "$ip_address: ${YELLOW}$ports${NC}"
    done

    # Run detailed Nmap scan on active IPs
    echo -e "\n${BLUE}[*]${NC} Running a detailed Nmap scan (-sC -sV -Pn -n) on the found IP addresses..."

    if [ "$verbosity" == "true" ]; then
        nmap -iL "$ip_file" -sC -sV -Pn -n -oA "$FULL_SCAN_FILE"
    else
        nmap -iL "$ip_file" -sC -sV -Pn -n -oA "$FULL_SCAN_FILE" > /dev/null 2>&1
    fi
}

# Main logic to call the appropriate function
if [ $# -lt 5 ]; then
    usage
fi

METHOD=$1
shift

# Initialize verbosity
verbosity="false"

while getopts "hvs:m:" opt; do
    case $opt in
        h) usage ;;
        v) verbosity="true" ;;
        s) SUBNET=$OPTARG ;;
        m) SUBNET_MASK=$OPTARG ;;
        *) usage ;;
    esac
done

if [ -z "$SUBNET" ] || [ -z "$SUBNET_MASK" ]; then
    usage
fi

# File names
SUBNET_FILENAME=$(echo "$SUBNET" | tr '.' '_')
IP_FILE="${SUBNET_FILENAME}-ip_addresses.txt"



# Calculate IP range
read start_ip_dec end_ip_dec <<< $(calculate_range "$SUBNET" "$SUBNET_MASK")

# Call the appropriate method
case "$METHOD" in
    sweep)
        ping_sweep "$start_ip_dec" "$end_ip_dec" "$SUBNET" "$SUBNET_MASK" "$IP_FILE"
        echo -e "\n${YELLOW}Done!${NC}"
        ;;
    scan)
        if [ ! -f "$IP_FILE" ]; then
            ping_sweep "$start_ip_dec" "$end_ip_dec" "$SUBNET" "$SUBNET_MASK" "$IP_FILE"
        fi
        scanner "$IP_FILE" "$SUBNET_FILENAME" "$verbosity"
        echo -e "\n${YELLOW}Done!${NC}"
        ;;
    *)
        usage
        ;;
esac
