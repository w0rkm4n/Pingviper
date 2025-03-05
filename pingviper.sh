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
    echo -e "\n${NC}"
    echo -e "Usage: pingviper.sh [-h] [-f <file>] [-s <Subnet>] [-m <Mask>]\n"
    exit 1
}

ip_to_dec() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$((a << 24 | b << 16 | c << 8 | d))"
}

dec_to_ip() {
    local dec="$1"
    echo "$((dec >> 24 & 255)).$((dec >> 16 & 255)).$((dec >> 8 & 255)).$((dec & 255))"
}

calculate_range() {
    local subnet="$1"
    local mask="$2"

    local subnet_dec=$(ip_to_dec "$subnet")
    local host_bits=$((32 - mask))
    local total_ips=$((1 << host_bits))
    local start_ip_dec=$((subnet_dec & ~((1 << host_bits) - 1)))
    local end_ip_dec=$((start_ip_dec + total_ips - 1))

    echo "$start_ip_dec" "$end_ip_dec"
}

ping_sweep() {
    local start_ip_dec="$1"
    local end_ip_dec="$2"
    local subnet="$3"
    local mask="$4"
    local ip_file="$5"

    local broadcast_ip=$(dec_to_ip "$end_ip_dec")

    echo -e "${BLUE}[*]${NC} Running ping sweep on ${subnet}/${mask}..."
    > "$ip_file"
    temp_file=$(mktemp)

    for ((ip_dec=start_ip_dec; ip_dec<=end_ip_dec; ip_dec++)); do
        ip=$(dec_to_ip "$ip_dec")
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

    wait
    cat "$temp_file" >> "$ip_file"
    rm "$temp_file"
    sed -i '/^$/d' "$ip_file"
    sort "$ip_file" | uniq > ip.tmp
    mv ip.tmp "$ip_file"

    IP_COUNT=$(wc -l < "$ip_file")
    if [ "$IP_COUNT" -eq 0 ]; then
        echo -e "${RED}[-]${NC} No active IP addresses found. Moving to the next subnet."
        rm "$ip_file"
        return
    fi

    echo -e "\n${GREEN}[+]${NC} Number of IP addresses found: $IP_COUNT"
    echo -e "${GREEN}[+]${NC} Ping sweep completed. Results saved to $ip_file."
}

while getopts "f:s:m:" opt; do
    case $opt in
        f) FILE=$OPTARG ;;
        s) SUBNET=$OPTARG ;;
        m) SUBNET_MASK=$OPTARG ;;
        *) usage ;;
    esac
done

if [ -n "$FILE" ]; then
    if [ ! -f "$FILE" ]; then
        echo -e "${RED}[-]${NC} File not found: $FILE"
        exit 1
    fi
    while IFS=/ read -r subnet mask; do
        echo -e "${BLUE}[*]${NC} Processing subnet: $subnet/$mask"
        SUBNET_FILENAME=$(echo "$subnet" | tr '.' '_')
        IP_FILE="${SUBNET_FILENAME}-ip_addresses.txt"
        read start_ip_dec end_ip_dec <<< $(calculate_range "$subnet" "$mask")
        ping_sweep "$start_ip_dec" "$end_ip_dec" "$subnet" "$mask" "$IP_FILE"
    done < "$FILE"
elif [ -n "$SUBNET" ] && [ -n "$SUBNET_MASK" ]; then
    SUBNET_FILENAME=$(echo "$SUBNET" | tr '.' '_')
    IP_FILE="${SUBNET_FILENAME}-ip_addresses.txt"
    read start_ip_dec end_ip_dec <<< $(calculate_range "$SUBNET" "$SUBNET_MASK")
    ping_sweep "$start_ip_dec" "$end_ip_dec" "$SUBNET" "$SUBNET_MASK" "$IP_FILE"
else
    usage
fi

echo -e "\n${YELLOW}Done!${NC}"
