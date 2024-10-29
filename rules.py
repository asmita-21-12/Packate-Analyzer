import time
import json
# Define the path to your output text file
output_file = 'anomalies.json'

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []  # Return an empty list if the file does not exist

def write_to_file(message):
    anomalies = read_json_file(output_file)
    anomalies.append(message)
    with open(output_file, 'w') as file:
        json.dump(anomalies, file, indent=4)

def handle_unusual_dns_queries(packet):
    message = {"type": "Unusual DNS Query", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_dns_tunneling(packet):
    message = {"type": "DNS Tunneling", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_dns_amplification_attack(packet):
    message = {"type": "DNS Amplification Attack", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_excessive_icmp_traffic(packet):
    message = {"type": "Excessive ICMP Traffic", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_port_scanning(packet):
    message = {"type": "Port Scanning", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_unusual_port_usage(packet):
    message = {"type": "Unusual Port Usage", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_unexpected_protocols(packet):
    message = {"type": "Unexpected Protocol", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_obsolete_protocols(packet):
    message = {"type": "Obsolete Protocol", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_unexpected_encryption(packet):
    message = {"type": "Unexpected Encryption", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_unauthorized_network_services(packet):
    message = {"type": "Unauthorized Network Service", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_abnormal_tcp_flags(packet):
    message = {"type": "Abnormal TCP Flags", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_large_number_of_syn_packets(packet):
    message = {"type": "Large Number of SYN Packets", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_ip_address_spoofing(packet):
    message = {"type": "IP Address Spoofing", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_high_number_of_connections(packet):
    message = {"type": "High Number of Connections", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_lateral_movement(packet):
    message = {"type": "Lateral Movement", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_rogue_dhcp_server(packet):
    message = {"type": "Rogue DHCP Server", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_arp_spoofing(packet):
    message = {"type": "ARP Spoofing", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_network_reconnaissance(packet):
    message = {"type": "Network Reconnaissance", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_data_exfiltration(packet):
    message = {"type": "Data Exfiltration", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_unusual_file_transfers(packet):
    message = {"type": "Unusual File Transfer", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_email_exfiltration(packet):
    message = {"type": "Email Exfiltration", "packet": packet, "timestamp": time.time()}
    write_to_file(message)

def handle_data_hoarding(packet):
    message = {"type": "Data Hoarding", "packet": packet, "timestamp": time.time()}
    write_to_file(message)


# Initialize counters and sets
icmp_counter = {}
port_access = {}
syn_counter = {}
ip_set = set()
connection_counter = {}
lateral_movement_counter = {}
dhcp_servers = set()
arp_table = {}
reconnaissance_counter = {}
file_transfer_counter = {}
email_exfiltration_counter = {}
data_hoarding_counter = {}

# Detection functions
def is_unusual_dns_query(packet):
    if packet.get('protocol') == 'DNS':
        data = packet.get('data', {})
        if len(data.get('query', '')) > 512 or 'TYPE' in data:
            return True
    return False

def is_dns_tunneling(packet):
    if packet.get('protocol') == 'DNS':
        data = packet.get('data', {})
        if len(data.get('domain', '')) > 1000:
            return True
    return False

def is_dns_amplification_attack(packet):
    if packet.get('protocol') == 'DNS':
        length = int(packet.get('length', 0))
        if length > 4096:
            return True
    return False

def is_excessive_icmp_traffic(packet, icmp_counter):
    if packet.get('protocol') == 'ICMP':
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in icmp_counter:
                icmp_counter[src_ip] = 0
            icmp_counter[src_ip] += 1
            if icmp_counter[src_ip] > 100:  # Threshold for excessive ICMP traffic
                return True
    return False

def is_port_scanning(packet, port_access):
    if packet.get('protocol') == 'TCP':
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in port_access:
                port_access[src_ip] = set()
            data = packet.get('data', {})
            if 'port' in data:
                port = int(data['port'])
                port_access[src_ip].add(port)
                if len(port_access[src_ip]) > 10:  # Threshold for port scanning
                    return True
    return False

def is_unusual_port_usage(packet):
    if packet.get('protocol') == 'TCP':
        data = packet.get('data', {})
        if 'port' in data:
            port = int(data['port'])
            if not (1 <= port <= 1024 or 49152 <= port <= 65535):
                return True
    return False

def is_unexpected_protocols(packet):
    if packet.get('protocol') not in ['TCP', 'UDP', 'ICMP', 'DNS']:
        return True
    return False

def is_obsolete_protocols(packet):
    if packet.get('protocol') in ['FTP', 'TELNET']:
        return True
    return False

def is_unexpected_encryption(packet):
    data = packet.get('data', {})
    if 'encryption' in data and data['encryption'] not in ['AES', 'TLS']:
        return True
    return False

def is_unauthorized_network_services(packet):
    data = packet.get('data', {})
    if 'service' in data and data['service'] not in ['HTTP', 'HTTPS', 'SSH']:
        return True
    return False

def is_abnormal_tcp_flags(packet):
    if packet.get('protocol') == 'TCP':
        flags = packet.get('data', {}).get('flags', '')
        if 'SYN' in flags and 'ACK' not in flags:
            return True
        if 'RST' in flags and 'SYN' not in flags:
            return True
    return False

def is_large_number_of_syn_packets(packet, syn_counter):
    if packet.get('protocol') == 'TCP':
        if 'SYN' in packet.get('data', {}).get('flags', ''):
            src_ip = packet.get('src_ip')
            if src_ip:
                if src_ip not in syn_counter:
                    syn_counter[src_ip] = 0
                syn_counter[src_ip] += 1
                if syn_counter[src_ip] > 100:  # Threshold for SYN packets
                    return True
    return False

def is_ip_address_spoofing(packet, ip_set):
    src_ip = packet.get('src_ip')
    if src_ip:
        if src_ip in ip_set:
            return True
        ip_set.add(src_ip)
    return False

def is_high_number_of_connections(packet, connection_counter):
    if packet.get('protocol') == 'TCP':
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in connection_counter:
                connection_counter[src_ip] = set()
            data = packet.get('data', {})
            if 'port' in data:
                port = int(data['port'])
                connection_counter[src_ip].add(port)
                if len(connection_counter[src_ip]) > 50:  # Threshold for connections
                    return True
    return False

def is_lateral_movement(packet, lateral_movement_counter):
    if packet.get('protocol') == 'TCP':
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        if dst_ip:
            if dst_ip.startswith('192.168.') or dst_ip.startswith('10.'):
                if src_ip:
                    if src_ip not in lateral_movement_counter:
                        lateral_movement_counter[src_ip] = set()
                    lateral_movement_counter[src_ip].add(dst_ip)
                    if len(lateral_movement_counter[src_ip]) > 5:  # Threshold for lateral movement
                        return True
    return False

def is_rogue_dhcp_server(packet, dhcp_servers):
    if packet.get('protocol') == 'UDP' and 'dhcp' in packet.get('data', {}):
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in dhcp_servers:
                dhcp_servers.add(src_ip)
                if len(dhcp_servers) > 1:  # Multiple DHCP servers detected
                    return True
    return False

def is_arp_spoofing(packet, arp_table):
    if packet.get('protocol') == 'ARP':
        src_ip = packet.get('src_ip')
        src_mac = packet.get('src_mac')
        if src_ip and src_mac:
            if src_ip not in arp_table:
                arp_table[src_ip] = src_mac
            elif arp_table[src_ip] != src_mac:
                return True
    return False

def is_network_reconnaissance(packet, reconnaissance_counter):
    if packet.get('protocol') in ['ICMP', 'TCP', 'UDP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in reconnaissance_counter:
                reconnaissance_counter[src_ip] = 0
            reconnaissance_counter[src_ip] += 1
            if reconnaissance_counter[src_ip] > 200:  # Threshold for reconnaissance
                return True
    return False


# **4. Traffic Volume and Pattern Anomalies**

# rules.py

# Define functions for new anomalies

def is_ddos_traffic(packet, traffic_counter):
    if packet.get('protocol') in ['TCP', 'UDP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in traffic_counter:
                traffic_counter[src_ip] = 0
            traffic_counter[src_ip] += 1
            if traffic_counter[src_ip] > 1000:  # Threshold for DDoS traffic
                return True
    return False

def is_suspicious_outbound_traffic(packet, outbound_counter):
    if packet.get('direction') == 'outbound':
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in outbound_counter:
                outbound_counter[src_ip] = 0
            outbound_counter[src_ip] += 1
            if outbound_counter[src_ip] > 500:  # Threshold for suspicious outbound traffic
                return True
    return False

def is_abnormal_traffic_volume(packet, volume_counter):
    if packet.get('protocol') in ['TCP', 'UDP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in volume_counter:
                volume_counter[src_ip] = 0
            volume_counter[src_ip] += int(packet.get('size', 0))
            if volume_counter[src_ip] > 1000000:  # Threshold for abnormal traffic volume
                return True
    return False

def is_abnormal_traffic_patterns(packet, pattern_counter):
    if packet.get('protocol') in ['TCP', 'UDP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in pattern_counter:
                pattern_counter[src_ip] = []
            pattern_counter[src_ip].append(packet.get('size', 0))
            if len(pattern_counter[src_ip]) > 10 and len(set(pattern_counter[src_ip])) < 2:
                return True
    return False

def is_anomalous_bandwidth_usage(packet, bandwidth_counter):
    if packet.get('protocol') in ['TCP', 'UDP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in bandwidth_counter:
                bandwidth_counter[src_ip] = 0
            bandwidth_counter[src_ip] += int(packet.get('size', 0))
            if bandwidth_counter[src_ip] > 500000:  # Threshold for anomalous bandwidth usage
                return True
    return False

def is_suspicious_vpn_usage(packet, vpn_counter):
    if packet.get('protocol') == 'UDP' and 'vpn' in packet.get('data', {}):
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in vpn_counter:
                vpn_counter[src_ip] = 0
            vpn_counter[src_ip] += 1
            if vpn_counter[src_ip] > 100:  # Threshold for suspicious VPN usage
                return True
    return False

def is_unexpected_p2p_traffic(packet, p2p_counter):
    if packet.get('protocol') in ['TCP', 'UDP'] and 'p2p' in packet.get('data', {}):
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in p2p_counter:
                p2p_counter[src_ip] = 0
            p2p_counter[src_ip] += 1
            if p2p_counter[src_ip] > 50:  # Threshold for unexpected P2P traffic
                return True
    return False

def is_network_worm(packet, worm_counter, time_window=60, threshold=200):
    current_time = time.time()
    protocol = packet.get('protocol')
    
    if protocol in ['TCP', 'UDP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            # Initialize worm_counter entry for src_ip if not present
            if src_ip not in worm_counter:
                worm_counter[src_ip] = []
            
            # Add current time to the list of packet times
            worm_counter[src_ip].append(current_time)
            
            # Remove packet times outside of the time window
            worm_counter[src_ip] = [t for t in worm_counter[src_ip] if current_time - t <= time_window]
            
            # Check if the number of packets within the time window exceeds the threshold
            if len(worm_counter[src_ip]) > threshold:
                return True
    
    return False

###5.File Transfer and Data Exfiltration

def is_data_exfiltration(packet):
    if packet.get('protocol') in ['HTTP', 'HTTPS', 'FTP', 'SFTP']:
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        if src_ip and dst_ip:
            data_size = int(packet.get('length', 0))
            if data_size > 1000000:  # Threshold for large data transfers
                return True
    return False

def is_unusual_file_transfers(packet, file_transfer_counter):
    if packet.get('protocol') in ['FTP', 'SFTP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in file_transfer_counter:
                file_transfer_counter[src_ip] = 0
            file_transfer_counter[src_ip] += int(packet.get('length', 0))
            if file_transfer_counter[src_ip] > 5000000:  # Threshold for file transfers
                return True
    return False

def is_email_exfiltration(packet, email_exfiltration_counter):
    if packet.get('protocol') == 'SMTP':
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in email_exfiltration_counter:
                email_exfiltration_counter[src_ip] = 0
            email_exfiltration_counter[src_ip] += int(packet.get('length', 0))
            if email_exfiltration_counter[src_ip] > 1000000:  # Threshold for email size
                return True
    return False

def is_data_hoarding(packet, data_hoarding_counter):
    if packet.get('protocol') in ['HTTP', 'HTTPS', 'FTP', 'SFTP']:
        src_ip = packet.get('src_ip')
        if src_ip:
            if src_ip not in data_hoarding_counter:
                data_hoarding_counter[src_ip] = 0
            data_hoarding_counter[src_ip] += int(packet.get('length', 0))
            if data_hoarding_counter[src_ip] > 10000000:  # Threshold for hoarded data
                return True
    return False
# Update the rules dictionary with new functions




# Rule definitions
rules = {
    'unusual_dns_queries': is_unusual_dns_query,
    'dns_tunneling': is_dns_tunneling,
    'dns_amplification_attack': is_dns_amplification_attack,
    'excessive_icmp_traffic': is_excessive_icmp_traffic,
    'port_scanning': is_port_scanning,
    'unusual_port_usage': is_unusual_port_usage,
    'unexpected_protocols': is_unexpected_protocols,
    'obsolete_protocols': is_obsolete_protocols,
    'unexpected_encryption': is_unexpected_encryption,
    'unauthorized_network_services': is_unauthorized_network_services,
    'abnormal_tcp_flags': is_abnormal_tcp_flags,
    'large_number_of_syn_packets': is_large_number_of_syn_packets,
    'ip_address_spoofing': is_ip_address_spoofing,
    'high_number_of_connections': is_high_number_of_connections,
    'lateral_movement': is_lateral_movement,
    'rogue_dhcp_server': is_rogue_dhcp_server,
    'arp_spoofing': is_arp_spoofing,
    'network_reconnaissance': is_network_reconnaissance,
    'ddos_traffic': is_ddos_traffic,
    'suspicious_outbound_traffic': is_suspicious_outbound_traffic,
    'abnormal_traffic_volume': is_abnormal_traffic_volume,
    'abnormal_traffic_patterns': is_abnormal_traffic_patterns,
    'anomalous_bandwidth_usage': is_anomalous_bandwidth_usage,
    'suspicious_vpn_usage': is_suspicious_vpn_usage,
    'unexpected_p2p_traffic': is_unexpected_p2p_traffic,
    'network_worms': is_network_worm,
    'data_exfiltration': is_data_exfiltration,
    'unusual_file_transfers': is_unusual_file_transfers,
    'email_exfiltration': is_email_exfiltration,
    'data_hoarding': is_data_hoarding
}

# Process packet example
def process_packet(packet):
    global icmp_counter, port_access, syn_counter, ip_set
    global connection_counter, lateral_movement_counter, dhcp_servers
    global arp_table, reconnaissance_counter, file_transfer_counter
    global email_exfiltration_counter, data_hoarding_counter

    # Check each rule
    for rule_name, rule_func in rules.items():
        if rule_name == 'excessive_icmp_traffic':
            if rule_func(packet, icmp_counter):
                handle_excessive_icmp_traffic(packet)
        elif rule_name == 'port_scanning':
            if rule_func(packet, port_access):
                handle_port_scanning(packet)
        elif rule_name == 'large_number_of_syn_packets':
            if rule_func(packet, syn_counter):
                handle_large_number_of_syn_packets(packet)
        elif rule_name == 'ip_address_spoofing':
            if rule_func(packet, ip_set):
                handle_ip_address_spoofing(packet)
        elif rule_name == 'high_number_of_connections':
            if rule_func(packet, connection_counter):
                handle_high_number_of_connections(packet)
        elif rule_name == 'lateral_movement':
            if rule_func(packet, lateral_movement_counter):
                handle_lateral_movement(packet)
        elif rule_name == 'rogue_dhcp_server':
            if rule_func(packet, dhcp_servers):
                handle_rogue_dhcp_server(packet)
        elif rule_name == 'arp_spoofing':
            if rule_func(packet, arp_table):
                handle_arp_spoofing(packet)
        elif rule_name == 'network_reconnaissance':
            if rule_func(packet, reconnaissance_counter):
                handle_network_reconnaissance(packet)
        elif rule_name == 'data_exfiltration':
            if rule_func(packet):
                handle_data_exfiltration(packet)
        elif rule_name == 'unusual_file_transfers':
            if rule_func(packet, file_transfer_counter):
                handle_unusual_file_transfers(packet)
        elif rule_name == 'email_exfiltration':
            if rule_func(packet, email_exfiltration_counter):
                handle_email_exfiltration(packet)
        elif rule_name == 'data_hoarding':
            if rule_func(packet, data_hoarding_counter):
                handle_data_hoarding(packet)
        else:
            # Handle any other rules that are not explicitly listed
            if rule_func(packet):
                globals().get(f'handle_{rule_name}', lambda x: None)(packet)
