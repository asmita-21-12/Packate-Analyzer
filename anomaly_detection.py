
import pyshark
from datetime import datetime
from rules import rules

# Define counters globally
counters = {
    'icmp': 0,
    'port': 0,
    'syn': 0,
    'ip': 0,
    'connection': 0,
    'lateral_movement': 0,
    'dhcp': 0,
    'arp': 0,
    'reconnaissance': 0,
    'dhos': 0,
    'outbound': 0,
    'volume': 0,
    'pattern': 0,
    'bandwidth': 0,
    'vpn': 0,
    'p2p': 0,
    'worms': 0,
    'file_transfer': 0,
    'email_exfiltration': 0,
    'data_hoarding': 0,
    'dns': 0,
    'tcp_flags': 0,
    'encryption': 0,
    'services': 0,
    'suspicious_patterns': 0
}

def analyze_packet(packet):
    """
    Extract relevant information from a packet for anomaly detection.
    """
    packet_info = {
        'protocol': packet.highest_layer,
        'src_ip': packet.ip.src if hasattr(packet, 'ip') else None,
        'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
        'length': packet.length if hasattr(packet, 'length') else None,
        'data': {}
    }
    
    if hasattr(packet, 'dns'):
        packet_info['data']['domain'] = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else None
        packet_info['data']['TYPE'] = packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else None
    
    if hasattr(packet, 'tcp'):
        packet_info['data']['port'] = packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else None
        packet_info['data']['flags'] = packet.tcp.flags_string if hasattr(packet.tcp, 'flags_string') else None
    
    if hasattr(packet, 'icmp'):
        packet_info['data']['type'] = packet.icmp.type if hasattr(packet.icmp, 'type') else None
    
    return packet_info

def extract_packet_info(packet):
    """
    Extract detailed information from a packet for the full report.
    """
    packet_info = {
        'number': packet.number,
        'timestamp': packet.sniff_time,
        'src_ip': packet.ip.src if hasattr(packet, 'ip') else None,
        'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
        'protocol': packet.highest_layer,
        'length': packet.length if hasattr(packet, 'length') else None,
        'data': {}
    }
    
    if hasattr(packet, 'dns'):
        packet_info['data']['domain'] = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else None
        packet_info['data']['TYPE'] = packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else None
    
    if hasattr(packet, 'tcp'):
        packet_info['data']['port'] = packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else None
        packet_info['data']['flags'] = packet.tcp.flags_string if hasattr(packet.tcp, 'flags_string') else None
    
    if hasattr(packet, 'icmp'):
        packet_info['data']['type'] = packet.icmp.type if hasattr(packet.icmp, 'type') else None
    
    return packet_info

def detect_anomalies(pcap_file):
    """
    Detect anomalies in a pcap file using defined rules and handlers.
    """
    capture = None
    anomalies = []
    packets = []
    
    rule_counter_mapping = {
        'excessive_icmp_traffic': 'icmp',
        'port_scanning': 'port',
        'large_number_of_syn_packets': 'syn',
        'ip_address_spoofing': 'ip',
        'high_number_of_connections': 'connection',
        'lateral_movement': 'lateral_movement',
        'rogue_dhcp_server': 'dhcp',
        'arp_spoofing': 'arp',
        'network_reconnaissance': 'reconnaissance',
        'ddos_traffic': 'dhos',
        'suspicious_outbound_traffic': 'outbound',
        'abnormal_traffic_volume': 'volume',
        'abnormal_traffic_patterns': 'pattern',
        'anomalous_bandwidth_usage': 'bandwidth',
        'suspicious_vpn_usage': 'vpn',
        'unexpected_p2p_traffic': 'p2p',
        'network_worms': 'worms',
        'data_exfiltration': 'file_transfer',
        'email_exfiltration': 'email_exfiltration',
        'data_hoarding': 'data_hoarding',
        'unusual_dns_queries': 'dns',
        'abnormal_tcp_flags': 'tcp_flags',
        'unexpected_encryption': 'encryption',
        'unauthorized_network_services': 'services',
        'suspicious_patterns': 'suspicious_patterns',
        'obsolete_protocols': 'suspicious_patterns'
    }

    try:
        capture = pyshark.FileCapture(pcap_file)
        for packet in capture:
            try:
                packets.append(packet)  # Store packet for later reporting
                packet_info = analyze_packet(packet)

                for rule_name, rule_func in rules.items():
                    try:
                        counter_name = rule_counter_mapping.get(rule_name, None)
                        if counter_name:
                            is_anomalous = rule_func(packet_info, counters[counter_name])
                        else:
                            is_anomalous = rule_func(packet_info)
                        
                        if is_anomalous:
                            anomalies.append({
                                'packet_number': packet.number,
                                'timestamp': packet.sniff_time,
                                'src_ip': packet_info['src_ip'],
                                'dst_ip': packet_info['dst_ip'],
                                'anomaly_type': rule_name,
                                'details': packet_info
                            })
                    except Exception as e:
                        print(f"Error applying rule '{rule_name}': {str(e)}")

            except Exception as e:
                print(f"Error processing packet {packet.number}: {str(e)}")
        
    except Exception as e:
        print(f"Error reading pcap file {pcap_file}: {str(e)}")
    
    return packets, anomalies

def generate_full_report(packets, anomalies):
    """
    Generate a detailed report of all analyzed packets, including those flagged as anomalies,
    and save it as a .txt file.
    """
    report_file = 'full_anomaly_report.txt'
    with open(report_file, 'w') as f:
        f.write("Full Packet Analysis Report\n")
        f.write("===========================\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Packets Analyzed: {len(packets)}\n")
        f.write(f"Total Anomalies Detected: {len(anomalies)}\n\n")
        
        # Section for all packets
        f.write("All Packet Details\n")
        f.write("------------------\n\n")
        for i, packet in enumerate(packets, start=1):
            packet_info = extract_packet_info(packet)
            f.write(f"Packet {i}:\n")
            f.write(f"  Packet Number: {packet_info['number']}\n")
            f.write(f"  Timestamp: {packet_info['timestamp']}\n")
            f.write(f"  Source IP: {packet_info['src_ip']}\n")
            f.write(f"  Destination IP: {packet_info['dst_ip']}\n")
            f.write(f"  Protocol: {packet_info['protocol']}\n")
            f.write(f"  Length: {packet_info['length']}\n")
            if 'data' in packet_info:
                f.write("  Data Details:\n")
                for key, value in packet_info['data'].items():
                    f.write(f"    {key}: {value}\n")
            f.write("\n")
        
        # Section for anomalies
        f.write("Anomalies Detected\n")
        f.write("------------------\n\n")
        for i, anomaly in enumerate(anomalies, start=1):
            f.write(f"Anomaly {i}:\n")
            f.write(f"  Packet Number: {anomaly['packet_number']}\n")
            f.write(f"  Timestamp: {anomaly['timestamp']}\n")
            f.write(f"  Source IP: {anomaly['src_ip']}\n")
            f.write(f"  Destination IP: {anomaly['dst_ip']}\n")
            f.write(f"  Anomaly Type: {anomaly['anomaly_type']}\n")
            f.write("  Details:\n")
            f.write(f"    Protocol: {anomaly['details']['protocol']}\n")
            f.write(f"    Source IP: {anomaly['details']['src_ip']}\n")
            f.write(f"    Destination IP: {anomaly['details']['dst_ip']}\n")
            if 'data' in anomaly['details']:
                f.write("    Data Details:\n")
                for key, value in anomaly['details']['data'].items():
                    f.write(f"      {key}: {value}\n")
            f.write("\n")
    
    print(f"Report generated: {report_file}")

# Define your anomaly detection rules here
rules = {
    # Define your anomaly detection rules here
}

# Example usage
pcap_file = r"C:\Users\Karan\Desktop\\5.SEM\SIH\0.network_analysis_tool\capture.pcap"
packets, anomalies = detect_anomalies(pcap_file)
generate_full_report(packets, anomalies)

