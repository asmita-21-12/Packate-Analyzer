


import win32evtlog
import re
import json
from collections import defaultdict

# Constants for anomaly detection thresholds
FAILED_LOGIN_THRESHOLD = 5  # Number of failed attempts in the time window
ACCOUNT_LOCKOUT_THRESHOLD = 3  # Number of lockouts
ROLE_CHANGE_SUSPICION = 'Admin'  # Example role change to detect

# Function to check for authentication and access control anomalies
def check_authentication_anomalies(log_data):
    failed_login_attempts = defaultdict(list)  # Stores failed attempts by IP address
    password_changes = defaultdict(list)  # Stores password changes by user
    account_lockouts = defaultdict(int)  # Counts lockouts by account
    role_changes = []  # Stores role changes
    
    # Analyze logs for anomalies
    for entry in log_data:
        message = entry.get('Message', '')
        timestamp = entry.get('Timestamp', '')

        # Brute Force Attacks
        if 'failed login' in message.lower():
            ip_match = re.search(r'from IP: (\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                ip = ip_match.group(1)
                failed_login_attempts[ip].append(timestamp)
                # Check if failed login attempts exceed threshold
                if len(failed_login_attempts[ip]) > FAILED_LOGIN_THRESHOLD:
                    print(f'Brute Force Attack detected: Multiple failed login attempts from IP {ip}.')

        # Password Changes
        if 'password changed' in message.lower():
            user_match = re.search(r'User: (\w+)', message)
            if user_match:
                user = user_match.group(1)
                password_changes[user].append(timestamp)
                # Check if password change is unusual (ignoring exact time here)
                if len(password_changes[user]) > 1:
                    print(f'Unusual password change detected for User: {user}.')

        # Unusual Account Lockouts
        if 'account locked out' in message.lower():
            account_match = re.search(r'Account: (\w+)', message)
            if account_match:
                account = account_match.group(1)
                account_lockouts[account] += 1
                if account_lockouts[account] > ACCOUNT_LOCKOUT_THRESHOLD:
                    print(f'Unusual account lockouts detected for Account: {account}.')

        # Suspicious Role Changes
        if 'role changed' in message.lower():
            role_change_match = re.search(r'User: (\w+) to (\w+)', message)
            if role_change_match:
                user = role_change_match.group(1)
                role = role_change_match.group(2)
                if role == ROLE_CHANGE_SUSPICION:
                    role_changes.append({'User': user, 'Role': role, 'Timestamp': timestamp})
                    print(f'Suspicious role change detected: User: {user} role changed to {role}.')

    return role_changes  # Return detected role changes for further analysis or reporting

# Function to check for system anomalies
def check_system_anomalies(log_data):
    service_restarts = defaultdict(list)  # Stores service restarts by service name
    resource_usage_spikes = []  # Stores detected resource usage spikes
    unauthorized_installations = []  # Stores unauthorized software installations
    configuration_changes = []  # Stores system configuration changes
    
    for entry in log_data:
        message = entry.get('Message', '')
        timestamp = entry.get('Timestamp', '')

        # Unexpected Service Restarts
        if 'service restarted unexpectedly' in message.lower():
            service_match = re.search(r'Service X', message)
            if service_match:
                service_name = service_match.group(0)
                service_restarts[service_name].append(timestamp)
                # Example threshold check, adjust as needed
                if len(service_restarts[service_name]) > 3:
                    print(f'Unexpected service restarts detected for Service: {service_name}.')

        # Resource Usage Spikes
        if 'cpu usage spiked' in message.lower() or 'memory usage spiked' in message.lower() or 'disk usage spiked' in message.lower():
            resource_usage_spikes.append({'Timestamp': timestamp, 'Message': message})
            print(f'Resource usage spike detected: {message}.')

        # Unauthorized Software Installations
        if 'software installation attempt' in message.lower() and 'unapproved' in message.lower():
            unauthorized_installations.append({'Timestamp': timestamp, 'Message': message})
            print(f'Unauthorized software installation detected: {message}.')

        # Configuration Changes
        if 'system configuration changed' in message.lower():
            configuration_change_match = re.search(r'System configuration changed: (.+)', message)
            if configuration_change_match:
                change_details = configuration_change_match.group(1)
                configuration_changes.append({'Timestamp': timestamp, 'Change Details': change_details})
                print(f'System configuration change detected: {change_details}.')

# Function to analyze Windows Event Logs
def analyze_windows_event_logs(log_type):
    server = 'localhost'  # Local machine
    log = log_type  # E.g., 'System', 'Application', 'Security'
    
    hand = win32evtlog.OpenEventLog(server, log)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    log_data = []

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        
        for event in events:
            event_id = event.EventID
            event_time = event.TimeGenerated.Format()
            event_source = event.SourceName
            event_type = event.EventType
            event_message = event.StringInserts

            # Initialize default values
            suspicious = False
            msi_detected = False
            anomaly = False
            detection_method = ''
            anomaly_details = ''

            # Simple check for suspicious activities and .msi files in system logs
            if event_type in [win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE]:
                suspicious = True

            if event_message:
                message = ' '.join(event_message)
                if re.search(r'failed|unauthorized|error|denied|invalid', message, re.IGNORECASE):
                    suspicious = True
                if re.search(r'\.msi', message, re.IGNORECASE):
                    msi_detected = True

            # Additional anomaly detection logic
            if event_id == 37 and suspicious:
                anomaly = True
                detection_method = 'Event ID specific rule'
                anomaly_details = 'Event ID 37 with suspicious activity detected.'

            log_data.append({
                'Event ID': event_id,
                'Timestamp': event_time,
                'Source': event_source,
                'Event Type': event_type,
                'Message': message,
                'Suspicious': suspicious,
                'MSI Detected': msi_detected,
                'Anomaly': anomaly,
                'Detection Method': detection_method,
                'Anomaly Details': anomaly_details
            })

    win32evtlog.CloseEventLog(hand)
    
    # Check for system anomalies
    check_system_anomalies(log_data)
    
    return log_data

# Function to save log data to a JSON file
def save_to_json(log_data, output_file):
    with open(output_file, 'w') as f:
        json.dump(log_data, f, indent=4)

# Main function
def main():
    log_type = input("Enter the type of log to analyze (System, Application, Security): ")
    output_file = f"{log_type}_log_analysis.json"

    print(f"Analyzing {log_type} logs...")
    log_data = analyze_windows_event_logs(log_type)

    print(f"Checking for authentication and access control anomalies...")
    anomalies = check_authentication_anomalies(log_data)
    
    print(f"Saving results to {output_file}...")
    save_to_json(log_data, output_file)
    
    print("Detected Role Changes:", anomalies)
    print("Analysis complete.")

if __name__ == "__main__":
    main()






















# import os
# import re
# import hashlib
# import multiprocessing
# import pytz  # For timezone handling
# from datetime import datetime
# from concurrent.futures import ThreadPoolExecutor
# from collections import defaultdict
# import xml.etree.ElementTree as ET
# import pandas as pd
# import matplotlib.pyplot as plt
# import glob
# # from evtx import PyEvtxParser  # Ensure evtx is installed

# # Constants and configurations
# TEXT_LOG_FILES = [
#     "C:/Windows/Logs/WindowsUpdate/WindowsUpdate.log",
#     "C:/inetpub/logs/LogFiles/W3SVC1/*.log"
# ]
# EVTX_LOG_FILES = [
#     "C:/Windows/System32/winevt/Logs/System.evtx",
#     "C:/Windows/System32/winevt/Logs/Application.evtx"
# ]
# OUTPUT_REPORT = "log_analysis_report.txt"
# HASH_OUTPUT = "log_hashes.txt"
# KEYWORDS = ["error", "fail", "unauthorized", "login", "shutdown", "reboot"]

# def hash_file(filename):
#     """Create a SHA-256 hash of the given file."""
#     sha256 = hashlib.sha256()
#     try:
#         with open(filename, 'rb') as f:
#             for block in iter(lambda: f.read(4096), b""):
#                 sha256.update(block)
#     except PermissionError:
#         print(f"[!] Permission denied: {filename}")
#         return None
#     return sha256.hexdigest()

# def save_hashes(log_files, output_file):
#     """Save the hashes of the logs for integrity verification."""
#     with open(output_file, 'w') as f:
#         for log_file in log_files:
#             if os.path.exists(log_file):
#                 file_hash = hash_file(log_file)
#                 if file_hash:
#                     f.write(f"{log_file}: {file_hash}\n")
#                 else:
#                     f.write(f"{log_file}: PERMISSION DENIED\n")
#             else:
#                 f.write(f"{log_file}: FILE NOT FOUND\n")

# def read_text_log_file(log_file):
#     """Read the text log file and return its content as a list of lines."""
#     with open(log_file, 'r') as f:
#         return f.readlines()

# def parse_text_log_line(line):
#     """Parse a single log line and extract timestamp, source, and message."""
#     match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(.*)', line)
#     if match:
#         timestamp_str, source, message = match.groups()
#         timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
#         return timestamp, source, message
#     return None, None, None

# def filter_logs_by_keywords(log_lines, keywords):
#     """Filter log lines that contain any of the specified keywords."""
#     return [line for line in log_lines if any(keyword in parse_text_log_line(line)[2].lower() for keyword in keywords)]

# def correlate_events(log_lines):
#     """Correlate events based on timestamps and sources."""
#     correlated_events = defaultdict(list)
#     for line in log_lines:
#         timestamp, source, message = parse_text_log_line(line)
#         if timestamp and source:
#             correlated_events[timestamp].append((source, message))
#     return correlated_events

# def detect_anomalies(log_lines):
#     """Detect anomalies in the log lines."""
#     return [line for line in log_lines if "failed" in parse_text_log_line(line)[2].lower() or "unauthorized" in parse_text_log_line(line)[2].lower()]

# def parse_evtx_log(log_file):
#     """Parse .evtx log file (Windows Event Logs) and extract relevant information."""
#     try:
#         import Evtx.Evtx as evtx
#         log_lines = []
#         with evtx.Evtx(log_file) as log:
#             for record in log.records():
#                 event_xml = ET.fromstring(record.xml())
#                 timestamp = event_xml.find("System/TimeCreated").attrib['SystemTime']
#                 source = event_xml.find("System/Provider").attrib['Name']
#                 message = event_xml.find("EventData").text
#                 log_lines.append(f"{timestamp} {source} {message}")
#         return log_lines
#     except ImportError:
#         raise ImportError("Please install python-evtx to parse .evtx files.")
#     except PermissionError:
#         print(f"[!] Permission denied: {log_file}")
#         return []
#     except Exception as e:
#         print(f"[!] An unexpected error occurred: {e}")
#         return []

# def parse_log_line(log_line, log_type, timezone):
#     """
#     Parse a single log line based on its type and normalize the timestamp to the specified timezone.
#     """
#     patterns = {
#         'apache': r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+)',
#         'nginx': r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+)',
#         # Add more log types as needed
#     }

#     pattern = patterns.get(log_type)
#     if pattern:
#         match = re.match(pattern, log_line)
#         if match:
#             data = match.groupdict()
#             # Convert datetime to the specified timezone
#             log_time = datetime.strptime(data['datetime'], '%d/%b/%Y:%H:%M:%S %z')
#             data['datetime'] = log_time.astimezone(pytz.timezone(timezone))
#             return data
#     return None

# def process_log_batch(log_batch, log_type, timezone):
#     """
#     Process a batch of log lines.
#     """
#     return [parse_log_line(log_line, log_type, timezone) for log_line in log_batch if parse_log_line(log_line, log_type, timezone)]

# def read_log_file_in_batches(log_file, batch_size=1000):
#     """
#     Generator to read log files in batches.
#     """
#     with open(log_file, 'r') as f:
#         batch = []
#         for line in f:
#             batch.append(line)
#             if len(batch) >= batch_size:
#                 yield batch
#                 batch = []
#         if batch:
#             yield batch

# def process_log_file(log_file, log_type, timezone='UTC', batch_size=1000, workers=4):
#     """
#     Process a log file with batch processing and multi-threading/multiprocessing.
#     """
#     results = []
#     with ThreadPoolExecutor(max_workers=workers) as executor:
#         futures = [executor.submit(process_log_batch, batch, log_type, timezone) for batch in read_log_file_in_batches(log_file, batch_size)]
#         for future in futures:
#             results.extend(future.result())
#     return results

# def generate_report(filtered_logs, correlated_events, anomalies):
#     """Generate a summary report of the log analysis."""
#     with open(OUTPUT_REPORT, 'w') as f:
#         f.write("Log Analysis Report\n")
#         f.write("="*50 + "\n\n")

#         f.write("Filtered Logs:\n")
#         f.write("-"*50 + "\n")
#         f.writelines(filtered_logs)
#         f.write("\n\n")

#         f.write("Correlated Events:\n")
#         f.write("-"*50 + "\n")
#         for timestamp, events in correlated_events.items():
#             f.write(f"{timestamp}:\n")
#             for source, message in events:
#                 f.write(f"\tSource: {source}, Message: {message}\n")
#         f.write("\n\n")

#         f.write("Anomalies Detected:\n")
#         f.write("-"*50 + "\n")
#         f.writelines(anomalies)
#         f.write("\n\n")

#         f.write("End of Report\n")
#         f.write("="*50 + "\n")

# def plot_statistics(log_lines):
#     """Generate statistics and plots from the log analysis."""
#     # Example: Create a bar chart of keyword occurrences
#     keyword_counts = defaultdict(int)
#     for line in log_lines:
#         _, _, message = parse_text_log_line(line)
#         for keyword in KEYWORDS:
#             if keyword in message.lower():
#                 keyword_counts[keyword] += 1

#     if keyword_counts:
#         keywords, counts = zip(*keyword_counts.items())
#         plt.bar(keywords, counts)
#         plt.title("Keyword Occurrences in Logs")
#         plt.xlabel("Keywords")
#         plt.ylabel("Occurrences")
#         plt.show()
#     else:
#         print("No keywords found in logs to plot.")

# def main():
#     # Step 1: Save initial hashes of the log files
#     print("[*] Saving hashes of log files for integrity verification...")
#     save_hashes(TEXT_LOG_FILES + EVTX_LOG_FILES, HASH_OUTPUT)
#     print("[*] Hashes saved to", HASH_OUTPUT)

#     # Step 2: Read and parse text-based logs
#     print("[*] Reading and parsing text-based log files...")
#     all_log_lines = []
#     for log_file_pattern in TEXT_LOG_FILES:
#         for log_file in glob.glob(log_file_pattern):
#             if os.path.exists(log_file):
#                 log_lines = read_text_log_file(log_file)
#                 all_log_lines.extend(log_lines)
#             else:
#                 print(f"[!] Log file not found: {log_file}")

#     # Step 3: Parse and analyze EVTX logs
#     print("[*] Parsing and analyzing EVTX log files...")
#     for evtx_file in EVTX_LOG_FILES:
#         if os.path.exists(evtx_file):
#             evtx_logs = parse_evtx_log(evtx_file)
#             all_log_lines.extend(evtx_logs)
#         else:
#             print(f"[!] EVTX file not found: {evtx_file}")

#     # Step 4: Analyze logs
#     print("[*] Filtering logs by keywords...")
#     filtered_logs = filter_logs_by_keywords(all_log_lines, KEYWORDS)
    
#     print("[*] Correlating events...")
#     correlated_events = correlate_events(all_log_lines)
    
#     print("[*] Detecting anomalies...")
#     anomalies = detect_anomalies(all_log_lines)

#     # Step 5: Generate report
#     print("[*] Generating report...")
#     generate_report(filtered_logs, correlated_events, anomalies)
#     print("[*] Report generated:", OUTPUT_REPORT)

#     # Step 6: Plot statistics
#     print("[*] Plotting statistics...")
#     plot_statistics(all_log_lines)

# if __name__ == "__main__":
#     main()


# import win32evtlog
# import pandas as pd
# import re
# import json
# from reportlab.lib.pagesizes import letter
# from reportlab.pdfgen import canvas

# # Function to analyze Windows Event Logs
# def analyze_windows_event_logs(log_type):
#     server = 'localhost'  # Local machine
#     log = log_type  # E.g., 'System', 'Application', 'Security'
    
#     hand = win32evtlog.OpenEventLog(server, log)
#     flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
#     total = win32evtlog.GetNumberOfEventLogRecords(hand)

#     log_data = []
    
#     while True:
#         events = win32evtlog.ReadEventLog(hand, flags, 0)
#         if not events:
#             break
#         for event in events:
#             event_id = event.EventID
#             event_time = event.TimeGenerated.Format()
#             event_source = event.SourceName
#             event_type = event.EventType
#             event_message = event.StringInserts

#             # Simple check for suspicious activities and .msi files in system logs
#             suspicious = False
#             msi_detected = False

#             if event_type in [win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE]:
#                 suspicious = True

#             if event_message:
#                 message = ' '.join(event_message)
#                 if re.search(r'failed|unauthorized|error|denied|invalid', message, re.IGNORECASE):
#                     suspicious = True
#                 if re.search(r'\.msi', message, re.IGNORECASE):
#                     msi_detected = True
#             else:
#                 message = ''

#             log_data.append({
#                 'Event ID': event_id,
#                 'Timestamp': event_time,
#                 'Source': event_source,
#                 'Event Type': event_type,
#                 'Message': message,
#                 'Suspicious': suspicious,
#                 'MSI Detected': msi_detected
#             })

#     win32evtlog.CloseEventLog(hand)
#     return log_data

# # Function to save log data to an Excel file
# def save_to_excel(log_data, output_file):
#     df = pd.DataFrame(log_data)
#     df.to_excel(output_file, index=False)

# # Function to save log data to a JSON file
# def save_to_json(log_data, output_file):
#     with open(output_file, 'w') as f:
#         json.dump(log_data, f, indent=4)

# # Function to save log data to a PDF file
# def save_to_pdf(log_data, output_file):
#     c = canvas.Canvas(output_file, pagesize=letter)
#     width, height = letter
#     y_position = height - 50  # Start position for text

#     # Add title
#     c.setFont("Helvetica-Bold", 14)
#     c.drawString(50, y_position, "Windows Event Log Analysis")
#     y_position -= 30

#     # Add column headers
#     c.setFont("Helvetica-Bold", 10)
#     c.drawString(50, y_position, "Event ID")
#     c.drawString(150, y_position, "Timestamp")
#     c.drawString(250, y_position, "Source")
#     c.drawString(350, y_position, "Event Type")
#     c.drawString(450, y_position, "Message")
#     c.drawString(600, y_position, "Suspicious")
#     c.drawString(700, y_position, "MSI Detected")
#     y_position -= 20

#     # Add data rows
#     c.setFont("Helvetica", 8)
#     for entry in log_data:
#         if y_position < 50:  # Add a new page if space is not enough
#             c.showPage()
#             y_position = height - 50
#             c.setFont("Helvetica-Bold", 10)
#             c.drawString(50, y_position, "Event ID")
#             c.drawString(150, y_position, "Timestamp")
#             c.drawString(250, y_position, "Source")
#             c.drawString(350, y_position, "Event Type")
#             c.drawString(450, y_position, "Message")
#             c.drawString(600, y_position, "Suspicious")
#             c.drawString(700, y_position, "MSI Detected")
#             y_position -= 20
#             c.setFont("Helvetica", 8)

#         c.drawString(50, y_position, str(entry['Event ID']))
#         c.drawString(150, y_position, entry['Timestamp'])
#         c.drawString(250, y_position, entry['Source'])
#         c.drawString(350, y_position, str(entry['Event Type']))
#         c.drawString(450, y_position, entry['Message'])
#         c.drawString(600, y_position, str(entry['Suspicious']))
#         c.drawString(700, y_position, str(entry['MSI Detected']))
#         y_position -= 15

#     c.save()

# # Main function
# def main():
#     log_type = input("Enter the type of log to analyze (System, Application, Security): ")
#     excel_file = f"{log_type}_log_analysis.xlsx"
#     json_file = f"{log_type}_log_analysis.json"
#     pdf_file = f"{log_type}_log_analysis.pdf"

#     print(f"Analyzing {log_type} logs...")
#     log_data = analyze_windows_event_logs(log_type)
    
#     print(f"Saving results to {excel_file}...")
#     save_to_excel(log_data, excel_file)

#     print(f"Saving results to {json_file}...")
#     save_to_json(log_data, json_file)

#     print(f"Saving results to {pdf_file}...")
#     save_to_pdf(log_data, pdf_file)
    
#     print("Analysis complete.")

# if __name__ == "__main__":
#     main()

# ================================================================


# import os
# import re
# import hashlib
# import multiprocessing
# import pytz  # For timezone handling
# from datetime import datetime
# from concurrent.futures import ThreadPoolExecutor
# from collections import defaultdict
# import xml.etree.ElementTree as ET
# import pandas as pd
# import matplotlib.pyplot as plt
# import glob
# import win32evtlog  # Required for Event Log access on Windows

# # Constants and configurations
# TEXT_LOG_FILES = [
#     "C:/Windows/Logs/WindowsUpdate/WindowsUpdate.log",
#     "C:/inetpub/logs/LogFiles/W3SVC1/*.log"
# ]
# EVTX_LOG_FILES = [
#     "C:/Windows/System32/winevt/Logs/System.evtx",
#     "C:/Windows/System32/winevt/Logs/Application.evtx"
# ]
# OUTPUT_REPORT = "log_analysis_report.txt"
# HASH_OUTPUT = "log_hashes.txt"
# KEYWORDS = ["error", "fail", "unauthorized", "login", "shutdown", "reboot"]

# # Anomaly detection patterns and thresholds
# patterns = {
#     'failed_login_attempts': re.compile(r'Failed login attempt from IP: (\d+\.\d+\.\d+\.\d+)'),
#     'successful_login_unusual_location': re.compile(r'Successful login from IP: (\d+\.\d+\.\d+\.\d+) at location: (.*)'),
#     'login_attempts_outside_hours': re.compile(r'Login attempt from IP: (\d+\.\d+\.\d+\.\d+) at (\d{2}:\d{2})'),
#     'unauthorized_user_creation': re.compile(r'Unauthorized account creation: Username: (.*)'),
#     'account_deletion_without_auth': re.compile(r'Account deletion without authorization: Username: (.*)'),
#     'privilege_escalation': re.compile(r'Privilege escalation attempt: User: (.*), New Privilege: (.*)'),
#     'failed_password_reset_attempts': re.compile(r'Failed password reset attempt for User: (.*)'),
#     'concurrent_logins': re.compile(r'Concurrent logins detected for User: (.*) from IPs: (.*)'),
#     'unauthorized_file_access': re.compile(r'Unauthorized access to file: (.*)'),
#     'unusual_file_access_patterns': re.compile(r'Access to a large number of files by User: (.*)'),
#     'unexpected_reboots': re.compile(r'Unexpected system reboot detected: Reason: (.*)'),
#     'cpu_memory_spikes': re.compile(r'Sudden spike in CPU usage: (\d+)% or Memory usage: (\d+)%'),
#     'high_disk_io': re.compile(r'High disk I/O activity: (\d+) bytes'),
#     'unusual_outbound_connections': re.compile(r'Unusual outbound network connection to IP: (\d+\.\d+\.\d+\.\d+)'),
#     'high_number_inbound_connections': re.compile(r'High number of inbound connections: (\d+)'),
#     'non_standard_ports': re.compile(r'Use of non-standard port for communication: (\d+)'),
#     'large_data_transfers': re.compile(r'Large data transfer detected: (\d+) bytes to IP: (\d+\.\d+\.\d+\.\d+)'),
#     'increase_in_network_traffic': re.compile(r'Increase in network traffic: (\d+) bytes'),
#     'connections_to_malicious_ips': re.compile(r'Connection to known malicious IP: (\d+\.\d+\.\d+\.\d+)'),
#     'unusual_dns_queries': re.compile(r'Unusual DNS query pattern: (.*)'),
# }

# # Define thresholds for detection
# thresholds = {
#     'error_count': 10,
#     'warning_count': 20,
# }

# # Function to create a SHA-256 hash of the given file
# def hash_file(filename):
#     sha256 = hashlib.sha256()
#     try:
#         with open(filename, 'rb') as f:
#             for block in iter(lambda: f.read(4096), b""):
#                 sha256.update(block)
#     except PermissionError:
#         print(f"[!] Permission denied: {filename}")
#         return None
#     return sha256.hexdigest()

# # Function to save the hashes of the logs for integrity verification
# def save_hashes(log_files, output_file):
#     with open(output_file, 'w') as f:
#         for log_file in log_files:
#             if os.path.exists(log_file):
#                 file_hash = hash_file(log_file)
#                 if file_hash:
#                     f.write(f"{log_file}: {file_hash}\n")
#                 else:
#                     f.write(f"{log_file}: PERMISSION DENIED\n")
#             else:
#                 f.write(f"{log_file}: FILE NOT FOUND\n")

# # Function to read text log files and return their content as a list of lines
# def read_text_log_file(log_file):
#     with open(log_file, 'r') as f:
#         return f.readlines()

# # Function to parse a single log line and extract timestamp, source, and message
# def parse_text_log_line(line):
#     match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(.*)', line)
#     if match:
#         timestamp_str, source, message = match.groups()
#         timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
#         return timestamp, source, message
#     return None, None, None

# # Function to filter log lines by specified keywords
# def filter_logs_by_keywords(log_lines, keywords):
#     return [line for line in log_lines if any(keyword in parse_text_log_line(line)[2].lower() for keyword in keywords)]

# # Function to correlate events based on timestamps and sources
# def correlate_events(log_lines):
#     correlated_events = defaultdict(list)
#     for line in log_lines:
#         timestamp, source, message = parse_text_log_line(line)
#         if timestamp and source:
#             correlated_events[timestamp].append((source, message))
#     return correlated_events

# # Rule-based detection function
# def rule_based_detection(message):
#     suspicious_keywords = ['failed', 'unauthorized', 'error', 'denied', 'invalid']
#     msi_keywords = ['.msi']
#     suspicious = any(keyword in message.lower() for keyword in suspicious_keywords)
#     msi_detected = any(keyword in message.lower() for keyword in msi_keywords)
#     return suspicious, msi_detected

# # Pattern-based detection function
# def pattern_based_detection(message):
#     results = {}
#     for key, pattern in patterns.items():
#         match = pattern.search(message)
#         if match:
#             results[key] = match.groups()
#     return results

# # Threshold-based detection function
# def threshold_based_detection(event_data):
#     counts = {
#         'error_count': sum(1 for e in event_data if e['Event Type'] == win32evtlog.EVENTLOG_ERROR_TYPE),
#         'warning_count': sum(1 for e in event_data if e['Event Type'] == win32evtlog.EVENTLOG_WARNING_TYPE)
#     }
#     anomalies = {
#         'Error Threshold Exceeded': counts['error_count'] > thresholds['error_count'],
#         'Warning Threshold Exceeded': counts['warning_count'] > thresholds['warning_count']
#     }
#     return anomalies

# # Function to detect anomalies in log lines
# def detect_anomalies(log_lines):
#     anomalies = []
#     for line in log_lines:
#         timestamp, source, message = parse_text_log_line(line)
        
#         # Rule-based detection
#         suspicious, msi_detected = rule_based_detection(message)
#         if suspicious or msi_detected:
#             anomalies.append((timestamp, source, message, "Rule-based Anomaly Detected"))
        
#         # Pattern-based detection
#         pattern_results = pattern_based_detection(message)
#         if pattern_results:
#             anomalies.append((timestamp, source, message, f"Pattern-based Anomaly Detected: {pattern_results}"))
        
#         # Store detailed anomaly information
#         if suspicious:
#             anomalies.append((timestamp, source, message, "Suspicious Keyword Detected"))
#         if msi_detected:
#             anomalies.append((timestamp, source, message, ".msi File Detected"))

#     return anomalies

# # Function to parse .evtx log files and extract relevant information
# def parse_evtx_log(log_file):
#     try:
#         import Evtx.Evtx as evtx
#         log_lines = []
#         with evtx.Evtx(log_file) as log:
#             for record in log.records():
#                 event_xml = ET.fromstring(record.xml())
#                 timestamp = event_xml.find("System/TimeCreated").attrib['SystemTime']
#                 source = event_xml.find("System/Provider").attrib['Name']
#                 message = event_xml.find("EventData").text
#                 log_lines.append(f"{timestamp} {source} {message}")
#         return log_lines
#     except ImportError:
#         raise ImportError("Please install python-evtx to parse .evtx files.")
#     except PermissionError:
#         print(f"[!] Permission denied: {log_file}")
#         return []
#     except Exception as e:
#         print(f"[!] An unexpected error occurred: {e}")
#         return []

# # Function to generate a detailed report of the detected anomalies
# def generate_detailed_anomaly_report(anomalies):
#     with open(OUTPUT_REPORT, 'a') as f:
#         f.write("\n\nDetailed Anomaly Report:\n")
#         for anomaly in anomalies:
#             timestamp, source, message, description = anomaly
#             f.write(f"Timestamp: {timestamp}, Source: {source}, Message: {message}, Description: {description}\n")

# # Function to perform anomaly detection and log the results
# def detect_and_log_anomalies(log_files):
#     with open(OUTPUT_REPORT, 'w') as f:
#         for log_file in log_files:
#             if os.path.exists(log_file):
#                 if log_file.endswith('.evtx'):
#                     log_lines = parse_evtx_log(log_file)
#                 else:
#                     log_lines = read_text_log_file(log_file)

#                 # Anomaly detection
#                 anomalies = detect_anomalies(log_lines)
#                 if anomalies:
#                     f.write(f"Anomalies detected in {log_file}:\n")
#                     for anomaly in anomalies:
#                         timestamp, source, message, description = anomaly
#                         f.write(f"Timestamp: {timestamp}, Source: {source}, Message: {message}, Description: {description}\n")
                    
#                     # Generate detailed anomaly report
#                     generate_detailed_anomaly_report(anomalies)

# # Main function to orchestrate the log analysis and anomaly detection
# def main():
#     log_files = TEXT_LOG_FILES + EVTX_LOG_FILES
#     save_hashes(log_files, HASH_OUTPUT)
#     detect_and_log_anomalies(log_files)

# if __name__ == "__main__":
#     main()












# import os
# import re
# import hashlib
# from datetime import datetime
# from collections import defaultdict
# import xml.etree.ElementTree as ET
# import win32evtlog  # Required for Event Log access on Windows

# # Constants and configurations
# TEXT_LOG_FILES = [
#     "C:/Windows/Logs/WindowsUpdate/WindowsUpdate.log",
#     "C:/inetpub/logs/LogFiles/W3SVC1/*.log"
# ]
# EVTX_LOG_FILES = [
#     "C:/Windows/System32/winevt/Logs/System.evtx",
#     "C:/Windows/System32/winevt/Logs/Application.evtx"
# ]
# OUTPUT_REPORT = "log_analysis_report.txt"
# HASH_OUTPUT = "log_hashes.txt"
# KEYWORDS = ["error", "fail", "unauthorized", "login", "shutdown", "reboot"]

# # Anomaly detection patterns and thresholds
# patterns = {
#     'failed_login_attempts': re.compile(r'Failed login attempt from IP: (\d+\.\d+\.\d+\.\d+)'),
#     'successful_login_unusual_location': re.compile(r'Successful login from IP: (\d+\.\d+\.\d+\.\d+) at location: (.*)'),
#     # Add other patterns here...
# }

# # Define thresholds for detection
# thresholds = {
#     'error_count': 10,
#     'warning_count': 20,
# }

# def hash_file(filename):
#     sha256 = hashlib.sha256()
#     try:
#         with open(filename, 'rb') as f:
#             for block in iter(lambda: f.read(4096), b""):
#                 sha256.update(block)
#     except PermissionError:
#         print(f"[!] Permission denied: {filename}")
#         return None
#     return sha256.hexdigest()

# def save_hashes(log_files, output_file):
#     with open(output_file, 'w') as f:
#         for log_file in log_files:
#             if os.path.exists(log_file):
#                 file_hash = hash_file(log_file)
#                 if file_hash:
#                     f.write(f"{log_file}: {file_hash}\n")
#                 else:
#                     f.write(f"{log_file}: PERMISSION DENIED\n")
#             else:
#                 f.write(f"{log_file}: FILE NOT FOUND\n")

# def read_text_log_file(log_file):
#     with open(log_file, 'r') as f:
#         return f.readlines()

# def parse_text_log_line(line):
#     match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(.*)', line)
#     if match:
#         timestamp_str, source, message = match.groups()
#         timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
#         return timestamp, source, message
#     return None, None, None

# def filter_logs_by_keywords(log_lines, keywords):
#     return [line for line in log_lines if parse_text_log_line(line)[2] and any(keyword in parse_text_log_line(line)[2].lower() for keyword in keywords)]

# def correlate_events(log_lines):
#     correlated_events = defaultdict(list)
#     for line in log_lines:
#         timestamp, source, message = parse_text_log_line(line)
#         if timestamp and source:
#             correlated_events[timestamp].append((source, message))
#     return correlated_events

# def rule_based_detection(message):
#     suspicious_keywords = ['failed', 'unauthorized', 'error', 'denied', 'invalid']
#     msi_keywords = ['.msi']
#     suspicious = any(keyword in message.lower() for keyword in suspicious_keywords) if message else False
#     msi_detected = any(keyword in message.lower() for keyword in msi_keywords) if message else False
#     return suspicious, msi_detected

# def pattern_based_detection(message):
#     results = {}
#     if message:
#         for key, pattern in patterns.items():
#             match = pattern.search(message)
#             if match:
#                 results[key] = match.groups()
#     return results

# def threshold_based_detection(event_data):
#     counts = {
#         'error_count': sum(1 for e in event_data if e['Event Type'] == win32evtlog.EVENTLOG_ERROR_TYPE),
#         'warning_count': sum(1 for e in event_data if e['Event Type'] == win32evtlog.EVENTLOG_WARNING_TYPE)
#     }
#     anomalies = {
#         'Error Threshold Exceeded': counts['error_count'] > thresholds['error_count'],
#         'Warning Threshold Exceeded': counts['warning_count'] > thresholds['warning_count']
#     }
#     return anomalies

# def detect_anomalies(log_lines):
#     anomalies = []
#     for line in log_lines:
#         timestamp, source, message = parse_text_log_line(line)
        
#         # Rule-based detection
#         suspicious, msi_detected = rule_based_detection(message)
#         if suspicious or msi_detected:
#             anomalies.append((timestamp, source, message, "Rule-based Anomaly Detected"))
        
#         # Pattern-based detection
#         pattern_results = pattern_based_detection(message)
#         if pattern_results:
#             anomalies.append((timestamp, source, message, f"Pattern-based Anomaly Detected: {pattern_results}"))

#         # Additional anomaly detection can be added here

#     return anomalies

# def parse_evtx_log(log_file):
#     try:
#         import Evtx.Evtx as evtx
#         log_lines = []
#         with evtx.Evtx(log_file) as log:
#             for record in log.records():
#                 event_xml = ET.fromstring(record.xml())
#                 timestamp = event_xml.find("System/TimeCreated").attrib['SystemTime']
#                 source = event_xml.find("System/Provider").attrib['Name']
#                 message = event_xml.find("EventData").text
#                 log_lines.append(f"{timestamp} {source} {message}")
#         return log_lines
#     except ImportError:
#         raise ImportError("Please install python-evtx to parse .evtx files.")
#     except PermissionError:
#         print(f"[!] Permission denied: {log_file}")
#         return []
#     except Exception as e:
#         print(f"[!] An unexpected error occurred: {e}")
#         return []

# def generate_detailed_anomaly_report(anomalies):
#     with open(OUTPUT_REPORT, 'a') as f:
#         f.write("\n\nDetailed Anomaly Report:\n")
#         for anomaly in anomalies:
#             timestamp, source, message, description = anomaly
#             f.write(f"Timestamp: {timestamp}, Source: {source}, Message: {message}, Description: {description}\n")

# def detect_and_log_anomalies(log_files):
#     with open(OUTPUT_REPORT, 'w') as f:
#         for log_file in log_files:
#             if os.path.exists(log_file):
#                 if log_file.endswith('.evtx'):
#                     log_lines = parse_evtx_log(log_file)
#                 else:
#                     log_lines = read_text_log_file(log_file)

#                 # Anomaly detection
#                 anomalies = detect_anomalies(log_lines)
#                 if anomalies:
#                     f.write(f"Anomalies detected in {log_file}:\n")
#                     for anomaly in anomalies:
#                         timestamp, source, message, description = anomaly
#                         f.write(f"Timestamp: {timestamp}, Source: {source}, Message: {message}, Description: {description}\n")
                    
#                     generate_detailed_anomaly_report(anomalies)

# def main():
#     log_files = TEXT_LOG_FILES + EVTX_LOG_FILES
#     save_hashes(log_files, HASH_OUTPUT)
#     detect_and_log_anomalies(log_files)

# if __name__ == "__main__":
#     main()













