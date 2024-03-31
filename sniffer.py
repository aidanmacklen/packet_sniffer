import threading
import time
import pandas as pd
from scapy.all import sniff, TCP, UDP, IP
import logging
from datetime import datetime
import os

# Initialize a list to store packet data
packet_data_list = []

def packet_callback(packet):
    global packet_data_list
    # Check for IP packets that contain a TCP or UDP layer
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_layer = packet[IP]
        protocol = 'TCP' if packet.haslayer(TCP) else 'UDP'
        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]

        packet_info = {
            'Timestamp': timestamp,
            'Source IP': ip_layer.src,
            'Source Port': transport_layer.sport,
            'Destination IP': ip_layer.dst,
            'Destination Port': transport_layer.dport,
            'Protocol': protocol,
            'Info': str(transport_layer.payload)[:50]  # Extracting initial part of the payload
        }

        # Append packet data to the list (thread-safe operation)
        packet_data_list.append(packet_info)

def export_packet_data():
    global packet_data_list
    while True:
        with threading.Lock():
            temp_data_list = packet_data_list[:]
            packet_data_list = []

        if temp_data_list:
            packet_data_df = pd.DataFrame(temp_data_list)
            file_exists = os.path.exists('packet_data.csv')
            packet_data_df.to_csv('packet_data.csv', mode='a', header=not file_exists, index=False)
            logging.info(f"Exported {len(temp_data_list)} packets to CSV.")
            print(f"Exported {len(temp_data_list)} packets to CSV at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
        time.sleep(300)  # Export data every 5 minutes

if __name__ == "__main__":
    logging.basicConfig(filename='alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')
    print("Starting packet capture.")
    logging.info("Starting packet capture.")
    thread_sniffer = threading.Thread(target=lambda: sniff(filter="tcp or udp", prn=packet_callback, store=False))
    thread_exporter = threading.Thread(target=export_packet_data)
    thread_sniffer.start()
    thread_exporter.start()
