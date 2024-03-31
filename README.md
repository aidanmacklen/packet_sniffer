# Packet Sniffer
This is a Python-based packet sniffer used to sniff TCP and UDP packets that are being transmitted across your network. It does a proper job, logging timestamps, source and destination IPs, ports, and protocols of the packets to a CSV file for additional analysis.
# Features
Capture both TCP and UDP packets, Export packet data to a CSV file every 5 minutes, Threaded design for continuous packet sniffing and data exporting, Simple and easy-to-use for both educational and practical purposes.
# Prerequisites
Before we start with this packet sniffer, one should check if our system has Python installed or not. The program has a compatibility requirement from Python 3.x onward.

Additionally, you will need to install the following Python packages:
-pandas: For data manipulation and analysis.
-scapy: For packet capturing and analysis.

You can install these packages using pip, the Python package installer. Open your terminal or command prompt and run the following commands:
pip install pandas
pip install scapy
git clone [repository-url]
cd [directory-name]
sudo python packet_sniffer.py
The program will start capturing packets and export the data to a CSV file named packet_data.csv every 5 minutes. Logs related to the program's operation will be stored in alerts.log.
# Note
It needs capturing packets from a sniffed network interface, so it needs root or administrative privileges. Ensure you are authorized and cleared by the law of the respective land to monitor network traffic.
