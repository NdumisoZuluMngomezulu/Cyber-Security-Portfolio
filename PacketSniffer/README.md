A packet sniffer is a tool puts your network interface into promiscuous mode (or monitor mode for Wi-Fi) so it captures all traffic passing through it, not just packets addressed to your machine. It then captures raw frames off the wire, parses the headers at each layer (Ethernet → IP → TCP/UDP → application data) and displays or logs the decoded info (source/destination, ports, flags, payload)

How to run it :

bash :
sudo python3 packet_sniffer.py