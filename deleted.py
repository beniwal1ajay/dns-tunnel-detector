# advanced_dns_sniffer.py

import math
import sys

# scapy may not be available in every environment (tests, CI, etc.). Import defensively so
# the module can still be imported and a --test mode can run without starting a sniffer.
try:
    from scapy.all import sniff, DNS, DNSQR
except Exception:
    sniff = None
    DNS = None
    DNSQR = None

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a given data string.
    Entropy is a measure of randomness or unpredictability.
    A high entropy score suggests the data is random (like encoded data).
    A low score suggests it's structured (like a normal English word).
    """
    if not data:
        return 0
    
    # Calculate the frequency of each character in the string
    char_counts = {char: data.count(char) for char in set(data)}
    
    # Calculate the entropy
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in char_counts.values())
    
    return entropy

def packet_handler(packet):
    """
    This function is called for each captured packet.
    It now extracts and calculates advanced features from DNS queries.
    """
    # Filter for DNS queries only (qr=0)
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet.haslayer(DNSQR):
        
        dns_layer = packet.getlayer(DNS)
        dns_query = dns_layer[DNSQR]

        # Decode the query name (works when qname is bytes or str)
        qname = getattr(dns_query, 'qname', '')
        if isinstance(qname, (bytes, bytearray)):
            query_name = qname.decode(errors='ignore')
        else:
            # If it's already a str (some scapy versions/platforms) or other type, coerce to str
            query_name = str(qname)
        
        # Extract the main domain and the subdomain
        # e.g., for 'data.files.example.com', domain is 'example.com' and subdomain is 'data.files'
        parts = query_name.rstrip('.').split('.')
        if len(parts) > 2:
            domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
        else:
            domain = query_name.rstrip('.')
            subdomain = '' # No subdomain

        # --- Feature Calculation ---
        query_length = len(query_name)
        subdomain_length = len(subdomain)
        entropy = calculate_entropy(subdomain) # We only care about the entropy of the subdomain part

        # Get the query type (e.g., A, AAAA, TXT, etc.)
        qtype_int = dns_query.qtype
        # Scapy's DNS record types are numbers. 'A' is 1, 'TXT' is 16, etc.
        # We'll just use the number for now.
        
        # --- Print Results ---
        print(f"Query: {query_name:<40} | Length: {query_length:<5} | Subdomain Entropy: {entropy:.2f}")


def main():
    """
    Main function to start the packet sniffer.
    """
    print("Starting Advanced DNS Sniffer...")
    print("-" * 80)

    # Provide a safe test/dry-run mode that doesn't require root or network access.
    if '--test' in sys.argv or '-t' in sys.argv:
        print("Running self-test (no sniffing)")
        # Basic entropy checks
        print('Entropy("aaaa") =', calculate_entropy('aaaa'))
        print('Entropy("aZ3#xP9") =', calculate_entropy('aZ3#xP9'))

        # Create a fake packet object that mimics what packet_handler expects and call it
        class FakePacket:
            def __init__(self, qname):
                self._qname = qname

            def haslayer(self, layer):
                # pretend we always have DNS and DNSQR for the test
                return True

            def getlayer(self, layer):
                # Return an object which supports indexing with [DNSQR]
                class DnsLayer:
                    def __init__(self, qname):
                        self.qr = 0
                        # dns_layer[DNSQR] should return an object with qname and qtype
                        self._qd = type('QD', (), {'qname': qname, 'qtype': 1})()

                    def __getitem__(self, item):
                        return self._qd

                return DnsLayer(self._qname)

        print('\nTest with bytes qname:')
        packet_handler(FakePacket(b'subdata.example.com.'))
        print('\nTest with str qname:')
        packet_handler(FakePacket('subdata2.example.com.'))

        return

    if sniff is None:
        print("Scapy is not available in this Python environment. Install scapy or run with --test to dry-run.")
        return

    # Using 'iface' might be necessary on some systems. You can find your interface name
    # with the 'ip a' or 'ifconfig' command in the Kali terminal. Ex: 'eth0', 'wlan0'
    # sniff(filter="udp port 53", prn=packet_handler, store=0, iface='eth0')
    sniff(filter="udp port 53", prn=packet_handler, store=0)

if __name__ == "__main__":
    # Delegate to the new CLI runner if available, else run legacy main
    try:
        # prefer new runner
        from scripts.run_sniffer import main as run_main
        run_main()
    except Exception:
        main()