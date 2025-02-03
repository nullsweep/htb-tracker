import streamlit as st
import socket
import threading
import requests
import time
import pandas as pd
import ssl
import dns.resolver  # Requires dnspython: pip install dnspython
import os
import glob

# =============================================================================
# Utility: Reporting Functionality
# =============================================================================
def init_report():
    if "report" not in st.session_state:
        st.session_state["report"] = []

def report_log(message, level="INFO"):
    """
    Logs a message to the Streamlit UI and appends it to the session report.
    """
    init_report()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"{timestamp} - {level.upper()} - {message}"
    if level.upper() == "INFO":
        st.write(log_msg)
    elif level.upper() == "WARNING":
        st.warning(log_msg)
    elif level.upper() == "ERROR":
        st.error(log_msg)
    else:
        st.write(log_msg)
    st.session_state["report"].append(log_msg)

# =============================================================================
# Helper: Find Wordlists on the Local Machine
# =============================================================================
def find_wordlists(directory="/usr/share/dirb/wordlists"):
    """
    Searches for *.txt files in the specified directory.
    Returns a list of file paths.
    """
    if os.path.isdir(directory):
        return glob.glob(os.path.join(directory, "*.txt"))
    return []

# =============================================================================
# Module 1: Port Scanner
# =============================================================================
class PortScanner:
    """
    A basic multi-threaded TCP port scanner.
    """
    def __init__(self, target, ports):
        self.target = target
        self.ports = ports
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, port):
        """
        Attempts to connect to the given port. If successful, logs it as open.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    with self.lock:
                        self.open_ports.append(port)
                    report_log(f"Port {port} is open.", "INFO")
        except Exception as e:
            report_log(f"Error scanning port {port}: {e}", "DEBUG")

    def run_scan(self):
        """
        Runs the port scan using threads.
        """
        report_log(f"Starting port scan on {self.target} for ports: {self.ports}", "INFO")
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        report_log(f"Port scan complete. Open ports: {self.open_ports}", "INFO")
        return self.open_ports

# =============================================================================
# Module 2: Service Enumeration
# =============================================================================
class ServiceEnumerator:
    """
    Grabs service banners and, if applicable, performs HTTP enumeration.
    """
    def __init__(self, target, port):
        self.target = target
        self.port = port

    def banner_grab(self):
        """
        Attempts to grab the banner from the target service.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.target, self.port))
                banner = s.recv(1024)
                if banner:
                    decoded_banner = banner.decode(errors='ignore').strip()
                    report_log(f"Banner for port {self.port}: {decoded_banner}", "INFO")
                    return decoded_banner
                else:
                    report_log(f"No banner received on port {self.port}.", "INFO")
                    return ""
        except Exception as e:
            report_log(f"Error grabbing banner on port {self.port}: {e}", "WARNING")
            return ""

    def http_enum(self):
        """
        If the service appears to be HTTP, collects headers and a content snippet.
        """
        try:
            url = f"http://{self.target}:{self.port}"
            response = requests.get(url, timeout=5)
            headers = response.headers
            status = response.status_code
            snippet = response.text[:200]
            report_log(f"HTTP enumeration on port {self.port} succeeded (status {status}).", "INFO")
            report_log(f"HTTP Headers: {headers}", "INFO")
            report_log(f"HTTP Content Snippet: {snippet}", "INFO")
            return headers, status, snippet
        except Exception as e:
            report_log(f"HTTP enumeration failed on port {self.port}: {e}", "WARNING")
            return None

# =============================================================================
# Module 3: Exploitation (Sample/Demo)
# =============================================================================
class Exploiter:
    """
    A sample exploitation module that simulates attacking a vulnerable web endpoint.
    """
    def __init__(self, target, port):
        self.target = target
        self.port = port

    def simple_exploit(self):
        """
        A dummy exploit that posts a payload to a presumed vulnerable endpoint.
        """
        report_log(f"Attempting a sample exploit on {self.target}:{self.port}", "INFO")
        try:
            url = f"http://{self.target}:{self.port}/vulnerable_endpoint"
            payload = {"input": "' OR '1'='1"}
            response = requests.post(url, data=payload, timeout=5)
            if "Welcome" in response.text:
                report_log("Exploit appears to be successful!", "INFO")
                return True, "Exploit successful: Received positive response."
            else:
                report_log("Exploit did not work on the target.", "INFO")
                return False, "Exploit failed: Response did not indicate success."
        except Exception as e:
            report_log(f"Exploit error: {e}", "ERROR")
            return False, f"Exploit error: {e}"

# =============================================================================
# Module 4: Pentest Tool Wrapper with Branching Logic
# =============================================================================
class PentestTool:
    """
    The main pentesting framework tying all modules together.
    """
    def __init__(self, target):
        self.target = target

    def run_scan(self, ports):
        scanner = PortScanner(self.target, ports)
        return scanner.run_scan()

    def enumerate_service(self, port):
        """
        Runs manual enumeration for a given port.
        """
        enumerator = ServiceEnumerator(self.target, port)
        banner = enumerator.banner_grab()
        extra_info = ""
        if port in (80, 8080, 8000):
            http_info = enumerator.http_enum()
            if http_info:
                headers, status, snippet = http_info
                extra_info = f"HTTP Status: {status}"
        elif port == 22:
            if banner and "SSH" in banner:
                extra_info = "SSH service detected."
            else:
                extra_info = "SSH service suspected but banner unclear."
        elif port == 21:
            if banner and "FTP" in banner:
                extra_info = "FTP service detected."
            else:
                extra_info = "FTP service suspected but banner unclear."
        else:
            extra_info = "Generic service or no additional data."
        return banner, extra_info

    def auto_scan_and_enumerate(self, ports):
        """
        Performs a port scan and then automatically enumerates each open port using
        branching logic based on the service type.
        Returns a dictionary with details per open port.
        """
        open_ports = self.run_scan(ports)
        results = {}
        for port in open_ports:
            enumerator = ServiceEnumerator(self.target, port)
            banner = enumerator.banner_grab()
            service = "Generic"
            extra_info = ""
            if port in (80, 8080, 8000):
                service = "HTTP"
                http_info = enumerator.http_enum()
                if http_info:
                    headers, status, snippet = http_info
                    extra_info = f"HTTP Status: {status}, Headers: {headers}, Snippet: {snippet[:50]}..."
            elif port == 22:
                service = "SSH"
                if banner and "SSH" in banner:
                    extra_info = f"SSH service detected. Banner: {banner}"
                else:
                    extra_info = "SSH service suspected but banner unclear."
            elif port == 21:
                service = "FTP"
                if banner and "FTP" in banner:
                    extra_info = f"FTP service detected. Banner: {banner}"
                else:
                    extra_info = "FTP service suspected but banner unclear."
            else:
                extra_info = "No additional enumeration performed."
            results[port] = {
                "banner": banner,
                "service": service,
                "extra_info": extra_info
            }
        return open_ports, results

    def run_exploit(self, port):
        exploiter = Exploiter(self.target, port)
        success, message = exploiter.simple_exploit()
        report_log(f"Exploit result: {message}", "INFO")
        return success

# =============================================================================
# Additional Functionality 1: DNS & Subdomain Enumeration
# =============================================================================
def dns_enumeration(domain):
    """
    Performs DNS record enumeration (A, MX, NS, TXT) for the given domain.
    """
    records = {}
    for record_type in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [rdata.to_text() for rdata in answers]
            report_log(f"{record_type} records for {domain}: {records[record_type]}", "INFO")
        except Exception as e:
            records[record_type] = f"Error: {e}"
            report_log(f"Error retrieving {record_type} records for {domain}: {e}", "WARNING")
    return records

def subdomain_enumeration(domain, subdomains):
    """
    Attempts to resolve subdomains by prepending entries from a list to the domain.
    """
    found = {}
    for sub in subdomains:
        candidate = f"{sub.strip()}.{domain}"
        try:
            answers = dns.resolver.resolve(candidate, 'A')
            ips = [rdata.to_text() for rdata in answers]
            found[candidate] = ips
            report_log(f"Subdomain found: {candidate} -> {ips}", "INFO")
        except Exception as e:
            # Ignore non-resolving subdomains silently.
            pass
    return found

# =============================================================================
# Additional Functionality 2: SSL/TLS Analysis
# =============================================================================
def ssl_analysis(target, port):
    """
    Connects to a target and returns its SSL/TLS certificate details.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                report_log(f"SSL certificate for {target}:{port} retrieved.", "INFO")
                return cert
    except Exception as e:
        report_log(f"SSL analysis failed for {target}:{port}: {e}", "ERROR")
        return f"Error: {e}"

# =============================================================================
# Additional Functionality 3: Web Directory Enumeration
# =============================================================================
def directory_enumeration(target, port, paths):
    """
    Attempts to enumerate directories on a web server using a provided list of paths.
    """
    found_paths = {}
    for path in paths:
        url = f"http://{target}:{port}/{path.strip()}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in [200, 403]:
                found_paths[url] = r.status_code
                report_log(f"Directory found: {url} (Status: {r.status_code})", "INFO")
        except Exception as e:
            pass
    return found_paths

# =============================================================================
# Helper Function: Parse Port Input
# =============================================================================
def parse_ports(ports_str):
    """
    Parses a port specification string.
    Accepts ranges (e.g. "20-1024") or comma-separated lists (e.g. "22,80,443").
    """
    ports = []
    if "-" in ports_str:
        try:
            start, end = ports_str.split("-")
            ports = list(range(int(start), int(end) + 1))
        except ValueError:
            report_log("Invalid port range format. Use something like '20-1024'.", "ERROR")
    elif "," in ports_str:
        try:
            ports = [int(p.strip()) for p in ports_str.split(",")]
        except ValueError:
            report_log("Invalid comma-separated port list.", "ERROR")
    else:
        try:
            ports = [int(ports_str)]
        except ValueError:
            report_log("Port must be an integer.", "ERROR")
    return ports

# =============================================================================
# Streamlit UI Layout
# =============================================================================
def main():
    st.set_page_config(page_title="Pentest Tool", layout="wide")
    st.title("Advanced Educational Pentest Tool with Extended Functionality")
    st.write("**Use responsibly on authorized systems only.**")

    # Initialize report if not already done
    init_report()

    # Sidebar: Global Settings for primary scanning and target info
    st.sidebar.header("Target & Settings")
    target = st.sidebar.text_input("Target IP/Domain", value="10.10.10.10")
    ports_input = st.sidebar.text_input("Ports (range or comma-separated)", value="20-1024")

    # Create an instance of the pentest tool for the given target
    tool = PentestTool(target)

    # Define tabs for the various functionalities
    tab_auto, tab_manual, tab_exploit, tab_dns, tab_ssl, tab_dir, tab_report = st.tabs([
        "Combined Scan & Auto-Enumeration",
        "Manual Service Enumeration",
        "Exploitation",
        "DNS & Subdomain Enumeration",
        "SSL/TLS Analysis",
        "Directory Enumeration",
        "Report"
    ])

    # ---------------------
    # Tab 1: Combined Scan & Auto-Enumeration
    # ---------------------
    with tab_auto:
        st.header("Combined Scan & Auto-Enumeration")
        if st.button("Run Combined Scan & Auto-Enumeration"):
            ports = parse_ports(ports_input)
            if ports:
                with st.spinner("Scanning and enumerating services..."):
                    open_ports, enum_results = tool.auto_scan_and_enumerate(ports)
                    st.success(f"Scan complete. Open ports: {open_ports}")
                    # Display results in a table
                    data = []
                    for port, details in enum_results.items():
                        data.append({
                            "Port": port,
                            "Service": details["service"],
                            "Banner": details["banner"],
                            "Additional Info": details["extra_info"]
                        })
                    df = pd.DataFrame(data)
                    st.dataframe(df)
            else:
                st.error("No valid ports provided for scanning.")

    # ---------------------
    # Tab 2: Manual Service Enumeration
    # ---------------------
    with tab_manual:
        st.header("Manual Service Enumeration")
        enum_port = st.number_input("Port to enumerate", min_value=1, max_value=65535, value=80)
        if st.button("Run Manual Enumeration"):
            with st.spinner(f"Enumerating service on port {enum_port}..."):
                banner, extra_info = tool.enumerate_service(enum_port)
                st.info(f"Banner: {banner}")
                st.info(f"Additional Info: {extra_info}")

    # ---------------------
    # Tab 3: Exploitation
    # ---------------------
    with tab_exploit:
        st.header("Exploitation")
        exploit_port = st.number_input("Port to exploit", min_value=1, max_value=65535, value=80, key="exploit_port")
        if st.button("Run Exploit"):
            with st.spinner(f"Running exploit on port {exploit_port}..."):
                success = tool.run_exploit(exploit_port)
                if success:
                    st.success("Exploit appears to be successful!")
                else:
                    st.error("Exploit did not succeed.")

    # ---------------------
    # Tab 4: DNS & Subdomain Enumeration
    # ---------------------
    with tab_dns:
        st.header("DNS & Subdomain Enumeration")
        dns_domain = st.text_input("Domain for DNS Enumeration", value="example.com", key="dns_domain")
        # Attempt to find wordlists on the system
        sub_wordlists = find_wordlists("/usr/share/dirb/wordlists")
        if sub_wordlists:
            selected_sub_wordlist = st.selectbox("Select Subdomain Wordlist", options=sub_wordlists)
            try:
                with open(selected_sub_wordlist, "r") as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                st.info(f"Loaded {len(subdomains)} subdomains from {selected_sub_wordlist}")
            except Exception as e:
                st.error(f"Error loading file: {e}")
                subdomains = []
        else:
            sub_wordlist_input = st.text_area("Subdomain Wordlist (one per line)",
                                              value="www\nmail\nftp\nblog\nadmin", height=150)
            subdomains = [line.strip() for line in sub_wordlist_input.splitlines() if line.strip()]

        if st.button("Run DNS & Subdomain Enumeration"):
            with st.spinner("Enumerating DNS records..."):
                dns_results = dns_enumeration(dns_domain)
            st.subheader("DNS Records")
            st.write(dns_results)
            if subdomains:
                with st.spinner("Enumerating Subdomains..."):
                    sub_results = subdomain_enumeration(dns_domain, subdomains)
                st.subheader("Subdomains Found")
                if sub_results:
                    st.write(sub_results)
                else:
                    st.write("No subdomains found from the wordlist.")

    # ---------------------
    # Tab 5: SSL/TLS Analysis
    # ---------------------
    with tab_ssl:
        st.header("SSL/TLS Analysis")
        ssl_target = st.text_input("Target for SSL Analysis", value=target, key="ssl_target")
        ssl_port = st.number_input("SSL Port", min_value=1, max_value=65535, value=443, key="ssl_port")
        if st.button("Run SSL/TLS Analysis"):
            with st.spinner("Analyzing SSL/TLS certificate..."):
                cert = ssl_analysis(ssl_target, ssl_port)
            st.subheader("Certificate Details")
            if isinstance(cert, dict):
                st.json(cert)
            else:
                st.error(cert)

    # ---------------------
    # Tab 6: Directory Enumeration
    # ---------------------
    with tab_dir:
        st.header("Web Directory Enumeration")
        dir_target = st.text_input("Web Target", value=target, key="dir_target")
        dir_port = st.number_input("Web Port", min_value=1, max_value=65535, value=80, key="dir_port")
        # Attempt to find wordlists for directories
        dir_wordlists = find_wordlists("/usr/share/dirb/wordlists")
        if dir_wordlists:
            selected_dir_wordlist = st.selectbox("Select Directory Wordlist", options=dir_wordlists)
            try:
                with open(selected_dir_wordlist, "r") as f:
                    dir_paths = [line.strip() for line in f if line.strip()]
                st.info(f"Loaded {len(dir_paths)} paths from {selected_dir_wordlist}")
            except Exception as e:
                st.error(f"Error loading file: {e}")
                dir_paths = []
        else:
            default_dirs = "admin\nlogin\ndashboard\nconfig\nuploads\nimages"
            dir_wordlist_input = st.text_area("Directories to Check (one per line)", value=default_dirs, height=150)
            dir_paths = [line.strip() for line in dir_wordlist_input.splitlines() if line.strip()]

        if st.button("Run Directory Enumeration"):
            with st.spinner("Enumerating directories..."):
                found = directory_enumeration(dir_target, dir_port, dir_paths)
            st.subheader("Directories Found")
            if found:
                st.write(found)
            else:
                st.write("No directories found or accessible.")

    # ---------------------
    # Tab 7: Report & Download
    # ---------------------
    with tab_report:
        st.header("Execution Report")
        report_text = "\n".join(st.session_state["report"])
        st.text_area("Report Log", report_text, height=400)
        if st.button("Clear Report"):
            st.session_state["report"] = []
            st.experimental_rerun()
        st.download_button(
            label="Download Report",
            data=report_text,
            file_name="pentest_report.txt",
            mime="text/plain"
        )

if __name__ == "__main__":
    main()
