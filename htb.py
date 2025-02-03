import streamlit as st
import subprocess
import os
import re
import shutil
import json
import sqlite3
import datetime
import csv
from io import StringIO

# Attempt to import pdfkit for PDF export (optional)
try:
    import pdfkit
except ImportError:
    pdfkit = None

# =============================================================================
# Database functions for Scan History & Session Logging
# =============================================================================

def init_db():
    """Initialize (or connect to) the SQLite database for scan history."""
    conn = sqlite3.connect("scan_history.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            tool TEXT,
            target TEXT,
            parameters TEXT,
            output TEXT,
            errors TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan_to_db(tool, target, parameters, output, errors):
    """Save a scan entry to the database."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect("scan_history.db")
    c = conn.cursor()
    c.execute('''
        INSERT INTO scan_history (timestamp, tool, target, parameters, output, errors)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, tool, target, parameters, output, errors))
    conn.commit()
    conn.close()

def get_history():
    """Retrieve all scan history entries (most recent first)."""
    conn = sqlite3.connect("scan_history.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scan_history ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def clear_history():
    """Delete all scan history entries."""
    conn = sqlite3.connect("scan_history.db")
    c = conn.cursor()
    c.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()

def export_history_to_csv():
    """Export the scan history to CSV format."""
    rows = get_history()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Tool", "Target", "Parameters", "Output", "Errors"])
    for row in rows:
        writer.writerow(row)
    return output.getvalue()

# =============================================================================
# Utility Functions for Running Commands and Checking Dependencies
# =============================================================================

def command_exists(cmd: str) -> bool:
    """Check if a given command is available in the system's PATH."""
    return shutil.which(cmd) is not None

# -----------------------------------------------------------------------------
# Nmap and Gobuster functions (with customizable flags)
# -----------------------------------------------------------------------------

def run_nmap_scan(target: str, scan_option: str, custom_flags: str = "") -> (str, str):
    """
    Run an Nmap scan on the target with preset scan options merged with any custom flags.
    """
    scan_options = {
        "Quick Scan": ["-T4", "-F"],
        "Intense Scan": ["-A"],
        "Ping Scan": ["-sn"],
        "SYN Scan": ["-sS"],
        "Service Version": ["-sV"]
    }
    flags = scan_options.get(scan_option, [])
    if custom_flags:
        flags.extend(custom_flags.split())
    command = ["nmap"] + flags + [target]
    st.write("Running command:", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.stdout, result.stderr
    except Exception as e:
        return "", f"Exception occurred: {e}"

def run_gobuster_scan(target: str, wordlist: str, custom_flags: str = "") -> (str, str):
    """
    Run a Gobuster directory scan using the specified wordlist and custom flags.
    """
    command = ["gobuster", "dir", "-u", target, "-w", wordlist]
    if custom_flags:
        command.extend(custom_flags.split())
    st.write("Running command:", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.stdout, result.stderr
    except Exception as e:
        return "", f"Exception occurred: {e}"

# -----------------------------------------------------------------------------
# Additional Tools: Nikto and SSLScan
# -----------------------------------------------------------------------------

def run_nikto_scan(target: str, custom_flags: str = "") -> (str, str):
    """
    Run a Nikto scan against the given target URL.
    """
    command = ["nikto", "-h", target]
    if custom_flags:
        command.extend(custom_flags.split())
    st.write("Running command:", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.stdout, result.stderr
    except Exception as e:
        return "", f"Exception occurred: {e}"

def run_sslscan_scan(target: str, custom_flags: str = "") -> (str, str):
    """
    Run an SSLScan against the given target IP or domain.
    """
    command = ["sslscan", target]
    if custom_flags:
        command.extend(custom_flags.split())
    st.write("Running command:", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.stdout, result.stderr
    except Exception as e:
        return "", f"Exception occurred: {e}"

@st.cache_data(show_spinner=False)
def search_wordlists(search_directory: str) -> list:
    """Recursively search the given directory for .txt files (wordlists)."""
    wordlists = []
    for root, dirs, files in os.walk(search_directory):
        for file in files:
            if file.endswith('.txt'):
                wordlists.append(os.path.join(root, file))
    return wordlists

# =============================================================================
# Parsing, Summaries, and Risk Assessment for Reporting
# =============================================================================

def parse_nmap_output(nmap_output: str) -> dict:
    """Parse Nmap output to extract open ports (e.g., '22/tcp  open  ssh')."""
    open_ports = re.findall(r"(\d+/tcp)\s+open\s+(\S+)", nmap_output)
    return {"open_ports": open_ports, "count": len(open_ports)}

def parse_gobuster_output(gobuster_output: str) -> dict:
    """Parse Gobuster output to extract discovered directories (e.g., '/admin (Status: 200)')."""
    directories = re.findall(r"(/\S+)\s+\(Status:\s*(\d+)\)", gobuster_output)
    return {"directories": directories, "count": len(directories)}

def risk_assessment(nmap_data: dict, gobuster_data: dict) -> str:
    """Generate simple risk recommendations based on the parsed scan data."""
    recommendations = []
    for port, service in nmap_data.get("open_ports", []):
        if "22" in port:
            recommendations.append("SSH port is open. Check for weak credentials or outdated software.")
        if "80" in port or "443" in port:
            recommendations.append("Web service detected. Consider further web vulnerability scanning.")
    if gobuster_data.get("count", 0) > 0:
        for directory, status in gobuster_data.get("directories", []):
            if "admin" in directory.lower():
                recommendations.append(f"Potential admin panel found at {directory}. Investigate further.")
    if not recommendations:
        recommendations.append("No immediate risks detected based on the summaries.")
    return "\n".join(recommendations)

def generate_html_report(nmap_output, nmap_error, gobuster_output, gobuster_error,
                         target_ip, target_url, nmap_scan_option, wordlist_used,
                         custom_nmap_flags, custom_gobuster_flags,
                         nmap_summary, gobuster_summary, risk_recommendations) -> str:
    """
    Generate an HTML report containing global settings, raw outputs, parsed summaries, and risk recommendations.
    """
    report_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CTF Recon Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f4f4f4;
        }}
        h1, h2 {{
            color: #2c3e50;
        }}
        pre {{
            background-color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            overflow: auto;
        }}
        .section {{
            margin-bottom: 40px;
            background: #fff;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <h1>CTF Recon Report</h1>
    <div class="section">
        <h2>Global Settings</h2>
        <p><strong>Target IP/Domain (Nmap/SSLScan):</strong> {target_ip if target_ip else 'N/A'}</p>
        <p><strong>Nmap Scan Type:</strong> {nmap_scan_option}</p>
        <p><strong>Custom Nmap Flags:</strong> {custom_nmap_flags if custom_nmap_flags else 'None'}</p>
        <p><strong>Target URL (Gobuster/Nikto):</strong> {target_url if target_url else 'N/A'}</p>
        <p><strong>Wordlist Used (Gobuster):</strong> {wordlist_used if wordlist_used else 'N/A'}</p>
        <p><strong>Custom Gobuster Flags:</strong> {custom_gobuster_flags if custom_gobuster_flags else 'None'}</p>
    </div>
    <div class="section">
        <h2>Nmap Scan Output</h2>
        <pre>{nmap_output if nmap_output else "No output available."}</pre>
        <h3>Nmap Scan Errors</h3>
        <pre>{nmap_error if nmap_error else "No errors."}</pre>
        <h3>Nmap Summary</h3>
        <pre>{json.dumps(nmap_summary, indent=2)}</pre>
    </div>
    <div class="section">
        <h2>Gobuster Scan Output</h2>
        <pre>{gobuster_output if gobuster_output else "No output available."}</pre>
        <h3>Gobuster Scan Errors</h3>
        <pre>{gobuster_error if gobuster_error else "No errors."}</pre>
        <h3>Gobuster Summary</h3>
        <pre>{json.dumps(gobuster_summary, indent=2)}</pre>
    </div>
    <div class="section">
        <h2>Risk Recommendations</h2>
        <pre>{risk_recommendations}</pre>
    </div>
</body>
</html>
"""
    return report_html

# =============================================================================
# Main App
# =============================================================================

def main():
    # Inject Cyberpunk CSS styles for the whole app
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css?family=Orbitron&display=swap');
        body {
            background-color: #0d0d0d;
            color: #00ffea;
            font-family: 'Orbitron', sans-serif;
        }
        h1, h2, h3 {
            color: #ff0099;
            text-shadow: 0 0 10px #ff0099;
        }
        pre {
            background-color: #1a1a1a;
            border: 1px solid #ff0099;
            color: #00ffea;
            padding: 10px;
            border-radius: 5px;
        }
        .section {
            margin-bottom: 40px;
            background: rgba(0, 0, 0, 0.8);
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(255, 0, 153, 0.5);
        }
        .stButton>button {
            background-color: #ff0099;
            border: none;
            color: #fff;
            font-size: 16px;
            padding: 10px 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px #ff0099;
            transition: background-color 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #ff3366;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    
    st.title("CTF Recon & Enumeration App")
    st.markdown("**Streamline your recon phase with customizable scans, additional tools, and session logging.**")
    
    # Initialize the scan history database
    init_db()

    # -----------------------------
    # Sidebar: Global Settings & Tool Checks
    # -----------------------------
    st.sidebar.markdown("## Global Settings")
    st.sidebar.info("Enter your target details and options.")
    
    if not command_exists("nmap"):
        st.sidebar.error("Nmap is not installed or not in PATH!")
    if not command_exists("gobuster"):
        st.sidebar.error("Gobuster is not installed or not in PATH!")
    if not command_exists("nikto"):
        st.sidebar.error("Nikto is not installed or not in PATH!")
    if not command_exists("sslscan"):
        st.sidebar.error("SSLScan is not installed or not in PATH!")
    
    # Global target settings (re-used across tools)
    target_ip = st.sidebar.text_input("Target IP/Domain (Nmap & SSLScan)", value="",
                                        help="Enter the IP address or domain for Nmap/SSLScan")
    target_url = st.sidebar.text_input("Target URL (Gobuster & Nikto)", value="",
                                       help="Enter the target URL for Gobuster/Nikto (e.g., http://example.com)")
    wordlist_dir = st.sidebar.text_input("Wordlists Directory (Gobuster)", value="/usr/share/wordlists",
                                         help="Directory containing wordlists (.txt files)")
    # Option to upload a custom wordlist
    uploaded_wordlist = st.sidebar.file_uploader("Or upload a custom wordlist", type=["txt"])
    
    # -----------------------------
    # Session State Initialization for Scan Outputs/Options
    # -----------------------------
    for key in ["nmap_output", "nmap_error", "gobuster_output", "gobuster_error",
                "nikto_output", "nikto_error", "sslscan_output", "sslscan_error",
                "nmap_scan_option", "custom_nmap_flags", "wordlist_choice", "custom_gobuster_flags",
                "custom_nikto_flags", "custom_sslscan_flags"]:
        if key not in st.session_state:
            st.session_state[key] = ""
    
    # -----------------------------
    # Tabs for Different Tools and Functions
    # -----------------------------
    tabs = st.tabs(["Nmap Scanner", "Gobuster Scanner", "Nikto Scanner", "SSLScan Scanner", "Full Report", "History"])
    
    # -----------------------------
    # Nmap Scanner Tab
    # -----------------------------
    with tabs[0]:
        st.header("Nmap Scanner")
        if not target_ip:
            st.warning("Please enter a target IP/Domain in the sidebar.")
        else:
            nmap_scan_option = st.selectbox("Select Nmap Scan Type:", 
                                            ["Quick Scan", "Intense Scan", "Ping Scan", "SYN Scan", "Service Version"])
            custom_nmap_flags = st.text_input("Custom Nmap Flags (optional)", value="",
                                              help="Add any additional flags (e.g., --script vuln)")
            if st.button("Run Nmap Scan"):
                with st.spinner(f"Running {nmap_scan_option} on {target_ip}..."):
                    stdout, stderr = run_nmap_scan(target_ip, nmap_scan_option, custom_nmap_flags)
                st.session_state.nmap_output = stdout
                st.session_state.nmap_error = stderr
                st.session_state.nmap_scan_option = nmap_scan_option
                st.session_state.custom_nmap_flags = custom_nmap_flags
                # Save this scan to history
                parameters = f"Scan Option: {nmap_scan_option}, Custom Flags: {custom_nmap_flags}"
                save_scan_to_db("Nmap", target_ip, parameters, stdout, stderr)
                if stdout:
                    st.subheader("Nmap Output")
                    st.text_area("Output", stdout, height=300)
                if stderr:
                    st.error("Nmap Error")
                    st.text_area("Error", stderr, height=100)
    
    # -----------------------------
    # Gobuster Scanner Tab
    # -----------------------------
    with tabs[1]:
        st.header("Gobuster Scanner")
        if not target_url:
            st.warning("Please enter a target URL in the sidebar.")
        else:
            st.markdown(f"**Searching for wordlists in:** `{wordlist_dir}`")
            if os.path.exists(wordlist_dir):
                found_wordlists = search_wordlists(wordlist_dir)
            else:
                found_wordlists = []
                st.error(f"Directory `{wordlist_dir}` does not exist.")
            if uploaded_wordlist is not None:
                st.info("Using uploaded wordlist.")
                wordlist_choice = uploaded_wordlist.name
                temp_dir = "temp_wordlists"
                os.makedirs(temp_dir, exist_ok=True)
                temp_path = os.path.join(temp_dir, uploaded_wordlist.name)
                with open(temp_path, "wb") as f:
                    f.write(uploaded_wordlist.getbuffer())
                wordlist_path = temp_path
            elif found_wordlists:
                wordlist_path = st.selectbox("Select a Wordlist:", found_wordlists)
                wordlist_choice = wordlist_path
            else:
                wordlist_path = ""
                wordlist_choice = ""
            custom_gobuster_flags = st.text_input("Custom Gobuster Flags (optional)", value="",
                                                  help="Add any additional flags for Gobuster")
            if st.button("Run Gobuster Scan"):
                if not wordlist_path:
                    st.warning("Please select or upload a valid wordlist.")
                else:
                    with st.spinner(f"Running Gobuster scan on {target_url} using {wordlist_choice}..."):
                        stdout, stderr = run_gobuster_scan(target_url, wordlist_path, custom_gobuster_flags)
                    st.session_state.gobuster_output = stdout
                    st.session_state.gobuster_error = stderr
                    st.session_state.wordlist_choice = wordlist_choice
                    st.session_state.custom_gobuster_flags = custom_gobuster_flags
                    # Save scan to history
                    parameters = f"Wordlist: {wordlist_choice}, Custom Flags: {custom_gobuster_flags}"
                    save_scan_to_db("Gobuster", target_url, parameters, stdout, stderr)
                    if stdout:
                        st.subheader("Gobuster Output")
                        st.text_area("Output", stdout, height=300)
                    if stderr:
                        st.error("Gobuster Error")
                        st.text_area("Error", stderr, height=100)
    
    # -----------------------------
    # Nikto Scanner Tab
    # -----------------------------
    with tabs[2]:
        st.header("Nikto Scanner")
        if not target_url:
            st.warning("Please enter a target URL in the sidebar.")
        else:
            custom_nikto_flags = st.text_input("Custom Nikto Flags (optional)", value="",
                                               help="Add any additional flags for Nikto")
            if st.button("Run Nikto Scan"):
                with st.spinner(f"Running Nikto scan on {target_url}..."):
                    stdout, stderr = run_nikto_scan(target_url, custom_nikto_flags)
                st.session_state.nikto_output = stdout
                st.session_state.nikto_error = stderr
                st.session_state.custom_nikto_flags = custom_nikto_flags
                # Save scan to history
                parameters = f"Custom Flags: {custom_nikto_flags}"
                save_scan_to_db("Nikto", target_url, parameters, stdout, stderr)
                if stdout:
                    st.subheader("Nikto Output")
                    st.text_area("Output", stdout, height=300)
                if stderr:
                    st.error("Nikto Error")
                    st.text_area("Error", stderr, height=100)
    
    # -----------------------------
    # SSLScan Scanner Tab
    # -----------------------------
    with tabs[3]:
        st.header("SSLScan Scanner")
        if not target_ip:
            st.warning("Please enter a target IP/Domain in the sidebar.")
        else:
            custom_sslscan_flags = st.text_input("Custom SSLScan Flags (optional)", value="",
                                                 help="Add any additional flags for SSLScan")
            if st.button("Run SSLScan"):
                with st.spinner(f"Running SSLScan on {target_ip}..."):
                    stdout, stderr = run_sslscan_scan(target_ip, custom_sslscan_flags)
                st.session_state.sslscan_output = stdout
                st.session_state.sslscan_error = stderr
                st.session_state.custom_sslscan_flags = custom_sslscan_flags
                # Save scan to history
                parameters = f"Custom Flags: {custom_sslscan_flags}"
                save_scan_to_db("SSLScan", target_ip, parameters, stdout, stderr)
                if stdout:
                    st.subheader("SSLScan Output")
                    st.text_area("Output", stdout, height=300)
                if stderr:
                    st.error("SSLScan Error")
                    st.text_area("Error", stderr, height=100)
    
    # -----------------------------
    # Full Report Tab
    # -----------------------------
    with tabs[4]:
        st.header("Full Recon Report")
        st.markdown("This report compiles the global settings, scan outputs, summaries, and risk recommendations.")
        
        nmap_output = st.session_state.get("nmap_output", "")
        nmap_error = st.session_state.get("nmap_error", "")
        gobuster_output = st.session_state.get("gobuster_output", "")
        gobuster_error = st.session_state.get("gobuster_error", "")
        
        nmap_scan_option = st.session_state.get("nmap_scan_option", "N/A")
        custom_nmap_flags = st.session_state.get("custom_nmap_flags", "")
        wordlist_used = st.session_state.get("wordlist_choice", "N/A")
        custom_gobuster_flags = st.session_state.get("custom_gobuster_flags", "")
        
        nmap_summary = parse_nmap_output(nmap_output)
        gobuster_summary = parse_gobuster_output(gobuster_output)
        risk_recommendations = risk_assessment(nmap_summary, gobuster_summary)
        
        report_html = generate_html_report(
            nmap_output, nmap_error, gobuster_output, gobuster_error,
            target_ip, target_url, nmap_scan_option, wordlist_used,
            custom_nmap_flags, custom_gobuster_flags,
            nmap_summary, gobuster_summary, risk_recommendations
        )
        
        st.markdown("### HTML Report Preview")
        st.components.v1.html(report_html, height=600, scrolling=True)
        
        st.markdown("### Download Report")
        st.download_button(
            label="Download HTML Report",
            data=report_html,
            file_name="ctf_recon_report.html",
            mime="text/html"
        )
        if pdfkit:
            try:
                pdf_report = pdfkit.from_string(report_html, False)
                st.download_button(
                    label="Download PDF Report",
                    data=pdf_report,
                    file_name="ctf_recon_report.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"PDF generation failed: {e}")
        else:
            st.info("pdfkit is not installed; PDF export is unavailable.")
        report_json = {
            "global_settings": {
                "target_ip": target_ip,
                "nmap_scan_option": nmap_scan_option,
                "custom_nmap_flags": custom_nmap_flags,
                "target_url": target_url,
                "wordlist_used": wordlist_used,
                "custom_gobuster_flags": custom_gobuster_flags
            },
            "nmap": {
                "raw_output": nmap_output,
                "error": nmap_error,
                "summary": nmap_summary
            },
            "gobuster": {
                "raw_output": gobuster_output,
                "error": gobuster_error,
                "summary": gobuster_summary
            },
            "risk_recommendations": risk_recommendations
        }
        st.download_button(
            label="Download JSON Report",
            data=json.dumps(report_json, indent=2),
            file_name="ctf_recon_report.json",
            mime="application/json"
        )
    
    # -----------------------------
    # History Tab
    # -----------------------------
    with tabs[5]:
        st.header("Scan History")
        st.markdown("Below is a record of all scans executed through this app.")
        history = get_history()
        if history:
            # Display the history in a table
            st.table(history)
        else:
            st.info("No scan history available.")
        
        # Provide options to clear or export history
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Clear History"):
                clear_history()
                st.success("History cleared!")
        with col2:
            csv_data = export_history_to_csv()
            st.download_button(
                label="Export History as CSV",
                data=csv_data,
                file_name="scan_history.csv",
                mime="text/csv"
            )

if __name__ == "__main__":
    main()
