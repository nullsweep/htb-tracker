import streamlit as st
import subprocess
import os
import json
from datetime import datetime

st.title("HTB Machine Helper")

menu = st.sidebar.radio("Select an Option", ["Machine Info", "Nmap Scanner", "Gobuster Scanner", "Notes", "Enumeration Results", "Automation Scripts", "Export Data", "Save HTML Report"])

if 'machines' not in st.session_state:
    st.session_state['machines'] = {}

def save_data_to_file():
    with open("machines_data.json", "w") as file:
        json.dump(st.session_state['machines'], file)

def load_data_from_file():
    if os.path.exists("machines_data.json"):
        with open("machines_data.json", "r") as file:
            st.session_state['machines'] = json.load(file)

def generate_html_report():
    html_content = """<html>
    <head>
        <title>HTB Machine Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #2c3e50; }
            h2 { color: #34495e; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 5px 0; }
            .machine { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f9f9f9; }
            .key { font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>HTB Machine Report</h1>"""

    for name, details in st.session_state['machines'].items():
        html_content += f"<div class='machine'>"
        html_content += f"<h2>{name}</h2>"
        html_content += "<ul>"
        for key, value in details.items():
            html_content += f"<li><span class='key'>{key}:</span> {value}</li>"
        html_content += "</ul>"
        html_content += "</div>"

    html_content += "</body></html>"
    return html_content

load_data_from_file()

if menu == "Machine Info":
    st.header("Add or Update Machine Info")

    machine_name = st.text_input("Machine Name")
    ip_address = st.text_input("IP Address")
    difficulty = st.selectbox("Difficulty", ["Easy", "Medium", "Hard", "Insane"])
    status = st.selectbox("Status", ["Not Started", "In Progress", "Completed"])

    if st.button("Save Machine"):
        if machine_name and ip_address:
            st.session_state['machines'][machine_name] = {
                "IP Address": ip_address,
                "Difficulty": difficulty,
                "Status": status,
                "Last Updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            save_data_to_file()
            st.success(f"Saved information for {machine_name}.")
        else:
            st.error("Please fill in both the Machine Name and IP Address.")

    st.header("Current Machines")
    for name, details in st.session_state['machines'].items():
        st.write(f"**{name}** - {details}")

elif menu == "Nmap Scanner":
    st.header("Nmap Scanner")

    target_ip = st.text_input("Target IP Address")
    scan_options = st.text_area("Nmap Options", "-sC -sV -p- -T4")
    selected_machine = st.selectbox("Select Machine", st.session_state['machines'].keys(), index=0)

    if st.button("Run Nmap Scan"):
        if target_ip:
            with st.spinner("Running Nmap Scan..."):
                try:
                    result = subprocess.check_output(["nmap"] + scan_options.split() + [target_ip], text=True)
                    st.text_area("Scan Results", result, height=300)

                    # Save results to enumeration section
                    if selected_machine in st.session_state['machines']:
                        st.session_state['machines'][selected_machine]["Enumeration Results"] = \
                            st.session_state['machines'][selected_machine].get("Enumeration Results", "") + \
                            f"\n\nNmap Results:\n{result}"
                        save_data_to_file()
                        st.success(f"Results saved to {selected_machine}'s Enumeration Results.")
                except Exception as e:
                    st.error(f"Error running Nmap: {e}")
        else:
            st.error("Please provide a target IP address.")

elif menu == "Gobuster Scanner":
    st.header("Gobuster Scanner")

    target_url = st.text_input("Target URL (e.g., http://example.com)")
    wordlist = st.text_input("Wordlist Path (e.g., /usr/share/wordlists/dirb/common.txt)")
    extensions = st.text_input("File Extensions (comma-separated, e.g., php,html,txt)")
    threads = st.number_input("Number of Threads", min_value=1, max_value=100, value=10, step=1)
    selected_machine = st.selectbox("Select Machine", st.session_state['machines'].keys(), index=0)

    if st.button("Run Gobuster Scan"):
        if target_url and wordlist:
            try:
                cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-t", str(threads)]
                if extensions:
                    cmd.extend(["-x", extensions])

                with st.spinner("Running Gobuster Scan..."):
                    result = subprocess.check_output(cmd, text=True)
                st.text_area("Scan Results", result, height=300)

                # Save results to enumeration section
                if selected_machine in st.session_state['machines']:
                    st.session_state['machines'][selected_machine]["Enumeration Results"] = \
                        st.session_state['machines'][selected_machine].get("Enumeration Results", "") + \
                        f"\n\nGobuster Results:\n{result}"
                    save_data_to_file()
                    st.success(f"Results saved to {selected_machine}'s Enumeration Results.")
            except Exception as e:
                st.error(f"Error running Gobuster: {e}")
        else:
            st.error("Please provide both a Target URL and Wordlist Path.")

elif menu == "Notes":
    st.header("Machine Notes")

    if st.session_state['machines']:
        machine_selected = st.selectbox("Select Machine", st.session_state['machines'].keys())
        notes = st.text_area("Notes", st.session_state['machines'].get(machine_selected, {}).get("Notes", ""))

        if st.button("Save Notes"):
            st.session_state['machines'][machine_selected]["Notes"] = notes
            st.session_state['machines'][machine_selected]["Last Updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_data_to_file()
            st.success("Notes saved.")
    else:
        st.warning("No machines available. Please add a machine first.")

elif menu == "Enumeration Results":
    st.header("Store Enumeration Results")

    if st.session_state['machines']:
        machine_selected = st.selectbox("Select Machine", st.session_state['machines'].keys())
        enum_results = st.text_area("Enumeration Results", st.session_state['machines'].get(machine_selected, {}).get("Enumeration Results", ""))

        if st.button("Save Results"):
            st.session_state['machines'][machine_selected]["Enumeration Results"] = enum_results
            st.session_state['machines'][machine_selected]["Last Updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_data_to_file()
            st.success("Enumeration results saved.")

        st.subheader("Saved Results")
        if machine_selected in st.session_state['machines']:
            st.text_area("Saved Enumeration Results", st.session_state['machines'][machine_selected].get("Enumeration Results", ""), height=300)
    else:
        st.warning("No machines available. Please add a machine first.")

elif menu == "Automation Scripts":
    st.header("Automation Scripts")

    st.write("Run pre-configured scripts to automate repetitive tasks.")

    script_options = ["Update System", "Run Enumeration", "Cleanup"]
    selected_script = st.selectbox("Select Script", script_options)

    if st.button("Run Script"):
        try:
            if selected_script == "Update System":
                result = subprocess.check_output(["sudo", "apt", "update", "&&", "sudo", "apt", "upgrade", "-y"], text=True)
            elif selected_script == "Run Enumeration":
                result = subprocess.check_output(["echo", "Enumeration Script Placeholder"], text=True)
            elif selected_script == "Cleanup":
                result = subprocess.check_output(["echo", "Cleanup Script Placeholder"], text=True)
            st.text_area("Script Output", result, height=300)
        except Exception as e:
            st.error(f"Error running script: {e}")

elif menu == "Export Data":
    st.header("Export Data")

    st.write("Export all machine data as a JSON file.")

    if st.button("Export"):
        with open("exported_data.json", "w") as file:
            json.dump(st.session_state['machines'], file)
        with open("exported_data.json", "rb") as file:
            st.download_button("Download JSON File", file, "machines_data.json", "application/json")
            st.success("Data exported successfully.")

elif menu == "Save HTML Report":
    st.header("Save HTML Report")

    st.write("Generate and save an HTML report for all machines.")

    if st.button("Generate Report"):
        html_report = generate_html_report()
        with open("htb_report.html", "w") as file:
            file.write(html_report)
        with open("htb_report.html", "rb") as file:
            st.download_button("Download HTML Report", file, "htb_report.html", "text/html")
            st.success("HTML report generated and saved successfully.")
