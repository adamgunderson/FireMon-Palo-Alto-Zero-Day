import sys
# Adding FireMon package path
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.8/site-packages')
try:
    import requests
    import os
    import zipfile
    import xml.etree.ElementTree as ET
    import csv
    from getpass import getpass
    import urllib3
except:
    try:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')
        import requests
        import os
        import zipfile
        import xml.etree.ElementTree as ET
        import csv
        from getpass import getpass
        import urllib3
    except:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.10/site-packages')
        import requests
        import os
        import zipfile
        import xml.etree.ElementTree as ET
        import csv
        from getpass import getpass
        import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DOMAIN_ID = 1

# Function to authenticate and retrieve token
def authenticate(server, username, password):
    url = f"https://{server}/securitymanager/api/authentication/login"
    headers = {"Content-Type": "application/json"}
    payload = {"username": username, "password": password}
    
    response = requests.post(url, json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("token")

# Function to get devices in the specified group
def get_devices_in_group(server, token, device_group_id):
    url = f"https://{server}/securitymanager/api/domain/{DOMAIN_ID}/devicegroup/{device_group_id}/device"
    headers = {
        "X-FM-AUTH-Token": token,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("results", [])

# Function to export device configuration
def export_device_config(server, token, device_id):
    url = f"https://{server}/securitymanager/api/domain/{DOMAIN_ID}/device/{device_id}/export/config"
    headers = {
        "X-FM-AUTH-Token": token,
        "Accept": "application/octet-stream"
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.content

# Function to extract non-RFC1918 entries from XML
def extract_non_rfc1918_entries_from_xml(xml_content):
    rfc1918_prefixes = ["10.", "172.16.", "192.168."]
    tree = ET.ElementTree(ET.fromstring(xml_content))
    non_rfc1918_entries = []

    for entry in tree.findall(".//entry"):
        name = entry.get("name", "")
        if not any(name.startswith(prefix) for prefix in rfc1918_prefixes):
            non_rfc1918_entries.append(name)
    return non_rfc1918_entries

# Main function
def main():
    # Prompt for user inputs
    server = input("Enter server (default: localhost): ").strip() or "localhost"
    username = input("Enter username: ").strip()
    password = getpass("Enter password: ").strip()
    device_group_id = input("Enter device group ID: ").strip()
    
    try:
        token = authenticate(server, username, password)
        print("Authentication successful.")
    except Exception as e:
        print(f"Authentication failed: {e}")
        return

    try:
        devices = get_devices_in_group(server, token, device_group_id)
        output_csv = "non_rfc1918_entries.csv"
        
        with open(output_csv, mode="w", newline="") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(["Device Name", "Management IP", "Non-RFC1918 Entries"])
            
            for device in devices:
                device_id = device["id"]
                device_name = device.get("name", "Unknown")
                management_ip = device.get("managementIp", "Unknown")
                
                print(f"Processing device: {device_name} ({management_ip})")
                config_zip_content = export_device_config(server, token, device_id)
                
                # Save and extract ZIP
                zip_path = f"{device_name}_config.zip"
                with open(zip_path, "wb") as zipfile_handle:
                    zipfile_handle.write(config_zip_content)
                
                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    zip_ref.extractall(f"./{device_name}_config")
                
                # Locate and parse XML
                xml_file_path = f"./{device_name}_config/running-config.xml"
                if os.path.exists(xml_file_path):
                    with open(xml_file_path, "r") as xml_file:
                        xml_content = xml_file.read()
                        non_rfc1918_entries = extract_non_rfc1918_entries_from_xml(xml_content)
                        csvwriter.writerow([device_name, management_ip, ", ".join(non_rfc1918_entries)])
                else:
                    print(f"XML file not found for {device_name}")
                
                # Clean up
                os.remove(zip_path)
                os.system(f"rm -rf ./{device_name}_config")
        
        print(f"Non-RFC1918 entries saved to {output_csv}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
