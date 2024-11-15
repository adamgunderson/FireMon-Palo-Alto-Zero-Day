import sys
# Adding FireMon package path
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.8/site-packages')
try:
    import requests
    import os
    import zipfile
    import xml.etree.ElementTree as ET
    import csv
    import re
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
        import re
        from getpass import getpass
        import urllib3
    except:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.10/site-packages')
        import requests
        import os
        import zipfile
        import xml.etree.ElementTree as ET
        import csv
        import re
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

# Function to get devices in the specified group, paginated
def get_devices_in_group(server, token, device_group_id):
    headers = {
        "X-FM-AUTH-Token": token,
        "Accept": "application/json"
    }
    devices = []
    page = 0
    while True:
        url = f"https://{server}/securitymanager/api/domain/{DOMAIN_ID}/devicegroup/{device_group_id}/device?page={page}&pageSize=10"
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        devices.extend(data.get("results", []))
        if len(data.get("results", [])) < 10:  # If fewer than 10 devices, last page
            break
        page += 1
    return devices

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

# Function to extract non-RFC1918 IP entries from XML
def extract_non_rfc1918_ips_from_xml(xml_content):
    rfc1918_prefixes = ["10.", "172.16.", "192.168."]
    valid_ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(?:/\d{1,2})?$")
    tree = ET.ElementTree(ET.fromstring(xml_content))
    non_rfc1918_ips = []

    for entry in tree.findall(".//entry"):
        name = entry.get("name", "")
        if valid_ip_pattern.match(name) and not any(name.startswith(prefix) for prefix in rfc1918_prefixes):
            non_rfc1918_ips.append(name)
    return non_rfc1918_ips

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
            csvwriter.writerow(["Device Name", "Management IP", "Non-RFC1918 IPs"])
            
            for device in devices:
                device_id = device["id"]
                device_name = device.get("name", "Unknown")
                management_ip = device.get("managementIp", "Unknown")
                
                print(f"Processing device: {device_name} ({management_ip})")
                
                try:
                    config_zip_content = export_device_config(server, token, device_id)
                    
                    # Save and extract ZIP
                    zip_path = f"{device_name}_config.zip"
                    with open(zip_path, "wb") as zipfile_handle:
                        zipfile_handle.write(config_zip_content)
                    
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        zip_ref.extractall(f"./{device_name}_config")
                    
                    # Locate and parse XML
                    xml_file_path = f"./{device_name}_config/running"
                    if os.path.exists(xml_file_path):
                        with open(xml_file_path, "r") as xml_file:
                            xml_content = xml_file.read()
                            non_rfc1918_ips = extract_non_rfc1918_ips_from_xml(xml_content)
                            if non_rfc1918_ips:  # Only write to CSV if there are valid IPs
                                csvwriter.writerow([device_name, management_ip, ", ".join(non_rfc1918_ips)])
                    else:
                        print(f"XML file not found for {device_name}")
                    
                    # Clean up
                    os.remove(zip_path)
                    os.system(f"rm -rf ./{device_name}_config")
                
                except requests.exceptions.HTTPError as http_err:
                    if http_err.response.status_code == 404:
                        print(f"Device {device_name} ({device_id}) not found. Skipping...")
                    else:
                        print(f"HTTP error for device {device_name} ({device_id}): {http_err}")
                except Exception as e:
                    print(f"Error processing device {device_name} ({device_id}): {e}")
        
        print(f"Non-RFC1918 IPs saved to {output_csv}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
