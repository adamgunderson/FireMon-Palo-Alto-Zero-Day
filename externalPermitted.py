import sys
# Adding FireMon package path
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.8/site-packages')
try:
    import requests
    import zipfile
    import os
    import xml.etree.ElementTree as ET
    import re
    import csv
    from getpass import getpass
except:
    try:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')
        import requests
        import zipfile
        import os
        import xml.etree.ElementTree as ET
        import re
        import csv
        from getpass import getpass
    except:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.10/site-packages')
        import requests
        import zipfile
        import os
        import xml.etree.ElementTree as ET
        import re
        import csv
        from getpass import getpass

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

DOMAIN_ID = 1  # Assume domain ID is always 1

def get_auth_token(server, username, password):
    """Authenticate and get token."""
    print(f"Authenticating to {server}...")
    url = f"https://{server}/securitymanager/api/authentication/login"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()["token"]

def get_devices_in_group(server, token, device_group_id):
    """Get all devices in a group with pagination."""
    headers = {
        "X-FM-AUTH-Token": token,
        "Accept": "application/json"
    }
    devices = []
    page = 0
    while True:
        print(f"Fetching devices page {page + 1}...")
        url = f"https://{server}/securitymanager/api/domain/{DOMAIN_ID}/devicegroup/{device_group_id}/device?page={page}&pageSize=100"
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        current_batch = data.get("results", [])
        devices.extend(current_batch)
        print(f"Retrieved {len(current_batch)} devices from page {page + 1}")
        if len(current_batch) < 100:  # If fewer than 100 devices, it's the last page
            break
        page += 1
    
    print(f"Total devices found: {len(devices)}")
    return devices

def export_device_config(server, token, device_id):
    """Export device configuration."""
    url = f"https://{server}/securitymanager/api/domain/{DOMAIN_ID}/device/{device_id}/export/config"
    headers = {"X-FM-AUTH-Token": token, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.content

def extract_non_rfc1918_ips_from_permitted(xml_content):
    """Extract non-RFC1918 IPs from permitted-ip entries in XML."""
    rfc1918_prefixes = ["10.", "172.16.", "192.168."]
    valid_ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(?:/\d{1,2})?$")
    non_rfc1918_ips = []

    try:
        tree = ET.ElementTree(ET.fromstring(xml_content))
        permitted_ip_section = tree.findall(".//permitted-ip/entry")

        for entry in permitted_ip_section:
            ip_address = entry.get("name", "")
            if valid_ip_pattern.match(ip_address) and not any(ip_address.startswith(prefix) for prefix in rfc1918_prefixes):
                non_rfc1918_ips.append(ip_address)
    except ET.ParseError as e:
        print(f"Warning: XML parsing error - {str(e)}")
        return []
    
    return non_rfc1918_ips

def main():
    server = input("Enter FireMon server (default: localhost): ") or "localhost"
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    group_id = input("Enter Device Group ID: ")

    try:
        token = get_auth_token(server, username, password)
        print(f"Successfully authenticated to {server}")

        output_file = "non_rfc1918_entries.csv"
        with open(output_file, mode="w", newline="") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(["Device Name", "Management IP", "Non-RFC1918 IPs"])

            print(f"\nFetching devices in group {group_id}...")
            devices = get_devices_in_group(server, token, group_id)

            for index, device in enumerate(devices, 1):
                device_id = device["id"]
                device_name = device.get("name", "Unknown")
                # Fix: Changed from managementIP to managementIp
                management_ip = device.get("managementIp", "Unknown")

                print(f"\nProcessing device {index}/{len(devices)}: {device_name} ({device_id})")
                try:
                    print(f"Exporting configuration...")
                    config_zip_content = export_device_config(server, token, device_id)
                    zip_path = f"{device_name}_config.zip"
                    
                    print(f"Writing temporary zip file...")
                    with open(zip_path, "wb") as zipfile_handle:
                        zipfile_handle.write(config_zip_content)

                    extract_dir = f"./{device_name}_config"
                    print(f"Extracting configuration...")
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        zip_ref.extractall(extract_dir)

                    xml_file_path = os.path.join(extract_dir, "running")
                    if os.path.exists(xml_file_path):
                        print(f"Analyzing configuration...")
                        with open(xml_file_path, "r") as xml_file:
                            xml_content = xml_file.read()
                            non_rfc1918_ips = extract_non_rfc1918_ips_from_permitted(xml_content)
                            if non_rfc1918_ips:
                                print(f"Found {len(non_rfc1918_ips)} non-RFC1918 IPs")
                                csvwriter.writerow([device_name, management_ip, ", ".join(non_rfc1918_ips)])
                            else:
                                print("No non-RFC1918 IPs found")
                    else:
                        print(f"Warning: XML file not found for {device_name}")

                    # Cleanup
                    print("Cleaning up temporary files...")
                    os.remove(zip_path)
                    os.system(f"rm -rf {extract_dir}")

                except requests.exceptions.HTTPError as http_err:
                    if http_err.response.status_code == 404:
                        print(f"Error: Device {device_name} ({device_id}) not found. Skipping...")
                    else:
                        print(f"HTTP error for device {device_name} ({device_id}): {http_err}")
                except Exception as e:
                    print(f"Error processing device {device_name} ({device_id}): {e}")

        print(f"\nProcessing complete. Results saved to {output_file}")

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to server: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
