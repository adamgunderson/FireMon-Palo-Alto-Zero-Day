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

def get_auth_token(server, username, password):
    url = f"https://{server}/securitymanager/api/authentication/login"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()["token"]

def fetch_device_group(server, token, group_id, page):
    url = f"https://{server}/securitymanager/api/domain/1/devicegroup/{group_id}/device"
    headers = {"X-FM-AUTH-Token": token, "Content-Type": "application/json"}
    params = {"page": page, "pageSize": 100}
    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()
    return response.json()

def export_device_config(server, token, device_id):
    url = f"https://{server}/securitymanager/api/domain/1/device/{device_id}/export/config"
    headers = {"X-FM-AUTH-Token": token, "Content-Type": "application/json"}
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.content

def extract_non_rfc1918_ips_from_permitted(xml_content):
    rfc1918_prefixes = ["10.", "172.16.", "192.168."]
    valid_ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(?:/\d{1,2})?$")
    non_rfc1918_ips = []

    tree = ET.ElementTree(ET.fromstring(xml_content))
    permitted_ip_section = tree.findall(".//permitted-ip/entry")

    for entry in permitted_ip_section:
        ip_address = entry.get("name", "")
        if valid_ip_pattern.match(ip_address) and not any(ip_address.startswith(prefix) for prefix in rfc1918_prefixes):
            non_rfc1918_ips.append(ip_address)
    return non_rfc1918_ips

def main():
    server = input("Enter FireMon server (default: localhost): ") or "localhost"
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    group_id = input("Enter Device Group ID: ")

    token = get_auth_token(server, username, password)
    print(f"Authenticated to {server} successfully.")

    output_file = "non_rfc1918_entries.csv"
    with open(output_file, mode="w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Device Name", "Management IP", "Non-RFC1918 IPs"])
        page = 0
        while True:
            print(f"Fetching device group page {page}...")
            devices = fetch_device_group(server, token, group_id, page)
            if not devices["content"]:
                break

            for device in devices["content"]:
                device_id = device["id"]
                device_name = device.get("name", "Unknown")
                management_ip = device.get("managementIP", "Unknown")

                print(f"Processing device {device_name} ({device_id})...")
                try:
                    config_zip_content = export_device_config(server, token, device_id)
                    zip_path = f"{device_name}_config.zip"
                    with open(zip_path, "wb") as zipfile_handle:
                        zipfile_handle.write(config_zip_content)

                    extract_dir = f"./{device_name}_config"
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        zip_ref.extractall(extract_dir)

                    xml_file_path = os.path.join(extract_dir, "running")
                    if os.path.exists(xml_file_path):
                        with open(xml_file_path, "r") as xml_file:
                            xml_content = xml_file.read()
                            non_rfc1918_ips = extract_non_rfc1918_ips_from_permitted(xml_content)
                            if non_rfc1918_ips:
                                csvwriter.writerow([device_name, management_ip, ", ".join(non_rfc1918_ips)])
                            else:
                                print(f"No valid non-RFC1918 IPs found for {device_name}.")
                    else:
                        print(f"XML file not found for {device_name}.")

                    os.remove(zip_path)
                    os.system(f"rm -rf {extract_dir}")

                except requests.exceptions.HTTPError as http_err:
                    if http_err.response.status_code == 404:
                        print(f"Device {device_name} ({device_id}) not found. Skipping...")
                    else:
                        print(f"HTTP error for device {device_name} ({device_id}): {http_err}")
                except Exception as e:
                    print(f"Error processing device {device_name} ({device_id}): {e}")

            page += 1

    print(f"Processing complete. Results saved to {output_file}.")

if __name__ == "__main__":
    main()
