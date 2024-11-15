# Management Interface Access Audit Script

## Overview

This security audit script is designed to help organizations identify potentially risky configurations in their Palo Alto Networks firewall deployments. Specifically, it audits management interface access controls by identifying non-RFC1918 (public) IP addresses that have been granted management access to firewall interfaces.

## Business Context

Recent security advisories have emphasized the critical importance of restricting management interface access to trusted IP addresses only, and specifically preventing access from the public internet. This script helps security teams:

1. Quickly audit their entire firewall estate
2. Identify configurations that may need immediate review
3. Document current management access configurations
4. Support remediation planning

## Prerequisites

- FireMon Security Manager installation
- Python 3.8 or higher
- Required Python packages:
  - requests
  - zipfile
  - xml.etree.ElementTree
  - csv

## Features

- Automatic discovery of devices within specified device groups
- Extraction and analysis of management interface configurations
- Identification of non-RFC1918 permitted IP addresses
- CSV report generation for documentation and review
- Progress reporting and error handling
- Cleanup of temporary files

## Usage

1. Run the script:
```bash
python management_interface_audit.py
```

2. Enter the requested information:
- FireMon server address
- Username
- Password
- Device Group ID

3. The script will generate a CSV file named `non_rfc1918_entries.csv` containing:
- Device Name
- Management IP
- List of non-RFC1918 IPs configured for management access

## Output Format

The CSV output includes:
```csv
Device Name, Management IP, Non-RFC1918 IPs
PA-FW-01, 10.1.1.1, 203.0.113.0/24, 198.51.100.0/24
```

## Security Considerations

- The script should be run from a secure management workstation
- Credentials with read-only access are sufficient
- All temporary files are automatically cleaned up
- SSL certificate warnings are suppressed - ensure you're connecting to the correct server

## Best Practices

After running this script:

1. Review all identified non-RFC1918 IP addresses
2. Validate whether these IPs represent legitimate management stations
3. Document and justify any required public IP access
4. Consider implementing the following:
   - Use VPN for remote management access
   - Implement jump boxes/bastion hosts
   - Replace public IPs with private IP ranges where possible
   - Ensure management interfaces are not exposed to the internet

## Support

This script is provided for security auditing purposes. For implementation support:
- Contact your FireMon representative
- Review Palo Alto Networks security advisories
- Consult your security team for guidance on appropriate management access policies

## Disclaimer

This script is provided as-is for security auditing purposes. Always test in a non-production environment first and validate results before making any configuration changes.

---

**Note:** Regular audits of management access configurations are recommended as part of a comprehensive security program. This script should be part of a larger security strategy, not a standalone solution.
