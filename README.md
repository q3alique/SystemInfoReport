# SystemInfoReport
The system information enumeration script is designed to gather and present comprehensive details about a computer system. The information collected is useful for system audits, troubleshooting, security assessments, and general system administration tasks. The script provides insights into the following key areas:

1. **Basic Information**: Includes the username, hostname, and IP address of the system.
2. **Group Memberships**: Lists the groups that the current user belongs to, offering insights into user privileges and access levels.
3. **User Privileges**: Displays the specific privileges assigned to the current user, such as shutdown rights and access controls.
4. Existing Users and Groups: Provides a list of all local users and groups, indicating which accounts are active.
5. **Operating System Details**: Includes the name, version, and architecture of the operating system, which is essential for compatibility and support purposes.
6. **Network Information**: Details about the network adapters, their IP addresses, and MAC addresses, which are crucial for network management and security.
7. **ARP Table**: Displays the Address Resolution Protocol (ARP) table, showing IP addresses and corresponding MAC addresses on the network.
8. **Listening Ports**: Lists the network ports that are currently open and listening, which is important for identifying running services and potential vulnerabilities.
9. **Installed Applications**: Provides a list of all installed applications, including their versions and publishers, helping with software management and compliance.
10. **Running Processes**: Shows all currently running processes, including their IDs and CPU usage, which is useful for performance monitoring and process management.
11. **System Uptime**: Indicates how long the system has been running since the last reboot, useful for maintenance planning.
12. **Scheduled Tasks**: Lists all scheduled tasks on the system, which helps in understanding automated processes and maintenance schedules.
13. **Security Features**: Information on security features such as AMSI (Antimalware Scan Interface), AppLocker policies, and installed antivirus products.
14. **User Shell History**: Retrieves and displays the command history from PowerShell and CMD, which can be used for auditing user activities.

**Usage**:
`.\SystemInfoReport.ps1`

The HTML report is saved with a filename based on the system's hostname, username, and IP address, ensuring unique identification (e.g., HOSTNAME_Username_IP.html).
