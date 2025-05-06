import paramiko
import time

# Get user inputs
host = input("MikroTik IP address: ")
username = input("Username: ")
password = input("Password: ")

vpn_user = input("VPN Username: ")
vpn_pass = input("VPN Password: ")
ipsec_secret = input("IPSec Pre-Shared Key: ")
wan_interface = input("WAN Interface (e.g., ether1): ")

# DNS configuration
set_dns = input("Enable DNS configuration? (yes/no): ").strip().lower()
dns_commands = []
if set_dns == "yes":
    dns_server = input("DNS Server (e.g., 8.8.8.8): ")
    dns_commands = [
        f"/ip dns set servers={dns_server} allow-remote-requests=yes",
        f"/ppp profile set default local-address=192.168.100.1 remote-address=vpn-pool dns-server={dns_server}"
    ]
else:
    dns_commands = [
        "/ppp profile set default local-address=192.168.100.1 remote-address=vpn-pool"
    ]

# NAT + VPN + IPSec syslog logging
enable_syslog_nat_log = input("Send NAT, VPN, and IPSec logs to syslog server? (yes/no): ").strip().lower()
nat_log_syslog_commands = []
if enable_syslog_nat_log == "yes":
    syslog_ip = input("Syslog server IP address: ")
    syslog_port = input("Syslog port (default: 514): ").strip() or "514"
    nat_log_syslog_commands = [
        f"/ip firewall nat add chain=srcnat src-address=192.168.100.0/24 out-interface={wan_interface} action=masquerade log=yes log-prefix=\"NAT-LOG\"",
        f"/system logging action add name=remoteSyslog bsd-syslog=yes remote={syslog_ip} remote-port={syslog_port} target=remote",
        "/system logging add topics=firewall action=remoteSyslog",
        "/system logging add topics=ppp action=remoteSyslog",
        "/system logging add topics=ipsec action=remoteSyslog",
        "/system logging add topics=info action=remoteSyslog"
    ]
else:
    nat_log_syslog_commands = [
        f"/ip firewall nat add chain=srcnat src-address=192.168.100.0/24 out-interface={wan_interface} action=masquerade"
    ]

# Base VPN configuration
base_commands = [
    "/ip pool add name=vpn-pool ranges=192.168.100.10-192.168.100.50",
    f"/ppp secret add name={vpn_user} password={vpn_pass} service=l2tp profile=default",
    "/ip ipsec proposal add name=l2tp-proposal auth-algorithms=sha1 enc-algorithms=aes-256-cbc pfs-group=none",
    f"/ip ipsec peer add exchange-mode=main generate-policy=port-override secret=\"{ipsec_secret}\" "
    "address=0.0.0.0/0 enc-algorithm=aes-256 hash-algorithm=sha1 dh-group=modp1024",
    "/ip ipsec policy add proposal=l2tp-proposal template=yes",
    f"/interface l2tp-server server set enabled=yes default-profile=default use-ipsec=yes ipsec-secret=\"{ipsec_secret}\"",
    "/ip firewall filter add chain=input protocol=udp port=500,4500,1701 action=accept comment=\"L2TP VPN Ports\"",
    "/ip firewall filter add chain=input protocol=ipsec-esp action=accept",
    "/ip firewall filter add chain=input protocol=ipsec-ah action=accept"
]

# Combine all commands
commands = dns_commands + base_commands + nat_log_syslog_commands

# Execute configuration
def configure_mikrotik():
    print("\n Connecting to MikroTik...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password, port=22)
        shell = ssh.invoke_shell()
        for cmd in commands:
            print(f" Executing: {cmd}")
            shell.send(cmd + '\n')
            time.sleep(0.6)
        print("\n Configuration completed successfully. Logs will be sent to the syslog server if enabled.")
    except Exception as e:
        print(f"\n Error: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    configure_mikrotik()
