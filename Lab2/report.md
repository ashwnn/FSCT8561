## Reflection Questions

You must answer **all four** questions:

1. What information does port scanning reveal to an attacker?
Port scannling lets an attacker know what services/ports are listening and their status as well being able to discern what services are running.
2. Why is port scanning often the first step in an attack?
Because in order to perform an attack they need somewhere to perform it, it is often the first part of reconniscane to help determine running applications and services after which they can exploit.
3. How can defenders detect or limit scanning activities?
Using firewalls, and IDS/IPS alerts and rate limiting you can detect, mitigate and automatically filter these scans.
4. What are the limitations of basic port scanning?
It is very much incomplete and does not show the full picture. Filtered ports hide results, services are generally changed to a different port to mitigate basic attacks like these. UDP services are also often missed.

---

## Security Analysis

After performing a scan of ports 20-1024: an open 22/tcp running SSH. The scan also shows several ports as filtered: 25 (SMTP), 135 (MSRPC), 136, 137-139 (NetBIOS), and 445 (Microsoft-DS). Filtered usually indicate a firewall or upstream control is dropping probes, so the scanner cannot confirm whether services are listening. Even so, the key here is SSH is reachable from the network.

SSH is a high value target because it enables remote administration and can provide direct shell access. Attackers can abuse exposed SSH by brute forcing passwords, credential stuffing with leaked credentials, enumerating common usernames, and probing weak settings such as password logins or root access. If OpenSSH or the OS is unpatched, they may also attempt known vulnerabilities. The filtered Windows and SMB related ports suggest additional services may exist behind filtering, which can help and attacker follow up and probe deeper to see what they can find.

Attackers can use this output to focus effort on port 22: banner checks, authentication method discovery, and repeated login attempts within timeouts. A single successful login can enable data theft, persistence, and privilege escalation. Also watching for exposed SMB ports like 445, since SMB enumeration and file share access can be a large attack vector for an attcker.

Defensive measures should reduce exposure and harden authentication. Apply a default deny inbound firewall policy with UFW or equivalent iptables rules, and allow only required traffic. Restrict SSH to trusted source IPs, a VPN, or a bastion host. Disable password authentication, disable root SSH, enforce key based login, and patch OpenSSH and the OS regularly. Add an IDS system like CrowdSec to detect brute force patterns and push blocks to the firewall. Changing SSH from port 22 to an uncommon port can reduce background noise, but it is not a primary control.

