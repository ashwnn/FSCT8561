import nmap, sys, socket

def main():
    try:
        if len(sys.argv) < 2:
            print("python scanner.py <target ip>")
            exit(1)

        target = sys.argv[1]

        try:
            socket.gethostbyname(target)  # try and resolve hostname
        except socket.gaierror:
            print(f"Invalid hostname: {target}")
            exit(1)

        scanner = nmap.PortScanner()
        print("Scanning will take some time, please wait.")
        scanner.scan(target, "20-1024", "-sT --host-timeout 30s")

        print("\n" + "=" * 50)
        print(f" Scan Report for {target}")
        print("=" * 50)
        
        for host in scanner.all_hosts():
            print(f"\nHost: {host}")
            print("-" * 50)
            
            for p in scanner[host].all_protocols():
                print(f"Protocol: {p.upper()}")
                print("  Port  | State  | Service")
                print("  ------+--------+----------------")
                
                ports = scanner[host][p].keys()
                for port in sorted(ports):
                    state = scanner[host][p][port]["state"]
                    name = scanner[host][p][port]["name"]
                    print(f"  {port:>5} | {state:<6} | {name}")
        
        print("\n" + "=" * 50)

        if not scanner.all_hosts():
            print("Host unreachable or no ports in range")

    except nmap.PortScannerError as e:
        print(f"Nmap error: {e}")
    except PermissionError:
        print("Error: Need elevated privileges to run nmap")
    except socket.timeout:
        print("Error: Network timeout during scan")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

