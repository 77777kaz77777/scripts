import csv
import subprocess
import os

# === Prompt for input ===
host_list = input("Enter comma-separated Proxmox IPs/hosts (e.g., 10.0.0.1,10.0.0.2): ").strip()
ssh_user = input("Enter SSH username (default: root): ").strip() or "root"
csv_file = input("Enter path to CSV file (e.g., users_vms.csv): ").strip()
role = "student"

# === Check if CSV exists ===
if not os.path.isfile(csv_file):
    print(f"❌ CSV file not found: {csv_file}")
    exit(1)

# === Normalize line endings (convert Windows to Unix line endings) ===
with open(csv_file, 'r', newline='') as f:
    lines = f.read().replace('\r\n', '\n').replace('\r', '\n')
with open(csv_file, 'w', newline='') as f:
    f.write(lines)

# === Split host list ===
proxmox_hosts = [host.strip() for host in host_list.split(",") if host.strip()]
print(f"📄 Reading CSV: {csv_file}")
print(f"🔐 Assigning role: {role}")
print(f"🌐 Target hosts: {', '.join(proxmox_hosts)}\n")

# === Process CSV ===
with open(csv_file, newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if not row or not row[0].strip():
            continue  # Skip blank lines

        pve_user = row[0].strip()
        vm_ids = [vmid.strip() for vmid in row[1:] if vmid.strip()]

        print(f"👤 Processing user: {pve_user}")

        for vmid in vm_ids:
            for host in proxmox_hosts:
                print(f"   🔧 Assigning VM {vmid} on {host} → {pve_user}")
                cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    f"{ssh_user}@{host}",
                    f"pveum aclmod /vms/{vmid} -user '{pve_user}' -role '{role}'"
                ]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    print("     ✔ Success")
                else:
                    print("     ❌ Failed")
                    print("     STDERR:", result.stderr.strip())
        print("---")

print("✅ All assignments complete.")
