# Ubuntu Server 24.04 LTS Hardening Utility

**Version:** 1.1.0  
**Target:** Ubuntu Server 24.04 LTS (Noble)  
**Script:** `ubuntu-24.04-hardening.sh`

This is a conservative, role-neutral hardening baseline for a normal Ubuntu Server 24.04 LTS host. It is designed to improve the operating-system security posture without blindly applying every CIS item or breaking common server functions.

It provides four modes:

- `--audit`: read-only posture report; this is the default.
- `--dry-run`: validates the environment and prints the intended policy without changing the system.
- `--apply`: creates a checksummed backup and applies the selected controls.
- `--rollback`: restores backed-up configuration, runtime sysctls, SSH-key metadata, service states, and prior UFW state.

## Important operating rule

Keep the current SSH session open until a second, separate SSH login succeeds. Also keep the cloud/provider console available. Host UFW rules do not replace cloud security groups, provider firewalls, load-balancer rules, VPN ACLs, or upstream network policy.

## Core safeguards

The script is intentionally lockout-resistant:

- It does not install or expose OpenSSH when the server is absent.
- It validates the current OpenSSH configuration with `sshd -t` before changing it.
- It writes an early Ubuntu SSH drop-in and verifies both global and contextual effective values with `sshd -T`.
- It disables SSH passwords automatically only when it finds a valid local key for a non-root sudo user **and** confirms the current session was accepted with public-key authentication.
- Explicit `--disable-password-auth` still requires a valid local key and sudo account.
- Key-only mode sets `AuthenticationMethods publickey`, disables keyboard-interactive/password authentication, and disables direct root SSH login.
- It prepends the SSH UFW rule before user-level rules and opens SSH before enabling the firewall.
- It checks whether the current SSH source address falls within at least one supplied SSH CIDR.
- It never resets UFW, deletes existing firewall rules, pins obsolete SSH algorithms, or blindly disables IPv6, forwarding, or user namespaces.
- It creates root-only, SHA-256-verified backups before package/configuration changes.
- Audit and dry-run modes do not create or modify the hardening log.

## Controls applied by default

The default `--apply` profile configures:

- OpenSSH baseline hardening when `openssh-server` already exists.
- UFW default-deny inbound/routed policy, default-allow outbound policy, IPv4/IPv6 support, low-volume logging, and an SSH rate-limit rule.
- Fail2ban with a systemd-backed SSH jail.
- Ubuntu unattended upgrades while preserving Ubuntu's vendor-managed allowed origins.
- PAM password quality with a length-first 15-character policy, dictionary/user/GECOS checks, and no forced character-class composition or routine password expiry.
- Restrictive defaults for future home directories and login-shell umask.
- `sudo` PTY use, a short credential cache, command logging, and log rotation.
- A compatibility-conscious kernel/network sysctl baseline.
- Persistent journald storage and restrictive rsyslog file modes.
- Coredump suppression unless `--keep-coredumps` is selected.
- Linux Audit rules for identity, sudo, SSH, audit configuration, networking, systemd, cron, clock/hostname changes, mounts, and kernel modules.
- AppArmor service enablement/reload without converting existing profile modes.
- Restrictive permissions for account databases, sudoers, GRUB configuration, and SSH host keys.

Optional controls include AIDE initialization, strict reverse-path filtering, stricter uncommon-module blocking, immediate package upgrades, unattended reboot scheduling, SSH forwarding disablement, and immutable audit rules.

## What it deliberately does not automate

No generic script can safely infer every server role. This utility therefore does not automatically:

- Configure application-specific TLS, database permissions, web-server policy, secrets, containers, Kubernetes, or cloud IAM.
- Restrict arbitrary application ports to source CIDRs. `--ssh-allow-cidr` applies only to SSH; add reviewed UFW/nftables rules separately for other services.
- Remove packages or disable arbitrary services merely because they appear unnecessary.
- Change SSH ports or pin cipher/MAC/KEX lists that age badly and can block modern clients.
- Retrofit full-disk encryption, Secure Boot, TPM policy, a GRUB password, encrypted backups, or remote log collection.
- Force password rotation or arbitrary uppercase/lowercase/digit/symbol composition rules.
- Claim CIS, PCI DSS, ISO 27001, SOC 2, or any other compliance certification.

## Preflight checklist

Before applying to a production server:

1. Create a provider snapshot or VM snapshot.
2. Confirm provider-console or out-of-band access.
3. Confirm a non-root administrator exists and can use `sudo`.
4. Confirm a new SSH window can authenticate with the administrator's key.
5. Identify every required inbound TCP/UDP port.
6. Review Docker, containerd, Kubernetes, VPN, policy-routing, multi-homing, and domain-identity requirements.
7. Test the exact command on a disposable clone first.

## Install

```bash
sudo install -m 0750 ubuntu-24.04-hardening.sh /usr/local/sbin/ubuntu-hardening
sudo bash -n /usr/local/sbin/ubuntu-hardening
sudo /usr/local/sbin/ubuntu-hardening --help
```

Verify the supplied checksum from the same directory:

```bash
sha256sum -c ubuntu-24.04-hardening.sha256
```

For an additional local static-analysis pass:

```bash
shellcheck -x /usr/local/sbin/ubuntu-hardening
```

## Recommended rollout

### 1. Audit

```bash
sudo /usr/local/sbin/ubuntu-hardening --audit
```

The audit reports posture but returns a technical report, not a compliance attestation. Package-upgrade counts use the host's current APT metadata.

### 2. Dry-run the exact intended command

Typical web server:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --dry-run \
  --admin-user deploy \
  --allow-tcp 80,443
```

The default `auto` SSH policy disables passwords only when all key/session safety checks succeed. Otherwise, it preserves the current password-authentication policy and prints a warning.

### 3. Apply

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user deploy \
  --allow-tcp 80,443
```

Keep this session open. Open a second terminal and verify:

```bash
ssh deploy@SERVER_IP
sudo -v
```

Only close the original session after the second login and sudo test succeed.

## Key-only SSH with source restriction

Replace both example values before executing:

```bash
ADMIN_USER='deploy'
TRUSTED_SSH_CIDR='203.0.113.10/32'

sudo /usr/local/sbin/ubuntu-hardening \
  --dry-run \
  --admin-user "$ADMIN_USER" \
  --disable-password-auth \
  --ssh-allow-cidr "$TRUSTED_SSH_CIDR" \
  --allow-tcp 80,443

sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user "$ADMIN_USER" \
  --disable-password-auth \
  --ssh-allow-cidr "$TRUSTED_SSH_CIDR" \
  --allow-tcp 80,443
```

`203.0.113.0/24` is documentation-only address space. Do not copy it as a real access policy. Supply every legitimate office, VPN, bastion, or administrator source network by repeating `--ssh-allow-cidr`.

## Common profiles

Preserve SSH password authentication explicitly:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user deploy \
  --preserve-password-auth \
  --allow-tcp 80,443
```

Web server plus WireGuard:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user deploy \
  --allow-tcp 80,443 \
  --allow-udp 51820
```

Enable AIDE after the system/application deployment is stable:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user deploy \
  --allow-tcp 80,443 \
  --with-aide
```

Allow unattended-upgrades to reboot at 03:30 local server time:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user deploy \
  --allow-tcp 80,443 \
  --auto-reboot 03:30
```

For SSSD/Winbind or a heavily customized PAM stack, skip local pwquality until tested:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --apply \
  --admin-user deploy \
  --allow-tcp 80,443 \
  --no-pwquality
```

## Rollback

List backups:

```bash
sudo ls -lah /var/backups/ubuntu-hardening/
```

Restore the most recent backup:

```bash
sudo /usr/local/sbin/ubuntu-hardening --rollback latest
```

Restore a specific transaction:

```bash
sudo /usr/local/sbin/ubuntu-hardening \
  --rollback /var/backups/ubuntu-hardening/20260728T120000Z-12345
```

Rollback validates root ownership, permissions, archive member paths, and SHA-256 checksums before extraction. It restores:

- Backed-up configuration and managed files.
- Administrator SSH home/key-file metadata changed by the script.
- Saved runtime sysctl values.
- Recorded service active/enabled/masked states.
- The prior UFW active/inactive state and backed-up UFW configuration.
- Runtime audit rules when the kernel audit subsystem is not immutable.
- Pre-existing `/var/log/journal` and `/var/log/sudo.log` ownership/modes.

Rollback intentionally does **not** uninstall packages, downgrade package upgrades, delete generated AIDE databases, or delete security logs created after hardening. If audit rules were made immutable with `--audit-immutable`, a reboot is required to replace the running rule set after persistent rules are restored.

## Option reference

Run `--help` for the authoritative list. Important options are:

| Option | Effect |
|---|---|
| `--admin-user USER` | Non-root sudo user used for SSH lockout checks. |
| `--disable-password-auth` | Explicitly require key-only SSH after local-key validation. |
| `--preserve-password-auth` | Never change the effective SSH password policy. |
| `--ssh-allow-cidr CIDR` | Restrict SSH to one source network; repeatable. |
| `--allow-tcp PORTS` | Globally allow comma-separated inbound TCP ports. |
| `--allow-udp PORTS` | Globally allow comma-separated inbound UDP ports. |
| `--upgrade` | Apply currently available package upgrades during the transaction. |
| `--auto-reboot HH:MM` | Permit unattended-upgrades to reboot at a local time. |
| `--with-aide` | Initialize AIDE and enable its daily timer. |
| `--strict-rpf` | Use strict `rp_filter=1`; can break asymmetric/policy routing. |
| `--strict-modules` | Block uncommon filesystem/protocol modules on future load. |
| `--audit-immutable` | Set audit `-e 2`; rules cannot change again until reboot. |
| `--disable-ssh-forwarding` | Disable all SSH forwarding/tunneling features. |
| `--keep-coredumps` | Remove this script's coredump restrictions while preserving foreign files. |
| `--no-*` controls | Skip that module; they do not generally dismantle unrelated pre-existing policy. |
| `--force` | Override environment/conflict guards, not malformed input or SSH-key safety. |

## Compatibility cautions

- **Docker/containerd/Kubernetes:** published ports and runtime chains can interact with or bypass host UFW policy. Review `ss -lntup`, `ufw show raw`, nftables/iptables rules, and runtime network configuration.
- **Routers, NAT gateways, load balancers, multi-homed hosts, and policy routing:** review redirect, routed-policy, and reverse-path settings before applying. The compatible default is loose `rp_filter=2`; `--strict-rpf` is opt-in.
- **VPNs and SSH tunnels:** do not use `--disable-ssh-forwarding` unless forwarding is genuinely unnecessary.
- **SCTP, RDS, DCCP, TIPC, HFS/HFS+, JFFS2, and CramFS workloads:** do not use `--strict-modules` without confirming none are required.
- **Forensics and crash analysis:** use `--keep-coredumps` when coredumps are an intentional incident-response or debugging control; protect their confidentiality separately.
- **Domain identity:** SSSD/Winbind and custom PAM stacks require dedicated testing; use `--no-pwquality` when uncertain.
- **Desktop, WSL, containers:** the script refuses these by default. `--force` is an expert override, not a compatibility guarantee.

## Operational review after applying

```bash
sudo /usr/local/sbin/ubuntu-hardening --audit
sudo sshd -t
sudo sshd -T | less
sudo ufw status numbered
sudo ufw show raw
sudo fail2ban-client status sshd
sudo auditctl -s
sudo auditctl -l
sudo aa-status
systemctl --failed
ss -lntup
journalctl -p warning..alert --since today
```

Also review application logs, monitoring, backups, restore tests, cloud firewall rules, exposed DNS records, TLS configuration, credentials, and vulnerability-management results.

## Official references

- Ubuntu OpenSSH server documentation: <https://ubuntu.com/server/docs/how-to/security/openssh-server/>
- Ubuntu automatic-updates documentation: <https://ubuntu.com/server/docs/how-to/software/automatic-updates/>
- Ubuntu AppArmor documentation: <https://ubuntu.com/server/docs/how-to/security/apparmor/>
- Ubuntu Security Guide: <https://documentation.ubuntu.com/security/docs/compliance/usg/>
- Ubuntu Noble `pwquality.conf(5)`: <https://manpages.ubuntu.com/manpages/noble/man5/pwquality.conf.5.html>
- Ubuntu Noble `pam-auth-update(8)`: <https://manpages.ubuntu.com/manpages/noble/man8/pam-auth-update.8.html>
- Ubuntu Noble `ufw(8)`: <https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html>
- Ubuntu Noble `audit.rules(7)`: <https://manpages.ubuntu.com/manpages/noble/man7/audit.rules.7.html>
- Linux kernel IP sysctl documentation: <https://docs.kernel.org/networking/ip-sysctl.html>
- NIST SP 800-63B: <https://pages.nist.gov/800-63-4/sp800-63b.html>

## Validation performed on this artifact

The supplied version was checked with:

- `bash -n` syntax validation.
- Helper-level tests for ports, CIDRs, managed-file writes/removal, metadata state, tar-path validation, state serialization, and sysctl snapshots.
- Negative tests for invalid ports, invalid CIDRs, invalid reboot times, conflicting modes, and unsafe key-only requests.
- Read-only audit and dry-run execution tests.
- Audit runtime execution in a non-Ubuntu container using the explicit `--force` test override.
- `logrotate --debug` validation for the sudo log policy.

This does not replace testing the exact command on a disposable Ubuntu 24.04 clone that matches the production server's network, identity, storage, and application roles.
