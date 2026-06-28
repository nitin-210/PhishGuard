# PhishGuard Detonation Sandbox on an Isolated EC2 (production-grade)

This is the version you asked for: suspicious links are opened on a **disposable,
network-isolated AWS EC2 instance**, so that even if a link carries malware or a
virus it **cannot reach your personal resources or servers**, and it **cannot
even persist on the sandbox VM itself**.

## How the isolation works (three layers)

```
   Your backend (PhishGuard API)
          |  HTTPS, only this source is allowed in
          v
  ┌───────────────────────────────────────────────┐
  │  Isolated EC2 in a DEDICATED VPC               │   layer 1: network isolation
  │  - own VPC, no peering / VPN / transit gateway │   nothing internal to reach
  │  - NACL denies all private IP ranges outbound  │
  │  - security group: inbound only from backend   │
  │                                                │
  │   dispatcher.py                                │
  │      |  per link, launches...                  │
  │      v                                         │
  │   ┌──────────────────────────────┐            │   layer 2: ephemeral container
  │   │ fresh hardened container      │  --rm      │   created per link, destroyed
  │   │ (read-only, cap-drop, limits) │ ───────►   │   immediately after
  │   │ opens the link, screenshots   │  (gone)    │
  │   └──────────────────────────────┘            │
  └───────────────────────────────────────────────┘
          ^                                            layer 3: disposable host
          └─ recycle the whole EC2 on a schedule (Auto Scaling) so the VM itself
             is regularly thrown away and rebuilt clean.
```

1. **Network isolation — protects your resources.** The EC2 lives in its own VPC
   with no connection to anything else you own (no peering, no VPN). A network ACL
   additionally *denies* all outbound traffic to private IP ranges
   (`10/8`, `172.16/12`, `192.168/16`). So a compromised link can reach the public
   internet at most — never your databases, servers, or laptops. The security
   group only lets your backend's IP talk to it.

2. **Ephemeral containers — protect the VM.** The link is never opened on the EC2
   directly. For each link the dispatcher runs a **brand-new container** that is
   `--read-only`, drops all Linux capabilities, has `no-new-privileges`, strict
   CPU/RAM/PID limits, and a timeout — then is **destroyed (`--rm`)**. Nothing the
   link does survives the scan.

3. **Disposable host — defence in depth.** Even the EC2 is meant to be cattle, not
   a pet: run it in an Auto Scaling group (or re-run `terraform apply`) to recycle
   it regularly so the VM is rebuilt from a clean image.

## Deploy it

Prerequisites: an AWS account, the AWS CLI configured, and Terraform installed.

```bash
cd sandbox/aws/terraform
terraform init
terraform apply -var="allowed_cidr=YOUR.BACKEND.IP/32"
```
`allowed_cidr` is the only source allowed to call the sandbox — your backend's
public IP as a `/32` (or your VPN range). **Never** use `0.0.0.0/0`.

Terraform prints `sandbox_url`, e.g. `http://<public-ip>:9000`.

## Point the backend at it
On the machine running the PhishGuard API:
```powershell
$env:SANDBOX_URL="http://<public-ip>:9000"
uvicorn src.api:app --reload
```
Now every "🔬 Detonate safely" click opens the link on the isolated EC2, in a
throwaway container, and returns the screenshot + verdict.

## Tear it down (stop paying)
```bash
terraform destroy -var="allowed_cidr=YOUR.BACKEND.IP/32"
```

## Honest limits (put this in your report)
- No sandbox is 100% escape-proof. This design uses **defence in depth** (network
  isolation + ephemeral least-privilege containers + a disposable host) so that a
  single failure doesn't reach anything you care about.
- For stronger isolation you can swap Docker for **Firecracker microVMs / AWS
  Fargate**, add **egress filtering/proxying**, and put the dispatcher behind
  **private networking + IAM auth** instead of an IP allow-list.
- Running browsers against live malicious links costs money and carries risk;
  keep the instance small, recycle it, and destroy it when not in use.
