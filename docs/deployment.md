# Deployment and Operations Guide

## 1. Overview of Deployment Topologies

RTProtect architectures feature two deployment targets:
1. **Protected Client Binaries:** Distributed to end users, running on untrusted local Windows machines.
2. **Activation Authority Service:** Hosted in a secured data center or cloud environment managing license registrations, seat reservations, and dynamic countermeasure distributions.

---

## 2. Deploying Protected Client Applications

When an application is protected via `rtprotect-tool integrate`, the compiled distribution folder contains the following mandatory deployment artifacts:

```text
ApplicationDeployment/
|-- Application.exe         # Protected native binary (containing pre-main hook and VM wrappers)
|-- client.license          # Signed, machine-bound Ed25519 license file
|-- release.manifest        # Cryptographic resource manifest containing SHA-256 digests
|-- release.sig             # 64-byte Ed25519 digital signature of release.manifest
|-- release.pub             # 32-byte Ed25519 public key used by the binary to verify release.sig
|-- libcrypto-*.dll         # Bundled OpenSSL runtime cryptographic library
+-- libssl-*.dll            # Bundled OpenSSL TLS runtime library
```

### 2.1 File Placement Rules
All auxiliary security files (`client.license`, `release.manifest`, `release.sig`, `release.pub`, OpenSSL DLLs) must reside in the exact same directory as the executable. The runtime glue resolves auxiliary files strictly relative to the loaded module path (`::GetModuleFileNameA`), preventing path-traversal and working-directory redirection attacks.

### 2.2 Authenticode Signing
For commercial software distribution, sign the final executable with a standard Microsoft Authenticode certificate:
```powershell
signtool sign /f vendor_cert.pfx /p "cert_password" /tr http://timestamp.digicert.com /td sha256 /fd sha256 Application.exe
```
*Note: Run `signtool` before running `rtprotect-tool integrate` (or regenerate the manifest digest via `rtprotect-tool manifest-build` after signing) so the manifest SHA-256 matches the Authenticode-signed binary on disk.*

---

## 3. Production Deployment of the Activation Server

The `rtprotect-activation-server` is a standalone service managing online license validations over HTTPS.

### 3.1 Network and Operating Environment
- **Operating System:** Windows Server 2019, 2022, or Windows 10/11 x64.
- **Network Ports:** Port 8443 (HTTPS) or port 8080 behind an enterprise reverse proxy.
- **Firewall Configuration:** Allow incoming TCP connections on the configured service port.

### 3.2 Vault Provisioning (Windows DPAPI)
In production, unencrypted plaintext private keys are prohibited. Provision keys directly into the Windows DPAPI encrypted vault:

```powershell
# 1. Provision the vendor Ed25519 activation token signing private key into the vault
rtprotect-activation-server.exe --provision-vault "prod-activation-key-01" "activation.pub"

# 2. Provision the database AES-256 envelope encryption key into the vault
rtprotect-activation-server.exe --provision-db-vault "prod-db-key-01"
```

### 3.3 Production Server Launch Command

```powershell
rtprotect-activation-server.exe `
    --port 8443 `
    --host 0.0.0.0 `
    --tls-cert "C:\Certificates\activation.crt" `
    --tls-key "C:\Certificates\activation.key" `
    --vault-id "prod-activation-key-01" `
    --db-vault-id "prod-db-key-01" `
    --db "C:\RTProtectData\activations.db" `
    --admin-token-file "C:\RTProtectData\admin_token.secret"
```

---

## 4. Running as a Windows Service

To ensure continuous operation and automatic startup across reboots, register the activation server with the Windows Service Control Manager (`sc.exe`):

```powershell
# 1. Create the service
sc.exe create "RTProtectActivation" `
    binPath= "C:\RTProtect\rtprotect-activation-server.exe --port 8443 --host 0.0.0.0 --tls-cert C:\Certificates\activation.crt --tls-key C:\Certificates\activation.key --vault-id prod-activation-key-01 --db-vault-id prod-db-key-01 --db C:\RTProtectData\activations.db --admin-token-file C:\RTProtectData\admin_token.secret" `
    start= auto `
    displayName= "RTProtect Activation Authority"

# 2. Configure automatic restart on failure
sc.exe failure "RTProtectActivation" reset= 86400 actions= restart/60000/restart/60000/restart/60000

# 3. Start the service
sc.exe start "RTProtectActivation"
```

---

## 5. Reverse Proxy Configuration (Nginx Example)

If terminating TLS at a reverse proxy and forwarding cleartext HTTP to the activation server on localhost:

```nginx
server {
    listen 443 ssl http2;
    server_name activation.vendor.com;

    ssl_certificate /etc/ssl/certs/activation.crt;
    ssl_certificate_key /etc/ssl/private/activation.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 6. Operational Monitoring and Maintenance

### 6.1 Health Check Endpoint
Load balancers and monitoring agents (Datadog, Prometheus, Nagios) should poll:
```text
GET /health
```
A healthy server returns `HTTP 200 OK` with payload `{"status":"ok"}`.

### 6.2 Administrative Audit Logs
Query recent operational events:
```powershell
curl.exe -H "Authorization: Bearer <admin-token>" https://activation.vendor.com/events
```

### 6.3 Anomaly and Abuse Detection
Query the automated abuse analytics engine to detect concurrent activation spikes or abnormal seat allocations:
```powershell
curl.exe -H "Authorization: Bearer <admin-token>" https://activation.vendor.com/analytics
```

### 6.4 Atomic Database Backups
Because `ActivationDatabase` commits writes atomically via replacement, the database file (`activations.db`) can be copied safely while the server is active without taking the service offline:
```powershell
Copy-Item "C:\RTProtectData\activations.db" "C:\Backups\activations_$(Get-Date -Format 'yyyyMMdd_HHmmss').db"
```
