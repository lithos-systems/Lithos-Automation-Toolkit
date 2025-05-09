# VTScada HTTPS Setup with Let's Encrypt and Caddy

This guide outlines the complete process of securing VTScada with a Let's Encrypt certificate, processing the certificate on Linux, finalizing it on Windows, and configuring Caddy as a reverse proxy.

---

## Part 1: Generate and Sign a CSR with Let's Encrypt (Linux)

### Step 1: Generate a CSR in VTScada

1. Open **VTScada Application Manager**.
2. Go to **Thin Client and Server Setup → Certificates**.
3. Fill in the required fields for the certificate.
4. Click **Generate Request**.
5. Copy the entire CSR, including:

   ```
   -----BEGIN CERTIFICATE REQUEST-----
   ...
   -----END CERTIFICATE REQUEST-----
   ```

### Step 2: Save the CSR to a File (on Linux)

```bash
nano /tmp/request.csr
```

Paste the CSR and save the file.

### Step 3: Install Certbot

```bash
sudo apt install certbot
```

### Step 4: Use Certbot to Sign the CSR

```bash
sudo certbot certonly --manual \
  --csr /tmp/request.csr \
  --preferred-challenges http \
  --manual-public-ip-logging-ok
```

Certbot will prompt you to serve a challenge file at a specific URL.

### Step 5: Host the HTTP Challenge with Caddy

1. Create the file:

```bash
sudo mkdir -p /var/www/acme/.well-known/acme-challenge
echo "<token>" | sudo tee /var/www/acme/.well-known/acme-challenge/<filename>
```

2. Temporary Caddyfile entry:

```caddyfile
http://yourdomain.com {
    root * /var/www/acme
    file_server
}
```

3. Reload Caddy:

```bash
sudo systemctl reload caddy
```

4. Visit the challenge URL in a browser or with curl:

```bash
curl http://yourdomain.com/.well-known/acme-challenge/<filename>
```

5. Once verified, press **Enter** in the Certbot terminal.

### Step 6: Retrieve the Certificate Files

Certbot creates:

* `0000_cert.pem` – the signed certificate
* `0000_chain.pem` – the intermediate CA chain

Use `0000_cert.pem` to respond to VTScada.

---

## Part 2: Process the Certificate in VTScada (Windows)

### Step 7: Paste the Certificate Response

1. Open `0000_cert.pem` in a Tex Editor.
2. Copy the contents:

   ```
   -----BEGIN CERTIFICATE-----
   ...
   -----END CERTIFICATE-----
   ```
3. In **VTScada Application Manager**:

   * Go to **Thin Client and Server Setup → Certificates**
   * Click **Process Reply**

VTScada will:

* Detect the copied response in Clipboard
* Remove the CSR from "Certificate Requests"
* Add the signed cert to **Current User → Personal**

### Step 8: Export the Certificate with Private Key

1. Run `mmc`
2. Add **Certificates → My User Account** snap-in
3. Navigate to:

   ```
   Certificates - Current User → Personal → Certificates
   ```
4. Find your certificate → Right-click → **All Tasks → Export**
5. Follow the wizard:

   * **Export private key**
   * Save as `.pfx`, password-protected
   * Choose to delete the key after export

### Step 9: Import the Certificate into Local Computer Store

1. Open MMC again
2. Add **Certificates → Computer Account** snap-in
3. Go to:

   ```
   Certificates (Local Computer) → Personal
   ```
4. Right-click **Personal → All Tasks → Import**
5. Select the `.pfx` file and complete the wizard

### Step 10: Set Private Key Permissions

1. Locate the cert in **Certificates (Local Computer) → Personal**
2. Right-click → **All Tasks → Manage Private Keys**
3. Add the user/group VTScada runs under (e.g., `Domain Users`)
4. Grant **Read** access

### Step 11: Update VTScada Configuration

In `SETUP.INI` (usually in the VTScada config directory):

```ini
[SYSTEM]
SSLCertName = YourServer.Domain.Com
```

This must match the CN or Friendly Name in the cert.

Restart VTScada.

---

## Part 3: Configure Caddy as a Reverse Proxy

### Step 12: Optional – Set /etc/hosts for Internal Resolution (on Caddy server)

```bash
sudo nano /etc/hosts
```

Add:

```
<internal-ip>  yourbackend.domain.com
```

This ensures Caddy can resolve the backend to an internal address.

### Step 13: Caddyfile Example for Valid Cert (No TLS Skip)

```caddyfile
yourpublic.domain.com {
    reverse_proxy https://yourbackend.domain.com
}
```

### Alternate: If Backend Only Has IP or Uses Untrusted Cert

```caddyfile
yourpublic.domain.com {
    reverse_proxy https://<internal-ip> {
        transport http {
            tls_insecure_skip_verify
        }
    }
}
```

### Step 14: Reload Caddy

```bash
sudo systemctl reload caddy
```

---

## Summary Table

| Step           | Description                                             |
| -------------- | ------------------------------------------------------- |
| VTScada CSR    | Generated in App Manager, copied to Linux               |
| Certbot        | Signed CSR with Let's Encrypt using HTTP-01 challenge   |
| PEM to VTScada | Pasted reply cert to complete request                   |
| Export/Import  | Moved cert+key to Local Computer store                  |
| Permissions    | Granted VTScada access to private key                   |
| Caddy          | Used as HTTPS reverse proxy, with optional DNS override |
