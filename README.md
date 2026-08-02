# QatarBiz.com — Full Operating Website

A complete, self-contained business marketplace: public bilingual site (English / العربية),
real seller submissions with document upload, buyer inquiries, user accounts, and a live
admin panel — all backed by a real database. **Zero dependencies**: runs anywhere Node.js 18+ runs.

---

## What's in this folder

```
server.js            The entire backend (API + database + file storage + static hosting)
public/index.html    The entire frontend (bilingual EN/AR website)
data/                Created automatically on first run (database + uploaded documents)
```

## Run it (locally or on a server)

```bash
node server.js
```

That's it. The site is live at http://localhost:3000

On first run the server creates the admin account and prints the password to the console:

```
Email:    admin@qatarbiz.net
Password: (printed once — save it, then change it in Admin → Settings)
```

You can also set your own password before first run:

```bash
ADMIN_PASSWORD='YourStrongPassword' node server.js
```

## Publish on qatarbiz.net (recommended: small VPS)

1. Get a small VPS (DigitalOcean / Hetzner / any Qatari host, ~QAR 25–45/month), Ubuntu 22+.
2. Install Node and a reverse proxy with HTTPS (Caddy makes this a 2-minute job):
   ```bash
   sudo apt update && sudo apt install -y nodejs caddy
   ```
3. Upload this folder to `/opt/qatarbiz`, then keep it running as a service:
   ```bash
   sudo tee /etc/systemd/system/qatarbiz.service > /dev/null <<'EOF'
   [Unit]
   Description=QatarBiz
   After=network.target
   [Service]
   WorkingDirectory=/opt/qatarbiz
   ExecStart=/usr/bin/node server.js
   Restart=always
   Environment=PORT=3000
   [Install]
   WantedBy=multi-user.target
   EOF
   sudo systemctl enable --now qatarbiz
   ```
4. Point Caddy at it (automatic free HTTPS):
   ```bash
   echo 'qatarbiz.net, www.qatarbiz.net {
     reverse_proxy localhost:3000
   }' | sudo tee /etc/caddy/Caddyfile
   sudo systemctl restart caddy
   ```
5. In your domain registrar, point qatarbiz.net's A record at the server IP. Done.

Alternative: any Node hosting service (Render, Railway) also works — upload the folder,
set the start command to `node server.js`. Note: on hosts with ephemeral disks, attach a
persistent disk/volume for the `data/` folder so the database and documents survive deploys.

## How you operate it (day to day)

1. **You post the first listings**: sign in → Admin → **Create Listing** tab → fill and publish.
   Or submit through the public "Sell" wizards and approve them yourself.
2. **Seller submissions** arrive as status *Submitted* with every answer, private contact
   details, and uploaded documents (visible only to you). Use **Edit** to write the public
   title/price/description, then set status to **Published**.
3. **Buyer inquiries** appear in the Inquiries tab with full contact details. Work them
   through the pipeline: New → Buyer Contacted → Qualified → NDA Sent → Disclosure Approved → Closed.
4. **Instagram cards**: the download button next to any published listing generates a
   1080×1080 promotional PNG (identity-free).
5. Sellers and buyers can create accounts to track their submissions and inquiries.

## Confidentiality model (enforced by the server)

- The public API returns only whitelisted fields — seller names, phone numbers, CR numbers,
  and exact addresses are stored in a private section that never leaves the admin API.
- Uploaded documents are stored outside the public folder and served only to a signed-in admin.
- Passwords are hashed (scrypt), sessions are HttpOnly cookies, auth endpoints are rate-limited.

## Backups

Everything lives in the `data/` folder. Back it up with a single copy:

```bash
cp -r data /backup/qatarbiz-$(date +%F)
```

## What to add as you grow (not blockers for launch)

- Email/WhatsApp notifications on new submissions (needs an SMTP or WhatsApp Business API key)
- A payment record module for commissions
- Migration to PostgreSQL when listing volume grows into the thousands
