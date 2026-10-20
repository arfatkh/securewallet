# Deploying SecureWallet publicly

## Option A: Dokploy (recommended)

Dokploy pulls this repository from GitHub and runs `docker-compose.dokploy.yml`. Its Traefik proxy provides the domain and the HTTPS certificate.

```
Internet ──HTTPS──▶ Traefik (Dokploy) ──▶ web (nginx: CSP, rate limits) ──▶ api ──▶ db
                                          dokploy-network + edge             internal network only
```

1. **Project:** in Dokploy, **Projects → Create Project** `securewallet` → **Create Service → Compose**.
2. **General → Provider:** GitHub (or Git). Choose repository `israr13/securewallet`, branch `main`, compose path **`./docker-compose.dokploy.yml`**.
3. **Environment tab:** paste the following and **Save**.
   - The passwords are long random strings. Generate each with `openssl rand -hex 24`.
   - `DOMAIN` must be exactly the domain you add in step 4.
   ```
   POSTGRES_PASSWORD=<random>
   OWNER_DB_PASSWORD=<random>
   APP_DB_PASSWORD=<random>
   DOMAIN=wallet.example.com
   DEMO_MODE=true
   SESSION_IDLE_SECONDS=300
   ```
4. **Domains tab → Add Domain:**
   - Host: the same domain. It must have **HTTPS**, because the refresh cookie is Secure-only and passkeys need it. Use a domain or subdomain with an **A record pointing at the Dokploy server's IP**. A free DuckDNS subdomain works. Don't use the generated `*.traefik.me` hosts: those usually run on plain HTTP, and sign-in won't stay working.
   - Service: **web**. Container port: **8080**. Path: `/`.
   - **HTTPS on**, certificate **Let's Encrypt**.
5. **Deploy.** The first build takes 3–8 minutes. Then open `https://<domain>` and sign in as `ali` / `Wallet@2026!`.

**Updating:** push to `main`, then click **Deploy** again, or turn on **Auto Deploy**. Data in the `dbdata` and `keys` volumes is kept.

**Notes:**
- **Never change the passwords after the first deploy.** The database stores them when it's first created; to change them, delete the volumes too.
- **Changing the domain:** update `DOMAIN` as well, then redeploy. Passkeys are tied to the domain, so existing ones stop working on the new name.
- **Tests:** in Dokploy's terminal for the server, from the compose folder:
  ```
  docker compose -f docker-compose.dokploy.yml -f docker-compose.test.yml run --rm tests
  ```
- **Database console:** **Docker** tab → `securewallet-db` → Terminal → `psql -U postgres -d securewallet`.

## Option B: a plain VM with Caddy

The app runs as the same Docker stack as on a laptop, with **Caddy** in front on ports 80/443. Caddy gets a free Let's Encrypt certificate and serves everything over HTTPS.

```
Internet ──HTTPS 443──▶ caddy ──▶ web (nginx: CSP, rate limits) ──▶ api ──▶ db
                       (only published container)                      (internal network, no route out)
```

What changes in production (`docker-compose.prod.yml`):

| Setting | Why |
|---|---|
| Only Caddy publishes ports (80, 443). `web` is no longer published. | One way in, always over TLS |
| HTTP → HTTPS redirect, HSTS 1 year | No plaintext sessions |
| `COOKIE_SECURE=true` | The refresh cookie is never sent over HTTP |
| `RP_ID` / `EXPECTED_ORIGINS` = your domain | Passkeys are bound to the real site name |
| nginx takes the client IP from Caddy (`deploy/real_ip.conf`) | Per-IP login limits and the audit log see each visitor's real IP, not Caddy's |
| Random 32-character DB passwords, generated on the server | Secrets never touch GitHub |

### 1. Push the code to GitHub (on the laptop)

Create an **empty private** repository on github.com (no README), then in the `A1` folder:

```bash
git remote add origin https://github.com/<you>/securewallet.git
git push -u origin main
```

`.env` is in `.gitignore` and is never pushed. Keep the repo private, so classmates can't copy the assignment.

### 2. Create the VM (Azure portal, Azure for Students)

1. Go to **portal.azure.com** → *Virtual machines* → *Create*.
   - Image: **Ubuntu Server 24.04 LTS**.
   - Size: **B1s** (cheapest; the script adds swap) or **B2s** (faster builds).
   - Authentication: **SSH public key**. Download the `.pem` file.
   - Inbound ports: allow **SSH (22), HTTP (80), HTTPS (443)**.
2. After it's created, open the VM → **Overview → DNS name → Not configured**. Set a DNS name label such as `securewallet-fast`. Your domain becomes `securewallet-fast.<region>.cloudapp.azure.com`.
3. Recommended: under *Networking*, change the SSH (22) rule's source to **My IP**.

### 3. Install and start (on the VM)

```bash
ssh -i securewallet_key.pem azureuser@<your-domain>
git clone https://github.com/<you>/securewallet.git     # for a private repo, use a GitHub token as the password
cd securewallet
bash deploy/setup.sh <your-domain>
```

The first build takes 5–10 minutes. Then open `https://<your-domain>` and sign in as `ali` / `Wallet@2026!`.

### Updating after a change

On the laptop, commit and push. Then on the VM:

```bash
cd securewallet && bash deploy/update.sh
```

### Running the tests on the server

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.test.yml run --rm tests
```

The tests reset the demo data.

## Demo mode on a public site

`deploy/setup.sh` sets `DEMO_MODE=true`, so visitors can open the trace panel and the Security Lab.

- **Lab switches are global.** Anyone signed in can turn a control off for every user, or reset the data. **Reset demo data** in the Lab restores everything.
- **The demo accounts use a published password,** and the data is fake.

To run it as a plain secure wallet instead, set `DEMO_MODE=false` in `.env` and run `bash deploy/update.sh`. The Lab and trace endpoints then don't exist at all.

## Useful commands on the VM

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.prod.yml ps        # status
sudo docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f   # live logs
sudo docker compose exec db psql -U postgres -d securewallet                   # database console
```

To stop paying for the VM when it isn't needed, use **Stop** in the Azure portal (deallocate). The data is kept.
