# MuninID edge deploy (172.31.0.12)

Ansible playbook for the small demo/QA box. It sets up:

- **`podman_munin`** — a rootless podman user (subuid/subgid + lingering).
- **muninid + Anubis** — a rootless **quadlet** pod. muninid talks to the managed
  UpCloud Postgres/Valkey and to WildDuck at `172.31.0.22:8080` (internal net).
- **HAProxy** — the TLS edge for `idp.solutrix.io` and `demo.go53.eu`, with
  per-source-IP rate limiting.
- **Anubis** — a *mild* proof-of-work bot-wall that only challenges
  `/interaction` (login). All OAuth/OIDC/API paths pass straight through.
- **certbot** — HTTP-01 issuance/renewal proxied through HAProxy, with a deploy
  hook that rebuilds the combined PEMs and reloads HAProxy.
- **go53 demo** — started via `/root/install_demo.sh` with `SKIP_CADDY=1`; HAProxy
  fronts it instead of Caddy.

## Traffic flow

```
:443 HAProxy ──host idp.solutrix.io──> Anubis(:8923) ──> muninid(:8080)   (PoW only on /interaction)
             └─host demo.go53.eu────> go53-webadmin(127.0.0.1:3000)
:80  HAProxy ──/.well-known/acme-challenge──> certbot standalone(:8888)
             └─ else ─> 301 https
```

## Prerequisites

- DNS: `idp.solutrix.io` and `demo.go53.eu` → `212.147.245.131` (both in place).
- `vars/secrets.yml` filled in (copy from `secrets.example.yml`). It is gitignored;
  encrypt it: `ansible-vault encrypt vars/secrets.yml`.

## Run

```bash
cd deploy/ansible
ansible-playbook -i inventory.ini playbook.yml            # everything
ansible-playbook -i inventory.ini playbook.yml --check    # dry run
ansible-playbook -i inventory.ini playbook.yml --tags certs    # just certs
ansible-playbook -i inventory.ini playbook.yml --tags muninid  # just the pod
```

## Things to verify / tune

- **Anubis policy schema** (`templates/botPolicies.yaml.j2`) targets the
  action-based format (`ALLOW`/`CHALLENGE`). Newer Anubis releases use a weight
  system — check it against the pinned image (`anubis_image` in `vars/main.yml`).
- **Rate limits** live in `vars/main.yml` (`rl_global_per_10s`,
  `rl_interaction_per_10s`). Defaults: 100 req/10s globally, 20 req/10s on
  `/interaction`, per source IP, returning 429.
- The box is small (1 vCPU / 1.8 GB). Fine for demo/QA, not production load.
- `muninid-migrate` runs on every apply (goose `up` is idempotent).
