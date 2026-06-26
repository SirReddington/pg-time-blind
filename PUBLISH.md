# How to publish this repo to GitHub

Everything below is copy-paste. Replace `<your-username>` with your GitHub username.

## Option A — GitHub CLI (easiest, one step)

If you have the [`gh`](https://cli.github.com/) CLI installed and logged in (`gh auth login`):

```bash
cd pg-time-blind
git init
git add .
git commit -m "Initial commit: pg-time-blind PostgreSQL time-based blind SQLi extractor"
gh repo create pg-time-blind --public --source=. --remote=origin --push
```

Done — it creates the repo on GitHub and pushes in one command.

## Option B — Manual (create repo in the browser first)

1. Go to https://github.com/new
2. Repository name: **pg-time-blind**
3. Visibility: **Public**
4. Do **NOT** tick "Add a README", "Add .gitignore", or "Choose a license" (you already have them).
5. Click **Create repository**, then run:

```bash
cd pg-time-blind
git init
git add .
git commit -m "Initial commit: pg-time-blind PostgreSQL time-based blind SQLi extractor"
git branch -M main
git remote add origin https://github.com/<your-username>/pg-time-blind.git
git push -u origin main
```

If prompted for a password, use a **Personal Access Token** (Settings → Developer settings →
Personal access tokens), not your account password.

## After publishing

- Add topics on the repo page so people find it: `sql-injection`, `postgresql`, `pentesting`,
  `security-tools`, `ctf`, `blind-sqli`, `offensive-security`.
- Optionally add a short description: *"PostgreSQL time-based blind SQLi data extractor (no sqlmap)."*
- Edit the copyright name/year in `LICENSE` if you want your full name there.
