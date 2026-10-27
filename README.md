# Defensive HTTP Endpoint Testing & Automation

A defensive, highly reliable Python testing and health-monitoring framework designed for authorized website and API reliability verification. Features strict TLS verification, bounded concurrency, credential redaction, thread isolation, and scheduled automation via GitHub Actions.

---

## Features & Safety Invariants

1. **Strict Transport Security**: TLS certificate verification is always enforced (`session.verify = True`). Plaintext leakage is strictly prevented.
2. **Comprehensive Secret Redaction**: Passwords, tokens, and proxy credentials are never exposed in log outputs, exception strings, or configuration dumps.
3. **Safe Concurrency & Request Budgeting**: Defaults to bounded concurrency (2 threads) and small request budgets (10 requests) with zero aggressive retries (`MAX_RETRIES=0`) during validation to prevent overloading target endpoints.
4. **No Rate-Limit Evasion**: Designed exclusively for authorized health and performance monitoring on infrastructure you own or are explicitly authorized to test. Does not attempt to bypass access controls or evade rate limits.
5. **Decoupled Failover & Error Classification**: Accurately distinguishes between target timeouts, HTTP status categories (2xx, 4xx, 5xx), and network transport errors.
6. **Thread-Safe Session Lifecycle**: Manages thread-local HTTP sessions with guaranteed cleanup upon completion or mid-run cancellation.

---

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── scheduled-test.yml   # GitHub Actions workflow (every 5 mins + manual dispatch)
├── .env.example                 # Example template for local environment variables
├── .gitignore                   # Comprehensive secret, cache, and artifact exclusions
├── README.md                    # Project documentation & operational guidelines
├── requirements.txt             # Minimal Python dependencies (requests, urllib3)
├── test_http_client.py          # 21-point regression and unit test suite (local mock servers)
└── testing_public_domain.py     # Core defensive HTTP client implementation
```

---

## Local Development & Setup

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.11 and 3.14)
- Git

### 2. Environment Setup
```bash
# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (CMD):
.venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt
```

### 3. Running Unit Tests
All unit tests execute against local mock servers bound strictly to `127.0.0.1`. No external network traffic is generated.
```bash
python -m unittest test_http_client.py
```

### 4. Running Local Integration Tests
To test against a local server or authorized development endpoint:
```bash
# Optional: create a local .env file
cp .env.example .env

# Set your authorized target URL
export TARGET_URL="http://127.0.0.1:8000/"  # Linux/macOS
$env:TARGET_URL="http://127.0.0.1:8000/"    # Windows PowerShell

# Run the client
python testing_public_domain.py
```

Exit codes:
- `0`: Execution succeeded without network errors.
- `1`: Network transport failure, timeout, or 0 successful requests.
- `2`: Configuration validation error (e.g., unsupported URL scheme).
- `130`: Execution interrupted by user (`Ctrl+C`).

---

## GitHub Setup & Automation

### Step 1: Create a Private GitHub Repository
1. Log in to [GitHub](https://github.com/).
2. Click **New repository** (or navigate to `https://github.com/new`).
3. Set the repository name (e.g., `defensive-endpoint-tester`).
4. Select **Private** to ensure your configuration and test histories remain confidential.
5. Do **not** initialize with a README, .gitignore, or license (these are already configured).
6. Click **Create repository**.

### Step 2: Push Local Code to GitHub
Open your terminal in this project directory and run:

```bash
# Initialize git repository
git init -b main

# Add all project files
git add .

# Create the initial commit
git commit -m "feat: initial defensive testing suite and GitHub Actions workflow"

# Link your remote repository (replace with your GitHub username and repository name)
git remote add origin https://github.com/<your-username>/<your-repo-name>.git

# Push to GitHub
git push -u origin main
```

*(If you use GitHub CLI (`gh`), you can do this in one step: `gh repo create <repo-name> --private --source=. --remote=origin --push`)*

### Step 3: Configure `TARGET_URL` Repository Variable
1. In your GitHub repository, navigate to **Settings** > **Secrets and variables** > **Actions**.
2. Click on the **Variables** tab (next to Secrets).
3. Click **New repository variable**.
4. Set the **Name** to: `TARGET_URL`
5. Set the **Value** to your authorized domain or endpoint (e.g., `https://your-domain.com/health`).
6. Click **Add variable**.

> [!NOTE]
> `TARGET_URL` is configured as an Actions **Variable** (non-secret). If your endpoint requires authorization headers or proxy credentials, store them in the **Secrets** tab instead and reference them securely via environment variables. Never commit credentials to source control.

### Step 4: Run the Workflow Manually (`workflow_dispatch`)
1. Go to the **Actions** tab in your GitHub repository.
2. Select **Scheduled Defensive Endpoint Test** from the left sidebar.
3. Click **Run workflow**.
4. (Optional) Provide a target URL override or leave blank to use `vars.TARGET_URL`.
5. Click **Run workflow**.
6. Inspect the execution logs:
   - Step `Run unit test suite`: Verifies that all 21 regression tests pass.
   - Step `Validate target configuration`: Confirms the `TARGET_URL` variable is populated.
   - Step `Execute authorized integration test`: Runs the bounded 10-request batch with 2 threads and 0 retries.

### Step 5: Scheduled Execution Details (`*/5 * * * *`)
The workflow includes a cron schedule set to execute every 5 minutes:
```yaml
schedule:
  - cron: '*/5 * * * *'
```

Important scheduling considerations:
- **Queue Timing**: GitHub Actions cron schedules are placed into a shared execution queue. During peak global traffic hours, runs may be delayed by 2–5 minutes.
- **Concurrency Protection**: The workflow defines `concurrency: group: scheduled-testing-pipeline` to ensure runs never overlap or double-book requests against the target.
- **Repository Inactivity**: GitHub automatically disables scheduled workflows on repositories that have had no commit activity for 60 consecutive days. If this occurs, a banner will appear in the Actions tab allowing you to re-enable them with a single click.

---

## Safety & Compliance Guidelines
- Test only targets that you own or have explicit, documented authorization to test.
- Keep `TOTAL_REQUESTS` and `MAX_THREADS` within safe bounds.
- If a target returns status `429` (Too Many Requests) or `503` (Service Unavailable), investigate upstream server capacity rather than increasing concurrency or retries.
