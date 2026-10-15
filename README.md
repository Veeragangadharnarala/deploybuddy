# DeployBuddy — free GitHub Pages version

This is the static, browser-only version of DeployBuddy. It does not require Hatchable, a backend server, a database, or a paid API.

## What it does
- Lets you paste code or upload up to 80 small source/configuration files.
- Runs heuristic pattern checks in your browser for possible hard-coded credentials, debug output, TODO/FIXME markers, empty exception handlers, HTTP URLs, broad SQL queries, SQL concatenation, secret-like filenames, and some debug settings.
- Displays findings, severity, suggested owner/team, possible next steps, and verification ideas.
- Exports a JSON report.

## Important limitations
- This is an early MVP, not an AI code reviewer or a security scanner.
- It does not compile or execute code, run tests, scan dependencies, connect to a database, or deploy projects.
- Pattern matches can be false positives and may miss real problems. Always review results and use your real build, tests, and security tools.
- Source files are processed locally in the browser by this static app; the app does not send them to a server or persist scan reports.

## Publish on GitHub Pages for free
1. Sign in at https://github.com
2. Click **+** → **New repository**.
3. Name it `deploybuddy`, select **Public**, and create the repository. (A public repository is needed for the straightforward GitHub Free Pages setup.)
4. On the new repository page, choose **Add file** → **Upload files**.
5. Extract this ZIP on your computer first. Upload `index.html`, `styles.css`, `app.js`, and `README.md` from the extracted `deploybuddy-free` folder. Upload the files themselves to the repository root, not the ZIP file and not an extra nested folder.
6. Click **Commit changes**.
7. Open **Settings** → **Pages**.
8. Under **Build and deployment**, select **Deploy from a branch**.
9. Choose branch **main** and folder **/(root)**, then click **Save**.
10. Wait a few minutes. The Pages screen will show your public website URL, usually `https://YOUR-USERNAME.github.io/deploybuddy/`.

## Test it
Open your published URL, click **Scan a project**, choose **Load sample project**, and click **Analyze project**. Also test uploading a small source file and downloading the JSON report.

## Future upgrades
For real Java compilation, automated tests, dependency scanning, AI-based suggestions, user accounts, or saved history, you'll need a backend or trusted external service. Add those separately and check their free-tier limits before connecting billing.
