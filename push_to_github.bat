@echo off
REM Git commands to push all fixes to GitHub

cd "c:\Users\Lakshay\Documents\Nancy\Git\aws-iam-least-privilege-analyzer 2\aws-iam-least-privilege-analyzer"

echo Adding all changes...
git add .

echo Committing changes...
git commit -m "Fix CI pipeline: Add missing files and resolve linting errors

- Add LICENSE file (MIT)
- Add security.yml workflow
- Add comprehensive .gitignore
- Add terraform.tfvars.example
- Add pyproject.toml for Python packaging
- Fix all ruff linting errors (imports, typing, timezone)
- Convert Enum classes to StrEnum
- Fix relative imports to absolute imports
- All tests passing (31/31)"

echo Pushing to GitHub...
git push origin main

echo Done! Check GitHub Actions for CI results.
pause
