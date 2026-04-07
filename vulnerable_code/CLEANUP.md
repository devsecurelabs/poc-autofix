# Post-Pilot Cleanup

> ⚠️ Execute these steps after pilot validation is confirmed. Pilot samples must NEVER reach the main branch.

1. Close the PR without merging
2. Delete the remote branch:
   ```bash
   git push origin --delete pilot/l1-detection-test
   ```
3. Delete the local branch:
   ```bash
   git branch -D pilot/l1-detection-test
   ```
4. These pilot samples must NEVER reach the main branch.
