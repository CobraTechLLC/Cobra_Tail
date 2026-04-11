import subprocess
import os

def run_git_push():
    script_name = os.path.basename(__file__)
    remote_url = "git@github.com:CobraTechLLC/Cobra_Tail.git"

    try:
        print(f"--- 🐍 Cobra Tail: Automation Protocol ---")

        # 1. AUTO-INIT & REPAIR
        if not os.path.isdir(".git"):
            print("Initializing new Git repository...")
            subprocess.run(["git", "init"], check=True)
            subprocess.run(["git", "remote", "add", "origin", remote_url], check=True)

        # FORCE FIX: Rename branch to 'main' so it matches GitHub
        subprocess.run(["git", "branch", "-M", "main"], check=True)

        # 2. SANITIZATION SANITY CHECK
        # Refuse to push if the working tree contains any of the strings or
        # paths that were scrubbed during the pre-public audit. This is
        # belt-and-suspenders protection against accidentally re-introducing
        # the old IPs / personal paths / internal docs.
        forbidden_patterns = [
            "24.208.72.232",
            "73.162.45.100",
            "192.168.1.152",
            "/home/xsv",
        ]
        forbidden_paths = [
            "project_overview",
            "systemd_setup/lighthouse.service",
        ]
        dirty = False
        for pattern in forbidden_patterns:
            hit = subprocess.run(
                ["git", "grep", "-l", "--", pattern],
                capture_output=True, text=True
            )
            if hit.stdout.strip():
                print(f"❌ REFUSING TO PUSH: found forbidden string '{pattern}' in:")
                print(hit.stdout)
                dirty = True
        for path in forbidden_paths:
            if os.path.exists(path):
                print(f"❌ REFUSING TO PUSH: forbidden path exists: {path}")
                dirty = True
        if dirty:
            print("\nWorking tree contains material that was scrubbed during the audit.")
            print("Do NOT push this. Investigate and clean before retrying.")
            return

        # 3. STAGE & EXCLUDE SCRIPT
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run(["git", "rm", "--cached", script_name], capture_output=True)

        # 4. STATUS CHECK
        # Check for NEW changes
        status = subprocess.run(["git", "status", "--short"], capture_output=True, text=True).stdout.strip()
        # Check for ALREADY COMMITTED changes that haven't been pushed
        unpushed = subprocess.run(["git", "cherry", "-v"], capture_output=True, text=True).stdout.strip()

        if status:
            print("\n--- 🔍 New Changes Detected ---")
            print(status)
            confirm = input("\nCommit and push these changes? (y/n): ").lower()
            if confirm == 'y':
                msg = input("Enter commit message: ") or "Cobra Tail Update"
                subprocess.run(["git", "commit", "-m", msg], check=True)
            else:
                return

        elif unpushed:
            print("\n--- 📤 Found files already committed but not on GitHub ---")
            confirm = input("Push these existing files to GitHub now? (y/n): ").lower()
            if confirm != 'y':
                return
        else:
            print("✅ Everything is already synced with GitHub.")
            return

        # 5. THE PUSH — no auto-rebase fallback.
        # If the push is rejected, stop and let the human investigate.
        # Auto-rebasing on rejection would risk pulling a divergent (possibly
        # dirty) history back down into a sanitized local clone.
        print("\nUploading to CobraTechLLC/Cobra_Tail...")
        result = subprocess.run(
            ["git", "push", "-u", "origin", "main"],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            print(f"--- ✅ Protocol Complete: Files are Live ---")
        else:
            print(f"❌ Push Failed: {result.stderr}")
            print("")
            print("NOTE: This script no longer auto-rebases on rejection.")
            print("If the remote has diverged, investigate manually before")
            print("running any pull/rebase/force-push. The sanitized history")
            print("on GitHub must not be contaminated by a dirty local.")

    except subprocess.CalledProcessError as e:
        print(f"\n❌ Git Error: {e}")

if __name__ == "__main__":
    run_git_push()