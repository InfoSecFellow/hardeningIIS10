import os
import subprocess
import sys
import re
import shutil
import threading
import glob
import socket
import stat
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
DEPLOYMENT_DIR = os.path.join(SCRIPTS_DIR, "deployment")
ROLLBACK_DIR = os.path.join(SCRIPTS_DIR, "rollback")
CHECK_HARDENING_PS1 = os.path.join(SCRIPTS_DIR, "Check_Hardening.ps1")
LOG_DIR = os.path.join(BASE_DIR, "logs")
BACKUP_DIR = os.path.join(BASE_DIR, "Backups")

INETPUB_PATH = r"C:\inetpub"
INETSRV_PATH = r"C:\Windows\System32\inetsrv"

DOTNET_V2_CONFIG_GLOB = r"C:\Windows\Microsoft.NET\Framework64\v2.0.*\CONFIG"
DOTNET_V4_CONFIG_GLOB = r"C:\Windows\Microsoft.NET\Framework64\v4.0.*\Config"

ZIP_EXE = os.path.join(BASE_DIR, "zip.exe")
UNZIP_EXE = os.path.join(BASE_DIR, "unzip.exe")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

BANNER = """
================================================================================
Hardening for IIS 10.
The purpose of Hardening for IIS 10 is to create an additional security layer on 
the IIS platform following information security best practices.
Hardening IIS 10 controls were extracted from the CIS Benchmark IIS 10 v1.2.1.
See more: https://workbench.cisecurity.org
HIIS10 v1.0 - 2026
================================================================================
"""

ABORT_EVENT = threading.Event()
CURRENT_PROC = None


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str):
    logfile = os.path.join(LOG_DIR, f"hiis10_cli-{datetime.now().strftime('%Y%m%d')}.log")
    line = f"[{_ts()}] {message}"
    print(line)
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def runall_log_line(runall_logfile: str, script_name: str, ok: bool):
    status = "Script executed successfully!" if ok else "Script executed FAIL!"
    line = f"[{_ts()}] - {script_name} - {status}"
    with open(runall_logfile, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def numeric_sort_key(filename: str):
    numbers = re.findall(r"\d+", filename)
    return [int(n) for n in numbers]


def get_scripts(path: str):
    if not os.path.exists(path):
        return []
    scripts = [f for f in os.listdir(path) if f.lower().endswith(".ps1")]
    return sorted(scripts, key=numeric_sort_key)


def run_script_visible(script_path: str) -> bool:
    log(f"Executing script (visible console): {script_path}")
    try:
        p = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Normal",
                "-File", script_path,
            ],
            shell=False,
            creationflags=(subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0),
        )
        if p.returncode == 0:
            log(f"SUCCESS: {script_path}")
            return True
        log(f"ERROR: {script_path} | rc={p.returncode}")
        return False
    except Exception as e:
        log(f"ERROR: {script_path} | {e}")
        return False


def run_powershell_silent(script_path: str):
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", script_path,
    ]

    startupinfo = None
    creationflags = 0

    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW

    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def check_hardening():
    path = CHECK_HARDENING_PS1

    if not os.path.isfile(path):
        log(f"ERROR: Check_Hardening.ps1 not found: {path}")
        print("\nCheck_Hardening.ps1 não encontrado na pasta scripts. Verifique o caminho.")
        input("\nPress Enter to continue...")
        return

    log(f"Executing Check Hardening (silent): {path}")

    try:
        rc, out, err = run_powershell_silent(path)

        if rc == 0:
            log("SUCCESS: Check Hardening")
            print("\nCheck Hardening concluído com sucesso.")
        else:
            log(f"ERROR: Check Hardening | rc={rc}")
            print("\nCheck Hardening finalizado com erros. Consulte o log.")

        if out:
            log(f"stdout: {out}")
        if err:
            log(f"stderr: {err}")

    except Exception as e:
        log(f"ERROR: Check Hardening | {e}")
        print("\nErro inesperado durante a execução do Check Hardening. Consulte o log.")

    input("\nPress Enter to continue...")


def popen_powershell_hidden(script_path: str) -> subprocess.Popen:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", script_path,
    ]

    startupinfo = None
    creationflags = 0

    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )


def backup_folder(source_path: str, prefix: str) -> bool:
    if not os.path.exists(source_path):
        log(f"ERROR: Source folder does not exist: {source_path}")
        return False

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"{prefix}_{stamp}")

    log(f"Starting backup: {source_path} -> {dest}")
    try:
        shutil.copytree(source_path, dest)
        log(f"SUCCESS: Backup completed: {dest}")
        return True
    except Exception as ex:
        log(f"ERROR: Backup failed ({prefix}) | {ex}")
        return False


def backup_inetpub() -> bool:
    return backup_folder(INETPUB_PATH, "inetpub")


def backup_inetsrv() -> bool:
    return backup_folder(INETSRV_PATH, "inetsrv")


def backup_inetpub_and_inetsrv() -> bool:
    ok1 = backup_inetpub()
    ok2 = backup_inetsrv()
    return ok1 and ok2


def _find_dotnet_config_folders():
    targets = []

    for p in glob.glob(DOTNET_V2_CONFIG_GLOB):
        if os.path.isdir(p):
            ver = os.path.basename(os.path.dirname(p))
            targets.append((p, f"dotnet_framework64_{ver}_CONFIG"))

    for p in glob.glob(DOTNET_V4_CONFIG_GLOB):
        if os.path.isdir(p):
            ver = os.path.basename(os.path.dirname(p))
            targets.append((p, f"dotnet_framework64_{ver}_Config"))

    return targets


def backup_dotnet_folders() -> bool:
    targets = _find_dotnet_config_folders()
    if not targets:
        log(
            "ERROR: No .NET folders found using patterns:\n"
            f"  - {DOTNET_V2_CONFIG_GLOB}\n"
            f"  - {DOTNET_V4_CONFIG_GLOB}"
        )
        return False

    ok_all = True
    for src, prefix in targets:
        ok = backup_folder(src, prefix)
        ok_all = ok_all and ok
    return ok_all


def backup_all_deployment_folders() -> bool:
    log("Starting DEPLOYMENT pre-run backup: inetpub + inetsrv + .NET folders")

    ok_iis = backup_inetpub_and_inetsrv()
    if not ok_iis:
        log("ERROR: DEPLOYMENT pre-run backup failed (inetpub/inetsrv).")
        return False

    ok_dotnet = backup_dotnet_folders()
    if not ok_dotnet:
        log("ERROR: DEPLOYMENT pre-run backup failed (.NET folders).")
        return False

    log("SUCCESS: DEPLOYMENT pre-run backup completed (inetpub/inetsrv/.NET).")
    return True


def restart_iis() -> bool:
    log("Restarting IIS using iisreset...")
    try:
        subprocess.run(["iisreset"], check=True)
        log("SUCCESS: IIS restarted")
        return True
    except subprocess.CalledProcessError as e:
        log(f"ERROR: IIS restart failed | {e}")
        return False


def run_cmd_capture(cmd, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=cwd)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def zip_backup_folder(zip_exe: str, backup_dir: str, output_zip_path: str):
    if not os.path.isfile(zip_exe):
        return 2, "", f"zip.exe not found at: {zip_exe}"
    if not os.path.isdir(backup_dir):
        return 3, "", f"Backup directory not found: {backup_dir}"

    os.makedirs(os.path.dirname(output_zip_path), exist_ok=True)

    if os.path.exists(output_zip_path):
        try:
            os.remove(output_zip_path)
        except Exception as e:
            return 4, "", f"Failed to remove existing zip: {output_zip_path} | {e}"

    cmd = [zip_exe, "-r", output_zip_path, "*"]
    return run_cmd_capture(cmd, cwd=backup_dir)


def cleanup_backups_keep_zip(backup_dir: str, zip_full_path: str):
    errors = []
    backup_abs = os.path.abspath(backup_dir)

    if not os.path.isdir(backup_abs):
        return False, [f"Backup directory not found: {backup_abs}"]

    def _force_writable(path: str):
        try:
            os.chmod(path, stat.S_IWRITE)
        except Exception:
            pass

    def _on_rm_error(func, path, exc_info):
        _force_writable(path)
        try:
            func(path)
            return
        except Exception:
            pass
        try:
            if os.path.isdir(path):
                _force_writable(path)
                os.rmdir(path)
        except Exception as e:
            errors.append(f"Failed to remove (onerror): {path} | {e}")

    for name in os.listdir(backup_abs):
        item = os.path.join(backup_abs, name)

        if os.path.isdir(item):
            try:
                shutil.rmtree(item, onerror=_on_rm_error)
            except Exception as e:
                errors.append(f"Failed to remove dir: {item} | {e}")
            continue

        if name.lower().endswith(".zip"):
            continue

        if name.lower().endswith(".json"):
            try:
                _force_writable(item)
                os.remove(item)
            except Exception as e:
                errors.append(f"Failed to remove json: {item} | {e}")
            continue

    try:
        for root, dirs, files in os.walk(backup_abs, topdown=False):
            for d in dirs:
                p = os.path.join(root, d)
                try:
                    _force_writable(p)
                    os.rmdir(p)
                except Exception:
                    pass
    except Exception:
        pass

    return (len(errors) == 0), errors


def zip_and_cleanup_backups() -> bool:
    hostname = socket.gethostname()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_name = f"{hostname}_HIIS10_BackupFull_{stamp}.zip"
    zip_path = os.path.join(BACKUP_DIR, zip_name)

    log(f"Starting ZIP of backups folder -> {zip_path}")
    rc, out, err = zip_backup_folder(ZIP_EXE, BACKUP_DIR, zip_path)
    if rc != 0:
        log(f"ERROR: Failed to create backup ZIP | rc={rc}")
        if out:
            log(f"zip.exe stdout: {out}")
        if err:
            log(f"zip.exe stderr: {err}")
        return False

    log(f"SUCCESS: Backup ZIP created -> {zip_path}")

    log("Starting cleanup: removing folders and .json files (keeping all .zip)...")
    ok, errors = cleanup_backups_keep_zip(BACKUP_DIR, zip_path)
    if ok:
        log("SUCCESS: Cleanup completed. .zip files were preserved.")
        return True

    log("ERROR: Cleanup completed with failures:")
    for e in errors:
        log(f" - {e}")
    return False


def abort_listener():
    global CURRENT_PROC
    try:
        while not ABORT_EVENT.is_set():
            s = input().strip().lower()
            if s == "q":
                ABORT_EVENT.set()
                log("ABORT requested by user (q).")
                p = CURRENT_PROC
                if p is not None:
                    try:
                        p.terminate()
                        log("ABORT: Terminate signal sent to current PowerShell process.")
                    except Exception as e:
                        log(f"ABORT: Failed to terminate process | {e}")
                return
    except EOFError:
        return


def execute_all(directory: str, mode: str):
    global CURRENT_PROC

    scripts = get_scripts(directory)
    if not scripts:
        print("No scripts found.")
        input("\nPress Enter to continue...")
        return

    total = len(scripts)
    runall_logfile = os.path.join(LOG_DIR, f"hiis10_cli-runall_{datetime.now():%Y%m%d}.log")

    ABORT_EVENT.clear()
    CURRENT_PROC = None

    with open(runall_logfile, "a", encoding="utf-8") as f:
        f.write(f"\n[{_ts()}] - RUNALL started | mode={mode}\n")

    print("\n[INFO] Execute All started.")
    print("[INFO] To abort at any time: type 'q' and press Enter.\n")
    t = threading.Thread(target=abort_listener, daemon=True)
    t.start()

    if mode == "deployment":
        if ABORT_EVENT.is_set():
            log("RUNALL aborted before backup.")
            with open(runall_logfile, "a", encoding="utf-8") as f:
                f.write(f"[{_ts()}] - RUNALL aborted (before backup)\n")
            return

        ok_bkp = backup_all_deployment_folders()
        if not ok_bkp:
            print("\nBackup failed. Execution aborted.")
            log("ERROR: Backup failed. Deployment execution aborted.")
            with open(runall_logfile, "a", encoding="utf-8") as f:
                f.write(f"[{_ts()}] - RUNALL aborted (backup failed)\n")
            input("Press Enter to continue...")
            return

    for i, script in enumerate(scripts, start=1):
        if ABORT_EVENT.is_set():
            log(f"RUNALL aborted by user at {i-1}/{total}.")
            with open(runall_logfile, "a", encoding="utf-8") as f:
                f.write(f"[{_ts()}] - RUNALL aborted by user\n")
            print(f"\nAborted at {i-1}/{total}.")
            return

        script_full = os.path.join(directory, script)
        print(f"[{i}/{total}] Executing: {script}")
        log(f"Executing (silent): {script_full}")

        ok = False
        try:
            p = popen_powershell_hidden(script_full)
            CURRENT_PROC = p

            out, err = p.communicate()
            rc = p.returncode

            CURRENT_PROC = None

            out = (out or "").strip()
            err = (err or "").strip()

            if ABORT_EVENT.is_set():
                log(f"RUNALL aborted during execution: {script}")
                runall_log_line(runall_logfile, script, False)
                with open(runall_logfile, "a", encoding="utf-8") as f:
                    f.write(f"[{_ts()}] - RUNALL aborted during execution\n")
                print(f"\nAborted at {i}/{total}.")
                return

            if rc == 0:
                ok = True
                log(f"SUCCESS: {script}")
            else:
                log(f"ERROR: {script} | rc={rc}")
                if out:
                    log(f"stdout: {out}")
                if err:
                    log(f"stderr: {err}")

        except Exception as e:
            CURRENT_PROC = None
            log(f"ERROR: {script} | {e}")

        runall_log_line(runall_logfile, script, ok)

    print("\nAll scripts were executed. Check the logs to ensure there are no errors.")
    log("All scripts were executed. Check the logs to ensure there are no errors.")

    with open(runall_logfile, "a", encoding="utf-8") as f:
        f.write(f"[{_ts()}] - RUNALL finished\n")

    if mode == "deployment" and not ABORT_EVENT.is_set():
        ok_zip = zip_and_cleanup_backups()
        if not ok_zip:
            print("\nWARNING: Failed to zip/cleanup backups. Check logs.")
        restart_iis()

    input("Press Enter to continue...")


def execute_menu(title: str, directory: str, mode: str):
    while True:
        print(f"\n=== {title} ===\n")

        scripts = get_scripts(directory)
        if not scripts:
            print("No scripts found.")
            input("\nPress Enter to go back...")
            return

        for idx, script in enumerate(scripts, start=1):
            print(f"{idx}. {script}")

        print("\nA. Execute All")
        print("0. Back")

        choice = input("\nSelect an option: ").strip().lower()

        if choice == "0":
            return

        if choice == "a":
            execute_all(directory, mode=mode)
            continue

        if choice.isdigit() and 1 <= int(choice) <= len(scripts):
            script = scripts[int(choice) - 1]
            run_script_visible(os.path.join(directory, script))
            input("\nPress Enter to continue...")
        else:
            print("Invalid option.")


def main_menu():
    while True:
        print("\n=== Hardening Script Options ===\n")
        print("1. Hardening Deployment")
        print("2. Hardening Rollback")
        print("3. Backup inetpub & inetsrv")
        print("4. Backup .NET Folders")
        print("5. Restart IIS service")
        print("6. Check Hardening")
        print("7. Clear Screen")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            execute_menu("Hardening Deployment", DEPLOYMENT_DIR, mode="deployment")
        elif choice == "2":
            execute_menu("Hardening Rollback", ROLLBACK_DIR, mode="rollback")
        elif choice == "3":
            backup_inetpub_and_inetsrv()
            input("\nPress Enter to continue...")
        elif choice == "4":
            ok = backup_dotnet_folders()
            if not ok:
                print("\nBackup .NET folders failed (or no folders found). Check logs.")
            input("\nPress Enter to continue...")
        elif choice == "5":
            restart_iis()
            input("\nPress Enter to continue...")
        elif choice == "6":
            check_hardening()
        elif choice == "7":
            clear_screen()
            print(BANNER.strip())
        elif choice == "0":
            sys.exit(0)
        else:
            print("Invalid option.")


if __name__ == "__main__":
    clear_screen()
    print(BANNER.strip())
    main_menu()
