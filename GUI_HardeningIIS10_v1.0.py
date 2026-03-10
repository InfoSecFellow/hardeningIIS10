import os
import re
import sys
import shutil
import stat
import subprocess
import threading
import glob
import socket
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
DEPLOYMENT_DIR = os.path.join(SCRIPTS_DIR, "deployment")
ROLLBACK_DIR = os.path.join(SCRIPTS_DIR, "rollback")

CHECK_HARDENING_PS1 = os.path.join(SCRIPTS_DIR, "Check_Hardening.ps1")

BACKUP_DIR = os.path.join(BASE_DIR, "backups")
LOG_DIR = os.path.join(BASE_DIR, "logs")

SCRIPT_LOGS_DIR = os.path.join(BASE_DIR, "script_logs")
HIIS_LOGS_DIR = LOG_DIR

INETPUB_PATH = r"C:\inetpub"
INETSRV_PATH = r"C:\Windows\System32\inetsrv"

DOTNET_V2_CONFIG_GLOB = r"C:\Windows\Microsoft.NET\Framework64\v2.0.*\CONFIG"
DOTNET_V4_CONFIG_GLOB = r"C:\Windows\Microsoft.NET\Framework64\v4.0.*\Config"

ZIP_EXE = os.path.join(BASE_DIR, "zip.exe")
UNZIP_EXE = os.path.join(BASE_DIR, "unzip.exe")

os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(SCRIPT_LOGS_DIR, exist_ok=True)

BANNER = (
    "Hardening for IIS 10.\n"
    "The purpose of Hardening for IIS 10 is to create an additional security layer on the IIS platform,\n"
    "following information security best practices.\n"
    "Hardening IIS 10 controls were extracted from the CIS Benchmark IIS 10 v1.2.1.\n"
    "See more: https://workbench.cisecurity.org/\n"
    "HIIS10 v1.0 - 2026"
)

def numeric_sort_key(filename: str):
    nums = re.findall(r"\d+", filename)
    return [int(n) for n in nums]


def list_ps1(folder: str):
    if not os.path.exists(folder):
        return []
    files = [f for f in os.listdir(folder) if f.lower().endswith(".ps1")]
    return sorted(files, key=numeric_sort_key)


def run_powershell(script_path: str, hide_window: bool):
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", script_path,
    ]

    if os.name != "nt":
        p = subprocess.run(cmd, capture_output=hide_window, text=True, shell=False)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

    if hide_window:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        p = subprocess.run(
            cmd[:-2] + ["-WindowStyle", "Hidden"] + cmd[-2:],
            capture_output=True,
            text=True,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
            startupinfo=startupinfo,
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

    p = subprocess.run(
        cmd[:-2] + ["-WindowStyle", "Normal"] + cmd[-2:],
        shell=False,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    return p.returncode, "", ""


def popen_powershell_hidden(script_path: str):
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", script_path,
    ]

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
        startupinfo=startupinfo,
    )
    return p


def run_cmd_capture(cmd, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=cwd)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def start_service(service_name: str):
    return run_cmd_capture(["sc.exe", "start", service_name])


def restart_iis_cmd():
    return run_cmd_capture(["iisreset"])


def backup_folder(source: str, prefix: str, stamp: str):
    if not os.path.exists(source):
        raise FileNotFoundError(f"Source folder does not exist: {source}")
    dest = os.path.join(BACKUP_DIR, f"{prefix}_{stamp}")
    shutil.copytree(source, dest)
    return dest


def find_dotnet_config_folders():
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


def open_folder(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

    if os.name == "nt":
        subprocess.Popen(["explorer", path], shell=False)
        return

    try:
        subprocess.Popen(["open", path], shell=False)
    except Exception:
        subprocess.Popen(["xdg-open", path], shell=False)


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


class HardeningGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("HIIS10 v1.0")
        self.geometry("950x600")
        self.minsize(950, 600)

        self.mode_var = tk.StringVar(value="deployment")
        self.script_var = tk.StringVar(value="")

        self.logfile = os.path.join(LOG_DIR, f"hiis10_gui-{datetime.now():%Y%m%d}.log")

        self.abort_event = threading.Event()
        self.current_runall_proc = None

        self._build_ui()
        self._refresh_scripts()

        self.log("GUI started")
        self.log(f"BASE_DIR: {BASE_DIR}")
        self.log(f"Deployment dir: {DEPLOYMENT_DIR}")
        self.log(f"Rollback dir: {ROLLBACK_DIR}")

    def _build_ui(self):
        banner_frame = ttk.Frame(self, padding=10)
        banner_frame.pack(fill="x")
        ttk.Label(banner_frame, text=BANNER, justify="left").pack(anchor="w")

        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        mode_frame = ttk.LabelFrame(top, text="Mode", padding=10)
        mode_frame.pack(side="left", fill="y")

        ttk.Radiobutton(
            mode_frame,
            text="Hardening Deployment",
            value="deployment",
            variable=self.mode_var,
            command=self._refresh_scripts,
        ).pack(anchor="w", pady=2)

        ttk.Radiobutton(
            mode_frame,
            text="Hardening Rollback",
            value="rollback",
            variable=self.mode_var,
            command=self._refresh_scripts,
        ).pack(anchor="w", pady=2)

        script_frame = ttk.LabelFrame(top, text="Scripts", padding=10)
        script_frame.pack(side="left", fill="both", expand=True, padx=10)

        ttk.Label(script_frame, text="Select a script:").pack(anchor="w")
        self.combo = ttk.Combobox(script_frame, textvariable=self.script_var, state="readonly")
        self.combo.pack(fill="x", pady=6)

        btns = ttk.Frame(script_frame)
        btns.pack(anchor="w")

        ttk.Button(btns, text="Run Selected", command=self.run_selected).pack(side="left")
        ttk.Button(btns, text="Run All", command=self.run_all).pack(side="left", padx=8)

        self.abort_btn = ttk.Button(btns, text="Abort", command=self.abort_runall, state="disabled")
        self.abort_btn.pack(side="left", padx=8)

        ttk.Button(btns, text="Open Script_Logs", command=self.open_script_logs).pack(side="left", padx=8)
        ttk.Button(btns, text="Open HIIS_Logs", command=self.open_hiis_logs).pack(side="left", padx=8)

        self.progress_var = tk.IntVar(value=0)
        self.progress_label_var = tk.StringVar(value="Idle")

        ttk.Label(script_frame, textvariable=self.progress_label_var).pack(anchor="w", pady=(10, 2))
        self.progress = ttk.Progressbar(
            script_frame, orient="horizontal", mode="determinate", variable=self.progress_var
        )
        self.progress.pack(fill="x")

        actions = ttk.LabelFrame(top, text="Actions", padding=10)
        actions.pack(side="left", fill="y")

        ttk.Button(actions, text="Backup inetpub & inetsrv", command=self.backup_both).pack(fill="x", pady=2)
        ttk.Button(actions, text="Backup .NET Folders", command=self.backup_dotnet).pack(fill="x", pady=2)

        ttk.Button(actions, text="Check Hardening", command=self.check_hardening).pack(fill="x", pady=2)

        ttk.Button(actions, text="Restart IIS service", command=self.restart_iis).pack(fill="x", pady=2)
        ttk.Button(actions, text="Clear Screen", command=self.clear_log).pack(fill="x", pady=2)

        log_frame = ttk.LabelFrame(self, text="Execution Log", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, wrap="word")
        self.log_text.pack(side="left", fill="both", expand=True)

        scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)

    def open_script_logs(self):
        try:
            open_folder(SCRIPT_LOGS_DIR)
            self.log(f"Opened folder: {SCRIPT_LOGS_DIR}")
        except Exception as e:
            self.log(f"ERROR: Failed to open Script_Logs folder | {e}")
            messagebox.showerror("Open folder failed", "Failed to open Script_Logs folder. Check the log.")

    def open_hiis_logs(self):
        try:
            open_folder(HIIS_LOGS_DIR)
            self.log(f"Opened folder: {HIIS_LOGS_DIR}")
        except Exception as e:
            self.log(f"ERROR: Failed to open HIIS_Logs folder | {e}")
            messagebox.showerror("Open folder failed", "Failed to open HIIS_Logs folder. Check the log.")

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.log_text.insert("end", line)
        self.log_text.see("end")
        with open(self.logfile, "a", encoding="utf-8") as f:
            f.write(line)

    def clear_log(self):
        self.log_text.delete("1.0", "end")
        self.log("Log cleared")

    def _set_progress(self, current: int, total: int, text: str):
        def ui():
            self.progress["maximum"] = total if total > 0 else 1
            self.progress_var.set(current)
            self.progress_label_var.set(text)
        self.after(0, ui)

    def _runall_log_line(self, runall_logfile: str, script_name: str, ok: bool):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "Script executed successfully!" if ok else "Script executed FAIL!"
        line = f"[{ts}] - {script_name} - {status}\n"
        with open(runall_logfile, "a", encoding="utf-8") as f:
            f.write(line)

    def _set_abort_enabled(self, enabled: bool):
        def ui():
            self.abort_btn.configure(state=("normal" if enabled else "disabled"))
        self.after(0, ui)

    def _refresh_scripts(self):
        mode = self.mode_var.get()
        folder = DEPLOYMENT_DIR if mode == "deployment" else ROLLBACK_DIR
        scripts = list_ps1(folder)
        self.combo["values"] = scripts
        self.script_var.set(scripts[0] if scripts else "")
        self.log(f"Loaded {len(scripts)} script(s) for mode: {mode}")

    def _thread(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def abort_runall(self):
        self.abort_event.set()
        self.log("ABORT requested by user.")
        self._set_progress(self.progress_var.get(), max(int(self.progress["maximum"]), 1), "Abort requested...")

        proc = self.current_runall_proc
        if proc is not None:
            try:
                proc.terminate()
                self.log("ABORT: Terminate signal sent to current PowerShell process.")
            except Exception as e:
                self.log(f"ABORT: Failed to terminate process | {e}")

    def _backup_both_internal(self) -> bool:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        ok = True

        self.log(f"Starting backup inetpub ({INETPUB_PATH})")
        try:
            dest1 = backup_folder(INETPUB_PATH, "inetpub", stamp)
            self.log(f"SUCCESS: inetpub backup completed -> {dest1}")
        except Exception as ex:
            ok = False
            self.log(f"ERROR: inetpub backup failed | {ex}")

        self.log(f"Starting backup inetsrv ({INETSRV_PATH})")
        try:
            dest2 = backup_folder(INETSRV_PATH, "inetsrv", stamp)
            self.log(f"SUCCESS: inetsrv backup completed -> {dest2}")
        except Exception as ex:
            ok = False
            self.log(f"ERROR: inetsrv backup failed | {ex}")

        return ok

    def backup_both(self):
        def job():
            ok = self._backup_both_internal()
            if not ok:
                messagebox.showerror("Backup failed", "One or more backups failed. Check the log.")
        self._thread(job)

    def _backup_dotnet_internal(self) -> bool:
        targets = find_dotnet_config_folders()
        if not targets:
            self.log("ERROR: No .NET folders found with patterns:")
            self.log(f" - {DOTNET_V2_CONFIG_GLOB}")
            self.log(f" - {DOTNET_V4_CONFIG_GLOB}")
            return False

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        ok_all = True

        self.log("Starting backup .NET folders...")
        for src, prefix in targets:
            self.log(f"Starting backup {src}")
            try:
                dest = backup_folder(src, prefix, stamp)
                self.log(f"SUCCESS: {prefix} backup completed -> {dest}")
            except Exception as ex:
                ok_all = False
                self.log(f"ERROR: {prefix} backup failed | {ex}")

        return ok_all

    def backup_dotnet(self):
        def job():
            ok = self._backup_dotnet_internal()
            if not ok:
                messagebox.showerror("Backup failed", "Backup .NET folders failed (or no folders found). Check the log.")
        self._thread(job)

    def _backup_deployment_prereq_internal(self) -> bool:
        self.log("Starting DEPLOYMENT pre-run backup: inetpub + inetsrv + .NET folders")

        ok_iis = self._backup_both_internal()
        if not ok_iis:
            self.log("ERROR: DEPLOYMENT pre-run backup failed (inetpub/inetsrv).")
            return False

        ok_dotnet = self._backup_dotnet_internal()
        if not ok_dotnet:
            self.log("ERROR: DEPLOYMENT pre-run backup failed (.NET folders).")
            return False

        self.log("SUCCESS: DEPLOYMENT pre-run backup completed.")
        return True

    def _zip_backups_internal(self) -> tuple[bool, str | None]:
        hostname = socket.gethostname()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        zip_name = f"{hostname}_HIIS10_BackupFull_{stamp}.zip"
        zip_path = os.path.join(BACKUP_DIR, zip_name)

        self.log(f"Starting ZIP of backups folder -> {zip_path}")
        rc, out, err = zip_backup_folder(ZIP_EXE, BACKUP_DIR, zip_path)

        if rc == 0:
            self.log(f"SUCCESS: Backup ZIP created -> {zip_path}")
            if out:
                self.log(f"zip.exe output: {out}")
            return True, zip_path

        self.log(f"ERROR: Failed to create backup ZIP | rc={rc}")
        if out:
            self.log(f"zip.exe stdout: {out}")
        if err:
            self.log(f"zip.exe stderr: {err}")
        return False, None

    def _cleanup_backups_after_zip_internal(self, zip_path: str) -> bool:
        self.log("Starting cleanup: removing all items in backups folder except the generated ZIP...")
        ok, errors = cleanup_backups_keep_zip(BACKUP_DIR, zip_path)

        if ok:
            self.log("SUCCESS: Cleanup completed. Only ZIP kept in backups folder.")
            return True

        self.log("ERROR: Cleanup completed with failures:")
        for e in errors:
            self.log(f" - {e}")
        return False

    def check_hardening(self):
        def job():
            path = CHECK_HARDENING_PS1

            if not os.path.isfile(path):
                self.log(f"ERROR: Check_Hardening.ps1 not found: {path}")
                messagebox.showerror(
                    "Check Hardening",
                    "Check_Hardening.ps1 não encontrado na pasta scripts. Verifique o caminho."
                )
                return

            self.log(f"Executing Check Hardening (silent): {path}")

            try:
                rc, out, err = run_powershell(path, hide_window=True)

                if rc == 0:
                    self.log("SUCCESS: Check Hardening")
                else:
                    self.log(f"ERROR: Check Hardening | rc={rc}")

                if out:
                    self.log(f"stdout: {out}")
                if err:
                    self.log(f"stderr: {err}")

                if rc != 0:
                    messagebox.showwarning(
                        "Check Hardening",
                        "Check Hardening finalizado com erros. Consulte o log."
                    )

            except Exception as e:
                self.log(f"ERROR: Check Hardening | {e}")
                messagebox.showerror(
                    "Check Hardening",
                    "Erro inesperado durante a execução. Consulte o log."
                )

        self._thread(job)

    def run_selected(self):
        script = self.script_var.get()
        if not script:
            messagebox.showwarning("No script", "No script selected.")
            return

        folder = DEPLOYMENT_DIR if self.mode_var.get() == "deployment" else ROLLBACK_DIR
        path = os.path.join(folder, script)

        def job():
            self.log(f"Executing (visible console): {path}")
            try:
                rc, _, _ = run_powershell(path, hide_window=False)
                if rc == 0:
                    self.log(f"SUCCESS: {script}")
                else:
                    self.log(f"ERROR: {script} | rc={rc}")
                    messagebox.showerror("Execution failed", "Script execution failed. Check the log.")
            except Exception as e:
                self.log(f"ERROR: {script} | {e}")
                messagebox.showerror("Execution failed", "Unexpected error. Check the log.")

        self._thread(job)

    def run_all(self):
        mode = self.mode_var.get()
        folder = DEPLOYMENT_DIR if mode == "deployment" else ROLLBACK_DIR
        scripts = list_ps1(folder)
        if not scripts:
            messagebox.showinfo("No scripts", "No scripts were found for this mode.")
            return

        def job():
            self.abort_event.clear()
            self.current_runall_proc = None
            self._set_abort_enabled(True)

            total = len(scripts)
            self._set_progress(0, total, f"Starting... 0/{total}")

            runall_logfile = os.path.join(LOG_DIR, f"hiis10_gui-runall_{datetime.now():%Y%m%d}.log")
            with open(runall_logfile, "a", encoding="utf-8") as f:
                f.write(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] - RUNALL started | mode={mode}\n")

            if mode == "deployment":
                if self.abort_event.is_set():
                    self.log("RUNALL aborted before backup.")
                    with open(runall_logfile, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] - RUNALL aborted (before backup)\n")
                    self._set_progress(0, total, "Aborted.")
                    return

                ok_backup = self._backup_deployment_prereq_internal()
                if not ok_backup:
                    self.log("ERROR: Backup failed. Deployment execution aborted.")
                    self._set_progress(0, total, "Backup failed. Aborted.")
                    messagebox.showerror("Backup failed", "Backup failed. Deployment execution aborted.")
                    with open(runall_logfile, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] - RUNALL aborted (backup failed)\n")
                    return

            for i, s in enumerate(scripts, start=1):
                if self.abort_event.is_set():
                    self.log(f"RUNALL aborted by user before executing next script ({i}/{total}).")
                    with open(runall_logfile, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] - RUNALL aborted by user\n")
                    self._set_progress(i - 1, total, f"Aborted at {i-1}/{total}")
                    return

                p = os.path.join(folder, s)
                self._set_progress(i - 1, total, f"Executing {i}/{total}: {s}")
                self.log(f"Executing (silent): {p}")

                ok = False
                try:
                    proc = popen_powershell_hidden(p)
                    self.current_runall_proc = proc

                    out, err = proc.communicate()
                    rc = proc.returncode
                    out = (out or "").strip()
                    err = (err or "").strip()

                    self.current_runall_proc = None

                    if self.abort_event.is_set():
                        self.log(f"RUNALL aborted during execution: {s}")
                        self._runall_log_line(runall_logfile, s, False)
                        with open(runall_logfile, "a", encoding="utf-8") as f:
                            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] - RUNALL aborted during execution\n")
                        self._set_progress(i, total, f"Aborted at {i}/{total}")
                        return

                    if rc == 0:
                        ok = True
                        self.log(f"SUCCESS: {s}")
                    else:
                        self.log(f"ERROR: {s} | rc={rc}")
                        if out:
                            self.log(f"stdout: {out}")
                        if err:
                            self.log(f"stderr: {err}")

                except Exception as e:
                    self.current_runall_proc = None
                    self.log(f"ERROR: {s} | {e}")

                self._runall_log_line(runall_logfile, s, ok)
                self._set_progress(i, total, f"Completed {i}/{total}")

            self.log("All scripts were executed. Check the logs to ensure there are no errors.")
            self._set_progress(total, total, f"Done {total}/{total}")

            with open(runall_logfile, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] - RUNALL finished\n")

            if mode == "deployment" and not self.abort_event.is_set():
                ok_zip, zip_path = self._zip_backups_internal()
                if not ok_zip or not zip_path:
                    messagebox.showwarning(
                        "Backup ZIP failed",
                        "Falha ao compactar a pasta de backups. Verifique se zip.exe existe no diretório raiz e consulte o log.",
                    )
                    self._restart_iis_internal()
                    return

                ok_cleanup = self._cleanup_backups_after_zip_internal(zip_path)
                if not ok_cleanup:
                    messagebox.showwarning(
                        "Cleanup failed",
                        "Falha ao limpar a pasta de backups (mantendo apenas o .zip). Consulte o log.",
                    )

                self._restart_iis_internal()

        def finally_disable_abort():
            self._set_abort_enabled(False)
            self.current_runall_proc = None

        def wrapped_job():
            try:
                job()
            finally:
                finally_disable_abort()

        self._thread(wrapped_job)

    def _restart_iis_internal(self):
        self.log("Restarting IIS using iisreset...")

        rc, out, err = restart_iis_cmd()

        if rc == 0:
            self.log("SUCCESS: IIS restarted")
            if out:
                self.log(f"iisreset output: {out}")
            return

        if rc == 1062:
            self.log("WARNING: iisreset returned 1062 (service not started). Attempting to start WAS and W3SVC...")

            rc1, o1, e1 = start_service("WAS")
            self.log(f"sc start WAS -> rc={rc1} | out={o1} | err={e1}")

            rc2, o2, e2 = start_service("W3SVC")
            self.log(f"sc start W3SVC -> rc={rc2} | out={o2} | err={e2}")

            self.log("Retrying iisreset...")
            rcR, outR, errR = restart_iis_cmd()

            if rcR == 0:
                self.log("SUCCESS: IIS restarted (after starting services)")
                if outR:
                    self.log(f"iisreset output: {outR}")
                return

            self.log(f"ERROR: IIS restart failed after retry | rc={rcR} | out={outR} | err={errR}")
            messagebox.showwarning("IIS restart failed", "IIS restart failed. Check the log.")
            return

        self.log(f"ERROR: IIS restart failed | rc={rc} | out={out} | err={err}")
        messagebox.showwarning("IIS restart failed", "IIS restart failed. Check the log.")

    def restart_iis(self):
        self._thread(self._restart_iis_internal)


if __name__ == "__main__":
    app = HardeningGUI()
    app.mainloop()
