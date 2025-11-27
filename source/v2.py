# adb_apk_installer_with_permissions.py
import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# External dependency:
# pip install apkutils-patch
try:
    from apkutils2 import APK
except Exception as e:
    print("ERROR: apkutils2 not found. Install with: pip install apkutils-patch")
    raise

# ---------------------------
# Helpers for subprocess (no PowerShell popup on Windows)
# ---------------------------
IS_WINDOWS = os.name == "nt"

def run_subprocess(cmd, capture_output=True, text=True, check=False):
    """
    Runs subprocess safely (hides console on Windows).
    Returns CompletedProcess (or raises if check=True and returncode != 0).
    """
    kwargs = dict(stdout=subprocess.PIPE if capture_output else None,
                  stderr=subprocess.PIPE if capture_output else None,
                  text=text)
    if IS_WINDOWS:
        # Prevent console window popups on Windows
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        startupinfo = subprocess.STARTUPINFO()
        # startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # optional
        kwargs['startupinfo'] = startupinfo

    if check:
        return subprocess.run(cmd, check=True, **kwargs)
    else:
        return subprocess.run(cmd, **kwargs)

# ---------------------------
# Thread-safe logging for Tkinter + console
# ---------------------------
log_text_widget = None
install_button = None
browse_button = None
device_combo = None
apk_listbox = None

def log_output(msg):
    # Always print to console
    print(msg)
    # If GUI text widget exists, insert in thread-safe manner
    if log_text_widget:
        try:
            log_text_widget.after(0, lambda: _append_log(msg))
        except Exception:
            # fallback
            _append_log(msg)

def _append_log(msg):
    if log_text_widget:
        log_text_widget.insert(tk.END, msg + "\n")
        log_text_widget.see(tk.END)

# ---------------------------
# ADB helpers
# ---------------------------
def get_connected_devices():
    try:
        cp = run_subprocess(['adb', 'devices'])
        out = cp.stdout if cp.stdout is not None else ""
        devices = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line and line.endswith('device'):
                parts = line.split()
                devices.append(parts[0])
        return devices
    except Exception as e:
        log_output(f"[!] Error listing devices: {e}")
        return []

def get_device_sdk(device):
    """
    Returns integer SDK version for the device, or None on failure.
    """
    try:
        cp = run_subprocess(['adb', '-s', device, 'shell', 'getprop', 'ro.build.version.sdk'])
        out = (cp.stdout or "").strip()
        if out and out.isdigit():
            return int(out)
        # sometimes returns empty or with newline; try int conversion
        try:
            return int(out)
        except:
            return None
    except Exception as e:
        log_output(f"[!] Failed to get SDK version for {device}: {e}")
        return None

# ---------------------------
# Permission granting logic
# ---------------------------
def grant_storage_permissions(device, package_name, sdk_ver):
    """
    Attempts to grant appropriate storage/media permissions based on device sdk.
    We will run several attempts; failing to grant a permission is non-fatal.
    """
    if not package_name:
        log_output("[!] No package name provided for permission granting.")
        return

    attempts = []

    # For Android 13+ (SDK 33+): grant READ_MEDIA_* permissions
    if sdk_ver is not None and sdk_ver >= 33:
        attempts += [
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            # Some apps may still request READ_EXTERNAL_STORAGE; attempt it too
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]
    # For Android 11 & 12 (SDK 30-32): MANAGE_EXTERNAL_STORAGE can be used for broad access
    elif sdk_ver is not None and sdk_ver >= 30:
        # Try pm grant for read/write too (may or may not be requested by app)
        attempts += [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        ]
    # Older Android: READ/WRITE external storage
    else:
        attempts += [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]

    log_output(f"[i] Granting candidate storage permissions for {package_name} (SDK {sdk_ver})")

    for perm in attempts:
        try:
            # Try pm grant first
            cp = run_subprocess(['adb', '-s', device, 'shell', 'pm', 'grant', package_name, perm])
            # pm grant returns nothing on success; if stderr present, show it
            stdout = cp.stdout or ""
            stderr = cp.stderr or ""
            if cp.returncode == 0:
                log_output(f"[✓] pm grant {perm} -> OK for {package_name}")
            else:
                # Non-zero but continue
                log_output(f"[~] pm grant {perm} returned code {cp.returncode} for {package_name}. stdout: {stdout.strip()} stderr: {stderr.strip()}")

            # Special handling for MANAGE_EXTERNAL_STORAGE: pm grant sometimes fails. Try appops / cmd as fallback.
            if perm == "android.permission.MANAGE_EXTERNAL_STORAGE":
                try:
                    # cmd appops set <package> MANAGE_EXTERNAL_STORAGE allow
                    cp2 = run_subprocess(['adb', '-s', device, 'shell', 'cmd', 'appops', 'set', package_name, 'MANAGE_EXTERNAL_STORAGE', 'allow'])
                    if cp2.returncode == 0:
                        log_output(f"[✓] appops allow MANAGE_EXTERNAL_STORAGE for {package_name}")
                except Exception as e:
                    log_output(f"[!] appops fallback failed for MANAGE_EXTERNAL_STORAGE: {e}")

        except subprocess.CalledProcessError as e:
            # pm grant failed
            stderr = e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else str(e)
            log_output(f"[✗] pm grant {perm} failed: {stderr}")
        except Exception as e:
            log_output(f"[✗] Error while granting {perm}: {e}")

# ---------------------------
# Install & auto-run flow
# ---------------------------
def install_and_postprocess(device, apk_paths, on_done=None):
    """
    Installs the list of apk_paths on device, then extracts package+launcher using apkutils,
    attempts to grant storage permissions based on device SDK, and launches the app.
    """
    try:
        sdk = get_device_sdk(device)
        if sdk is None:
            log_output(f"[!] Could not detect Android SDK version for device {device}. Permission-granting may be limited.")

        for apk_path in apk_paths:
            apk_name = os.path.basename(apk_path)
            log_output(f"[i] Installing {apk_name} to {device}...")

            # Install APK
            try:
                cp = run_subprocess(['adb', '-s', device, 'install', '-r', apk_path], capture_output=True, text=True, check=False)
                if cp.returncode == 0:
                    log_output(f"[✓] Installed {apk_name} on {device}")
                else:
                    stderr = (cp.stderr or "").strip()
                    log_output(f"[✗] Failed to install {apk_name} on {device}: {stderr}")
                    # continue to next apk
                    continue
            except Exception as e:
                log_output(f"[✗] Exception installing {apk_name}: {e}")
                continue

            # Use apkutils to read manifest
            package_name = None
            main_activity = None
            try:
                apk_info = APK(apk_path)
                # package name
                try:
                    package_name = apk_info.get_manifest().package_name
                except Exception:
                    # fallback attempt
                    try:
                        package_name = apk_info.get_package()
                    except Exception:
                        package_name = None

                # main/launcher activity
                try:
                    main_activity = apk_info.get_main_activity()
                except Exception:
                    main_activity = None

                log_output(f"[i] APK detected package: {package_name}, main activity: {main_activity}")
            except Exception as e:
                log_output(f"[!] Error parsing APK with apkutils: {e}")

            # Grant storage/media permissions (best-effort)
            if package_name:
                grant_storage_permissions(device, package_name, sdk)

            # Launch the app (best attempt)
            if package_name:
                # Build full activity string for am start -n
                if main_activity:
                    # Normalize main_activity into full component form
                    # Cases:
                    # - "com.example.app.MainActivity" -> OK
                    # - ".MainActivity" or "MainActivity" -> need package prefix
                    if main_activity.startswith("."):
                        full_activity = f"{package_name}/{package_name}{main_activity}"
                    elif "/" in main_activity:
                        # If already contains slash (unlikely), use it
                        full_activity = main_activity
                    elif main_activity.startswith(package_name):
                        # something like com.example.app.MainActivity -> need slash between package and activity
                        full_activity = f"{package_name}/{main_activity}"
                    else:
                        # main_activity might be "com.example.app.MainActivity" or "MainActivity"
                        # If it looks like full class name (contains dots), attach to package
                        if "." in main_activity:
                            # if it already begins with package_name, use it
                            if main_activity.startswith(package_name):
                                full_activity = f"{package_name}/{main_activity}"
                            else:
                                # treat as full class name but ensure slash form
                                full_activity = f"{package_name}/{main_activity}"
                        else:
                            # bare activity name, prefix with package
                            full_activity = f"{package_name}/{package_name}.{main_activity}"
                else:
                    # No main activity found; fallback to monkey which will simulate launcher tap
                    full_activity = None

                if full_activity:
                    try:
                        cp_start = run_subprocess(['adb', '-s', device, 'shell', 'am', 'start', '-n', full_activity], check=False)
                        if cp_start.returncode == 0:
                            log_output(f"[✓] Launched {package_name} via {full_activity}")
                        else:
                            # if start failed, fallback to monkey
                            log_output(f"[~] am start returned code {cp_start.returncode}. Falling back to monkey.")
                            cp_monkey = run_subprocess(['adb', '-s', device, 'shell', 'monkey', '-p', package_name, '1'])
                            if cp_monkey.returncode == 0:
                                log_output(f"[✓] Launched {package_name} via monkey")
                            else:
                                log_output(f"[✗] Failed to launch {package_name} (monkey code {cp_monkey.returncode})")
                    except Exception as e:
                        log_output(f"[✗] Exception while launching {package_name}: {e}")
                else:
                    # Use monkey fallback
                    try:
                        cp_monkey = run_subprocess(['adb', '-s', device, 'shell', 'monkey', '-p', package_name, '1'])
                        if cp_monkey.returncode == 0:
                            log_output(f"[✓] Launched {package_name} via monkey fallback")
                        else:
                            log_output(f"[✗] Failed to launch {package_name} (monkey returned {cp_monkey.returncode})")
                    except Exception as e:
                        log_output(f"[✗] Exception while launching (monkey) {package_name}: {e}")
            else:
                log_output("[!] Skipping launch: package name not detected.")

    finally:
        # call on_done callback (used to re-enable UI)
        if callable(on_done):
            try:
                on_done()
            except Exception:
                pass

# ---------------------------
# GUI functions
# ---------------------------
def browse_apks():
    paths = filedialog.askopenfilenames(title="Select APK files", filetypes=[("APK files", "*.apk")])
    if paths:
        apk_listbox.delete(0, tk.END)
        for p in paths:
            apk_listbox.insert(tk.END, p)

def refresh_devices():
    devices = get_connected_devices()
    if device_combo:
        device_combo['values'] = devices
        if devices:
            # select first device if none selected
            if not device_combo.get():
                device_combo.set(devices[0])

def on_install_clicked():
    device = device_combo.get().strip()
    if not device:
        messagebox.showwarning("Device required", "Select a device first (Refresh if needed).")
        return
    apk_paths = list(apk_listbox.get(0, tk.END))
    if not apk_paths:
        messagebox.showwarning("APK required", "Select at least one APK to install.")
        return

    # Disable UI
    _set_ui_state(disabled=True)
    log_output(f"[i] Starting install thread for {len(apk_paths)} APK(s) on {device}...")

    def done_callback():
        # re-enable UI on GUI thread
        if log_text_widget:
            log_text_widget.after(0, lambda: _set_ui_state(disabled=False))
        else:
            _set_ui_state(disabled=False)
        log_output("[i] Install process finished.")

    # Start worker thread
    worker = threading.Thread(target=install_and_postprocess, args=(device, apk_paths, done_callback), daemon=True)
    worker.start()

def _set_ui_state(disabled=False):
    state = "disabled" if disabled else "normal"
    if install_button:
        install_button.config(state=state)
    if browse_button:
        browse_button.config(state=state)
    if device_combo:
        if disabled:
            device_combo.config(state="disabled")
        else:
            device_combo.config(state="readonly")
    if apk_listbox:
        if disabled:
            apk_listbox.config(state="disabled")
        else:
            apk_listbox.config(state="normal")

def open_add_device_window():
    def connect_action():
        ip_port = ip_entry.get().strip()
        pairing = code_entry.get().strip()
        if not ip_port:
            messagebox.showwarning("Missing IP:Port", "Enter IP:Port (example: 192.168.0.10:5555)")
            return
        # connect in background
        def do_connect():
            try:
                if pairing:
                    log_output(f"[i] Pairing with {ip_port} using code...")
                    run_subprocess(['adb', 'pair', ip_port, pairing], check=False)
                    log_output(f"[i] Pairing attempted for {ip_port}.")
                else:
                    log_output(f"[i] Connecting to {ip_port}...")
                    run_subprocess(['adb', 'connect', ip_port], check=False)
                    log_output(f"[i] Connect attempted for {ip_port}.")
                # refresh device list on GUI thread
                if log_text_widget:
                    log_text_widget.after(0, refresh_devices)
                else:
                    refresh_devices()
            except Exception as e:
                log_output(f"[✗] Connect error: {e}")

        threading.Thread(target=do_connect, daemon=True).start()
        add_window.destroy()

    add_window = tk.Toplevel()
    add_window.title("Add ADB Device")
    ttk.Label(add_window, text="IP:Port").grid(row=0, column=0, padx=5, pady=5)
    ip_entry = ttk.Entry(add_window, width=30)
    ip_entry.grid(row=0, column=1, padx=5, pady=5)
    ttk.Label(add_window, text="Pairing code (optional)").grid(row=1, column=0, padx=5, pady=5)
    code_entry = ttk.Entry(add_window, width=30)
    code_entry.grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(add_window, text="Connect", command=connect_action).grid(row=2, column=0, columnspan=2, pady=10)

def run_gui():
    global device_combo, apk_listbox, log_text_widget, install_button, browse_button

    root = tk.Tk()
    root.title("ADB APK Installer (auto-perm + auto-run)")

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)

    # Row 0 - Devices
    ttk.Label(frame, text="Device:").grid(row=0, column=0, sticky=tk.W)
    device_combo = ttk.Combobox(frame, width=40, state="readonly")
    device_combo.grid(row=0, column=1, sticky=tk.W)
    ttk.Button(frame, text="Refresh", command=refresh_devices).grid(row=0, column=2, padx=5)
    ttk.Button(frame, text="Add Device", command=open_add_device_window).grid(row=0, column=3, padx=5)

    # Row 1 - APK list
    ttk.Label(frame, text="APK Files:").grid(row=1, column=0, sticky=tk.NW)
    apk_listbox = tk.Listbox(frame, height=6, width=70, selectmode=tk.EXTENDED)
    apk_listbox.grid(row=1, column=1, columnspan=3, pady=5)

    # Row 2 - Buttons
    browse_button = ttk.Button(frame, text="Browse APKs", command=browse_apks)
    browse_button.grid(row=2, column=1, sticky=tk.W)
    install_button = ttk.Button(frame, text="Install to Device", command=on_install_clicked)
    install_button.grid(row=2, column=2, sticky=tk.W)

    # Row 3 - Log
    ttk.Label(frame, text="Log:").grid(row=3, column=0, sticky=tk.NW)
    log_text_widget = tk.Text(frame, height=14, width=100)
    log_text_widget.grid(row=3, column=1, columnspan=3, pady=10)

    # Populate device list
    refresh_devices()
    root.mainloop()

# ---------------------------
# CLI support (optional)
# ---------------------------
def cli_list_devices():
    devs = get_connected_devices()
    if devs:
        print("Connected devices:")
        for d in devs:
            print(" -", d)
    else:
        print("No devices found.")

def cli_install(device, apks):
    def on_done():
        print("[i] CLI install finished.")
    install_and_postprocess(device, apks, on_done)

# ---------------------------
# Main entry
# ---------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ADB APK Installer with auto-grant and auto-run")
    parser.add_argument("--devices", action="store_true", help="List connected adb devices")
    parser.add_argument("--install", nargs='+', help="Install APK(s) to device: first argument must be device id, remaining are apk paths", metavar="ARGS")
    args = parser.parse_args()

    if args.devices:
        cli_list_devices()
        sys.exit(0)

    if args.install:
        if len(args.install) < 2:
            print("Usage: --install <device> <apk1> [apk2 ...]")
            sys.exit(1)
        dev = args.install[0]
        apks = args.install[1:]
        cli_install(dev, apks)
        sys.exit(0)

    # GUI mode
    run_gui()
