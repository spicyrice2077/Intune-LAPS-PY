import msal
import requests
import base64
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
import pyperclip
import threading

CLIENT_ID = "xxxxxxxxxxxxxxxxxxxx"
TENANT_ID = "xxxxxxxxxxxxxxxxxxxx"
GRAPH_API_ENDPOINT = "https://graph.microsoft.com"


class GraphApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Intune LAPS PY - Matrix Edition")

        # Window geometry
        self.geometry("750x450")
        self.resizable(False, False)

        # Overall background color—black
        self.configure(bg="#000000")

        self.token = None
        self.create_widgets()

    def create_widgets(self):
        # Colors
        bg_color = "#000000"  # Pure black
        fg_color = "#00FF00"  # Bright green
        button_bg = "#222222"  # Dark gray for buttons
        entry_bg = "#111111"  # Slightly lighter black for entry
        text_bg = "#000000"  # Keep text background pure black

        # Container frame
        top_frame = tk.Frame(self, bg=bg_color)
        top_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel
        left_frame = tk.Frame(top_frame, bg=bg_color)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        # Sub-frame for login/logout side by side
        login_frame = tk.Frame(left_frame, bg=bg_color)
        login_frame.pack(anchor="w", pady=5)

        self.login_btn = tk.Button(
            login_frame,
            text="Login",
            command=self.start_login_thread,
            bg=button_bg,
            fg=fg_color,
            activebackground="#444444",
            activeforeground=fg_color
        )
        self.login_btn.pack(side=tk.LEFT)

        self.logout_btn = tk.Button(
            login_frame,
            text="Logout",
            command=self.logout,
            bg=button_bg,
            fg=fg_color,
            state="disabled",
            activebackground="#444444",
            activeforeground=fg_color
        )
        self.logout_btn.pack(side=tk.LEFT, padx=5)

        self.device_label = tk.Label(
            left_frame,
            text="Device Hostname:",
            bg=bg_color,
            fg=fg_color
        )
        self.device_label.pack(pady=5, anchor="w")

        self.device_entry = tk.Entry(
            left_frame,
            bg=entry_bg,
            fg=fg_color,
            insertbackground=fg_color
        )
        self.device_entry.pack(pady=5, anchor="w")

        self.search_btn = tk.Button(
            left_frame,
            text="Search",
            command=self.search_device,
            bg=button_bg,
            fg=fg_color,
            state="disabled",
            activebackground="#444444",
            activeforeground=fg_color
        )
        self.search_btn.pack(pady=5, anchor="w")

        self.copy_btn = tk.Button(
            left_frame,
            text="Copy Password",
            command=self.copy_password,
            bg=button_bg,
            fg=fg_color,
            state="disabled",
            activebackground="#444444",
            activeforeground=fg_color
        )
        self.copy_btn.pack(pady=5, anchor="w")

        # Right panel (output)
        right_frame = tk.Frame(top_frame, bg=bg_color)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.output = tk.Text(
            right_frame,
            bg=text_bg,
            fg=fg_color,
            height=8
        )
        self.output.pack(pady=5, fill=tk.BOTH, expand=True)

    def start_login_thread(self):
        """Start the interactive login in a background thread so the UI remains responsive."""
        thread = threading.Thread(target=self.login, daemon=True)
        thread.start()

    def login(self):
        authority = f"https://login.microsoftonline.com/{TENANT_ID}"
        app = msal.PublicClientApplication(CLIENT_ID, authority=authority)

        try:
            result = app.acquire_token_interactive(
                scopes=["https://graph.microsoft.com/.default"],
                prompt='select_account'
            )
        except Exception as e:
            self.safe_insert_output(f"Login Error: {e}")
            return

        # Check if user canceled
        if not result or "access_token" not in result:
            self.safe_messagebox_error("Login Canceled", "You canceled or closed the browser window.")
            return

        # Valid token
        self.token = result['access_token']
        self.safe_insert_output("Login successful.\n")

        # Get currently logged-in user's info
        user_url = f"{GRAPH_API_ENDPOINT}/v1.0/me"
        response = requests.get(user_url, headers={"Authorization": f"Bearer {self.token}"})
        if response.status_code == 200:
            user_data = response.json()
            display_name = user_data.get("displayName")
            email = user_data.get("mail") or user_data.get("userPrincipalName")
            self.safe_insert_output(f"Logged in as: {display_name} <{email}>\n")
        else:
            self.safe_insert_output(
                f"Failed to fetch user info: {response.status_code} - {response.text}\n"
            )

        self.safe_config_button(self.login_btn, "disabled")
        self.safe_config_button(self.logout_btn, "normal")
        self.safe_config_button(self.search_btn, "normal")

    def logout(self):
        self.token = None
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "Logged out.\n")
        self.login_btn.config(state="normal")
        self.logout_btn.config(state="disabled")
        self.search_btn.config(state="disabled")
        self.copy_btn.config(state="disabled")

    def search_device(self):
        hostname = self.device_entry.get().strip()
        if not hostname:
            messagebox.showwarning("Input Error", "Please enter a hostname.")
            return

        try:
            device_id = self.get_device_id(hostname)
            creds = self.get_device_credentials(device_id)

            # Build a nicely aligned output
            label_width = 14
            output_text = (
                f"{'Account Name:':<{label_width}}{creds['accountName']}\n"
                f"{'Password:':<{label_width}}{creds['password']}\n"
                f"{'Last Updated:':<{label_width}}{creds['backupDateTime']}\n"
            )

            self.output.delete(1.0, tk.END)
            self.output.insert(tk.END, output_text)
            self.copy_btn.config(state="normal")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_password(self):
        lines = self.output.get(1.0, tk.END).splitlines()
        for line in lines:
            if line.startswith("Password:"):
                password = line.replace("Password:", "").strip()
                pyperclip.copy(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
                return

    def get_device_id(self, hostname):
        url = f"{GRAPH_API_ENDPOINT}/v1.0/devices?$filter=displayName eq '{hostname}'&$select=deviceId"
        response = requests.get(url, headers={"Authorization": f"Bearer {self.token}"})
        if response.status_code == 200:
            devices = response.json().get('value', [])
            if devices:
                return devices[0]['deviceId']
            else:
                raise Exception("Device not found.")
        else:
            raise Exception(f"API call failed: {response.status_code} - {response.text}")

    def get_device_credentials(self, device_id):
        url = f"{GRAPH_API_ENDPOINT}/v1.0/directory/deviceLocalCredentials/{device_id}?$select=credentials"
        response = requests.get(url, headers={"Authorization": f"Bearer {self.token}"})
        if response.status_code == 200:
            credentials = response.json().get('credentials', [])
            if credentials:
                # Sort by 'backupDateTime' descending and pick the latest
                credentials.sort(
                    key=lambda x: datetime.strptime(
                        x['backupDateTime'][:26], "%Y-%m-%dT%H:%M:%S.%f"
                    ),
                    reverse=True
                )
                latest = credentials[0]
                return {
                    'accountName': latest['accountName'],
                    'password': base64.b64decode(latest['passwordBase64']).decode('utf-8'),
                    'backupDateTime': latest['backupDateTime']
                }
            else:
                raise Exception("No credentials found.")
        else:
            raise Exception(f"API call failed: {response.status_code} - {response.text}")

    # --- Thread-safe UI updates ---
    def safe_insert_output(self, text):
        """Safely insert text into the output box from a background thread."""
        self.after(0, lambda: self.output.insert(tk.END, text + "\n"))

    def safe_messagebox_error(self, title, msg):
        """Safely show an error messagebox from a background thread."""
        self.after(0, lambda: messagebox.showerror(title, msg))

    def safe_config_button(self, button, state):
        """Safely change a button state from a background thread."""
        self.after(0, lambda: button.config(state=state))


if __name__ == "__main__":
    app = GraphApp()
    app.mainloop()
