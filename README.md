# Intune-LAPS-PY
Utilize a desktop GUI app to retrieve Intune LAPS passwords from endpoints.

### Prereqs:
- Azure AD Setup
  - App Registration: Create a new Azure AD app or use an existing one.
  - API Permissions: Ensure delegated permissions include:
    - DeviceLocalCredential.Read.All
    - Device.Read.All
    - User.Read
    - DeviceLocalCredential.Read.All

- Environment Requirements
  - Python 3.x installed (if running the .py directly).
  - Libraries: msal, requests, pyperclip (plus built-ins like tkinter, base64, datetime, threading).
  - (Optional) PyInstaller if you want a standalone .exe with no Python installation required.

![Optional Alt Text](https://github.com/spicyrice2077/Intune-LAPS-PY/blob/main/App.png?raw=true)


