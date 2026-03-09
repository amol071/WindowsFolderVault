# FolderVault 🔐

FolderVault is a **C# console application** that creates a **password-protected encrypted folder (vault)** on Windows.

The application encrypts files when the vault is locked and decrypts them when the correct password is entered. It can also run in **background mode** and automatically **lock the vault after a configurable timeout**.

---

# Features

- Password-protected encrypted vault
- AES-GCM encryption
- Secure password hashing using PBKDF2
- Automatic vault locking
- Background monitoring mode
- Windows startup integration
- Command-line interface
- Configurable auto-lock timer

---

# How It Works

FolderVault uses the following folder structure:

```
VaultFolder/
 ├── Open/           (decrypted files while vault is unlocked)
 ├── vault.bin       (encrypted archive of vault contents)
 └── .vault_open     (marker file used by auto-lock monitor)
```

Configuration is stored in:

```
vault.config.json
```

### Workflow

1. When the vault is **opened**, files are decrypted into the `Open` folder.
2. When the vault is **closed**:
   - Files are compressed
   - Data is encrypted
   - Encrypted archive is stored as `vault.bin`
3. The decrypted `Open` folder is deleted.

---

# Requirements

- Windows
- .NET 6 / .NET 7 / .NET 8
- Visual Studio 2022 (recommended)

---

# Building the Project

Clone the repository:

```bash
git clone https://github.com/amol071/foldervault.git
cd foldervault
```

Build with .NET CLI:

```bash
dotnet build
```

Or build using Visual Studio:

```
Build → Build Solution
```

The executable will be located in:

```
bin/Debug/netX.X/
```

or after publishing:

```
bin/Release/netX.X/publish/
```

---

# Usage

Run commands from **Command Prompt** or **PowerShell** in the folder containing `FolderVault.exe`.

Example:

```powershell
.\FolderVault.exe <command>
```

---

# Commands

## Initialize Vault

Creates a new encrypted vault.

```
FolderVault.exe init
```

You will be prompted for:

- vault folder path
- password
- password confirmation

---

## Open Vault

Decrypts the vault contents.

```
FolderVault.exe open
```

Files will appear in:

```
VaultFolder/Open/
```

---

## Close Vault

Encrypts all files and removes the decrypted folder.

```
FolderVault.exe close
```

---

## Check Vault Status

Displays vault information.

```
FolderVault.exe status
```

Example output:

```
Vault folder: C:\SecureVault
State: Open
Last opened (UTC): 2026-03-09T10:20:00Z
Auto-lock (minutes): 5
```

---

## Set Auto Lock Time

Configure automatic vault locking.

```
FolderVault.exe set-autolock <minutes>
```

Example:

```
FolderVault.exe set-autolock 5
```

---

## Run Background Monitor

Starts the auto-lock monitor.

```
FolderVault.exe background
```

The monitor periodically checks whether the vault should be locked.

---

## Enable Windows Startup

Adds FolderVault to Windows startup.

```
FolderVault.exe startup-on
```

This will run FolderVault in background mode when Windows starts.

---

## Disable Windows Startup

Remove the startup entry.

```
FolderVault.exe startup-off
```

---

# Example Workflow

Initialize vault:

```
FolderVault.exe init
```

Open vault:

```
FolderVault.exe open
```

Add files to:

```
VaultFolder/Open/
```

Lock vault:

```
FolderVault.exe close
```

---

# Security Notes

FolderVault uses modern cryptographic practices:

- AES-GCM encryption
- PBKDF2 password hashing
- secure key derivation
- Windows DPAPI for local auto-lock support

Important:

- Files remain encrypted when the vault is locked
- Only the correct password can decrypt the vault
- Auto-lock protects files if the user forgets to close the vault

---

# Limitations

This project is currently a **console-based prototype**.

Possible improvements:

- system tray interface
- Windows Service background mode
- file activity monitoring
- inactivity detection
- multi-user support
- stronger tamper protection

---

# Future Improvements

Planned upgrades:

- Tray application UI
- real-time file activity monitoring
- improved vault management
- better background service architecture

---

# License

This project is intended for **educational and personal use**.

Use at your own risk for sensitive data.

---

⭐ If you find this project useful, consider giving it a star.
