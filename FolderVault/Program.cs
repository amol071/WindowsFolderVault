using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Win32;

namespace FolderVault;

internal static class Program
{
    private const int SaltSize = 16;
    private const int Iterations = 200_000;
    private const int KeySize = 32;
    private const int AesNonceSize = 12;
    private const int AesTagSize = 16;
    private const string ConfigFileName = "vault.config.json";
    private const string EncryptedFileName = "vault.bin";
    private const string OpenFolderName = "Open";
    private const string AutoLockMarkerFileName = ".vault_open";
    private static readonly TimeSpan DefaultAutoLock = TimeSpan.FromMinutes(5);

    private static string AppRoot => AppContext.BaseDirectory;
    private static string ConfigPath => Path.Combine(AppRoot, ConfigFileName);

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                PrintHelp();
                return 0;
            }

            var command = args[0].Trim().ToLowerInvariant();
            switch (command)
            {
                case "init":
                    InitVault();
                    break;
                case "open":
                    OpenVault();
                    break;
                case "close":
                    CloseVault();
                    break;
                case "status":
                    ShowStatus();
                    break;
                case "startup-on":
                    RegisterStartup();
                    break;
                case "startup-off":
                    UnregisterStartup();
                    break;
                case "background":
                    RunBackground();
                    break;
                case "set-autolock":
                    SetAutoLockMinutes(args);
                    break;
                default:
                    PrintHelp();
                    break;
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static void InitVault()
    {
        if (File.Exists(ConfigPath))
        {
            Console.WriteLine("Vault is already initialized.");
            return;
        }

        Console.Write("Vault folder path: ");
        var vaultFolder = Console.ReadLine()?.Trim('"', ' ') ?? string.Empty;
        if (string.IsNullOrWhiteSpace(vaultFolder))
            throw new InvalidOperationException("Vault path is required.");

        Directory.CreateDirectory(vaultFolder);
        var openFolder = GetOpenFolder(vaultFolder);
        Directory.CreateDirectory(openFolder);

        var password = ReadPassword("Set password: ");
        var confirm = ReadPassword("Confirm password: ");
        if (!password.SequenceEqual(confirm))
            throw new InvalidOperationException("Passwords do not match.");

        var passwordSalt = RandomNumberGenerator.GetBytes(SaltSize);
        var passwordHash = HashPassword(password, passwordSalt);

        var vaultKey = RandomNumberGenerator.GetBytes(KeySize);
        var encryptedVaultKey = ProtectVaultKeyWithPassword(vaultKey, password);
        var autoLockProtectedVaultKey = ProtectedData.Protect(vaultKey, null, DataProtectionScope.CurrentUser);
        CryptographicOperations.ZeroMemory(vaultKey);

        var config = new VaultConfig
        {
            VaultFolder = vaultFolder,
            PasswordSalt = Convert.ToBase64String(passwordSalt),
            PasswordHash = Convert.ToBase64String(passwordHash),
            EncryptedVaultKey = Convert.ToBase64String(encryptedVaultKey),
            AutoLockProtectedVaultKey = Convert.ToBase64String(autoLockProtectedVaultKey),
            IsOpen = true,
            LastOpenedUtc = DateTime.UtcNow,
            AutoLockMinutes = (int)DefaultAutoLock.TotalMinutes
        };

        SaveConfig(config);
        UpdateOpenMarker(config);
        Console.WriteLine("Vault initialized.");
        Console.WriteLine($"Place files inside: {openFolder}");
        Console.WriteLine("Then run 'close' to encrypt and lock the folder.");
        Console.WriteLine($"Auto-lock is enabled for {config.AutoLockMinutes} minutes.");
    }

    private static void OpenVault()
    {
        var config = LoadConfig();
        if (config.IsOpen)
        {
            Console.WriteLine("Vault is already open.");
            return;
        }

        var password = ReadPassword("Password: ");
        VerifyPassword(config, password);
        var vaultKey = UnprotectVaultKeyWithPassword(config, password);

        try
        {
            var encryptedPath = Path.Combine(config.VaultFolder, EncryptedFileName);
            var openFolder = GetOpenFolder(config.VaultFolder);
            Directory.CreateDirectory(openFolder);

            if (!File.Exists(encryptedPath))
            {
                Console.WriteLine("Nothing to open yet. The vault is empty.");
            }
            else
            {
                var tempZip = Path.Combine(Path.GetTempPath(), $"vault_{Guid.NewGuid():N}.zip");
                try
                {
                    DecryptFile(encryptedPath, tempZip, vaultKey);
                    if (Directory.Exists(openFolder))
                        Directory.Delete(openFolder, true);
                    Directory.CreateDirectory(openFolder);
                    System.IO.Compression.ZipFile.ExtractToDirectory(tempZip, openFolder, overwriteFiles: true);
                }
                finally
                {
                    if (File.Exists(tempZip)) File.Delete(tempZip);
                }
            }

            config.IsOpen = true;
            config.LastOpenedUtc = DateTime.UtcNow;
            SaveConfig(config);
            UpdateOpenMarker(config);
            Console.WriteLine($"Vault opened at: {openFolder}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    private static void CloseVault()
    {
        var config = LoadConfig();
        if (!config.IsOpen)
        {
            Console.WriteLine("Vault is already closed.");
            return;
        }

        var password = ReadPassword("Password: ");
        VerifyPassword(config, password);
        var vaultKey = UnprotectVaultKeyWithPassword(config, password);

        try
        {
            CloseVaultInternal(config, vaultKey, announce: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    private static void CloseVaultInternal(VaultConfig config, byte[] vaultKey, bool announce)
    {
        var openFolder = GetOpenFolder(config.VaultFolder);
        var encryptedPath = Path.Combine(config.VaultFolder, EncryptedFileName);
        var tempZip = Path.Combine(Path.GetTempPath(), $"vault_{Guid.NewGuid():N}.zip");

        try
        {
            if (File.Exists(tempZip)) File.Delete(tempZip);
            if (Directory.Exists(openFolder))
            {
                if (File.Exists(encryptedPath)) File.Delete(encryptedPath);
                System.IO.Compression.ZipFile.CreateFromDirectory(openFolder, tempZip, System.IO.Compression.CompressionLevel.Optimal, includeBaseDirectory: false);
                EncryptFile(tempZip, encryptedPath, vaultKey);
                Directory.Delete(openFolder, true);
            }
        }
        finally
        {
            if (File.Exists(tempZip)) File.Delete(tempZip);
        }

        config.IsOpen = false;
        SaveConfig(config);
        DeleteOpenMarker(config);

        if (announce)
            Console.WriteLine("Vault closed and encrypted.");
    }

    private static void ShowStatus()
    {
        var config = LoadConfig();
        Console.WriteLine($"Vault folder: {config.VaultFolder}");
        Console.WriteLine($"State: {(config.IsOpen ? "Open" : "Closed")}");
        Console.WriteLine($"Last opened (UTC): {config.LastOpenedUtc:O}");
        Console.WriteLine($"Auto-lock (minutes): {config.AutoLockMinutes}");
    }

    private static void RegisterStartup()
    {
        var exePath = Process.GetCurrentProcess().MainModule?.FileName
                      ?? throw new InvalidOperationException("Cannot determine executable path.");

        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true)
                        ?? throw new InvalidOperationException("Startup registry key could not be opened.");

        key.SetValue("FolderVault", $"\"{exePath}\" background");
        Console.WriteLine("Startup enabled for current user.");
    }

    private static void UnregisterStartup()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true)
                        ?? throw new InvalidOperationException("Startup registry key could not be opened.");

        key.DeleteValue("FolderVault", false);
        Console.WriteLine("Startup disabled.");
    }

    private static void RunBackground()
    {
        var config = LoadConfig();
        var openMarker = GetOpenMarkerPath(config.VaultFolder);

        if (!config.IsOpen || !File.Exists(openMarker))
        {
            Console.WriteLine("Background mode running. Vault is already closed.");
            return;
        }

        Console.WriteLine("Background mode started. Auto-lock monitor is active.");

        while (true)
        {
            try
            {
                config = LoadConfig();
                if (!config.IsOpen || !File.Exists(openMarker))
                {
                    Console.WriteLine("Vault already closed.");
                    return;
                }

                var lastTouchUtc = File.GetLastWriteTimeUtc(openMarker);
                var autoLockAt = lastTouchUtc.AddMinutes(config.AutoLockMinutes <= 0 ? 1 : config.AutoLockMinutes);

                if (DateTime.UtcNow >= autoLockAt)
                {
                    var protectedVaultKey = Convert.FromBase64String(config.AutoLockProtectedVaultKey);
                    var vaultKey = ProtectedData.Unprotect(protectedVaultKey, null, DataProtectionScope.CurrentUser);
                    try
                    {
                        CloseVaultInternal(config, vaultKey, announce: false);
                        Console.WriteLine($"Vault auto-locked at {DateTime.Now:G}.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(vaultKey);
                    }

                    return;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Background warning: {ex.Message}");
            }

            Thread.Sleep(TimeSpan.FromSeconds(10));
        }
    }

    private static void SetAutoLockMinutes(string[] args)
    {
        if (args.Length < 2 || !int.TryParse(args[1], out var minutes) || minutes <= 0)
            throw new InvalidOperationException("Usage: set-autolock <minutes>");

        var config = LoadConfig();
        config.AutoLockMinutes = minutes;
        SaveConfig(config);
        Console.WriteLine($"Auto-lock set to {minutes} minute(s).");

        if (config.IsOpen)
            UpdateOpenMarker(config);
    }

    private static void VerifyPassword(VaultConfig config, byte[] password)
    {
        var salt = Convert.FromBase64String(config.PasswordSalt);
        var expectedHash = Convert.FromBase64String(config.PasswordHash);
        var actualHash = HashPassword(password, salt);

        if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
            throw new UnauthorizedAccessException("Invalid password.");
    }

    private static byte[] HashPassword(byte[] password, byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        return kdf.GetBytes(KeySize);
    }

    private static byte[] ProtectVaultKeyWithPassword(byte[] vaultKey, byte[] password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
        using var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var wrappingKey = kdf.GetBytes(KeySize);
        var ciphertext = new byte[vaultKey.Length];
        var tag = new byte[AesTagSize];

        using var aes = new AesGcm(wrappingKey, AesTagSize);
        aes.Encrypt(nonce, vaultKey, ciphertext, tag);

        var result = new byte[SaltSize + AesNonceSize + AesTagSize + ciphertext.Length];
        Buffer.BlockCopy(salt, 0, result, 0, SaltSize);
        Buffer.BlockCopy(nonce, 0, result, SaltSize, AesNonceSize);
        Buffer.BlockCopy(tag, 0, result, SaltSize + AesNonceSize, AesTagSize);
        Buffer.BlockCopy(ciphertext, 0, result, SaltSize + AesNonceSize + AesTagSize, ciphertext.Length);

        CryptographicOperations.ZeroMemory(wrappingKey);
        return result;
    }

    private static byte[] UnprotectVaultKeyWithPassword(VaultConfig config, byte[] password)
    {
        var wrapped = Convert.FromBase64String(config.EncryptedVaultKey);
        var salt = wrapped[..SaltSize];
        var nonce = wrapped[SaltSize..(SaltSize + AesNonceSize)];
        var tag = wrapped[(SaltSize + AesNonceSize)..(SaltSize + AesNonceSize + AesTagSize)];
        var ciphertext = wrapped[(SaltSize + AesNonceSize + AesTagSize)..];

        using var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var wrappingKey = kdf.GetBytes(KeySize);
        var vaultKey = new byte[ciphertext.Length];

        using var aes = new AesGcm(wrappingKey, AesTagSize);
        aes.Decrypt(nonce, ciphertext, tag, vaultKey);
        CryptographicOperations.ZeroMemory(wrappingKey);
        return vaultKey;
    }

    private static void EncryptFile(string inputPath, string outputPath, byte[] vaultKey)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
        var plaintext = File.ReadAllBytes(inputPath);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesTagSize];

        using var aes = new AesGcm(vaultKey, AesTagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
        fs.Write(nonce);
        fs.Write(tag);
        fs.Write(ciphertext);
    }

    private static void DecryptFile(string inputPath, string outputPath, byte[] vaultKey)
    {
        var allBytes = File.ReadAllBytes(inputPath);
        var nonce = allBytes[..AesNonceSize];
        var tag = allBytes[AesNonceSize..(AesNonceSize + AesTagSize)];
        var ciphertext = allBytes[(AesNonceSize + AesTagSize)..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(vaultKey, AesTagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        File.WriteAllBytes(outputPath, plaintext);
    }

    private static byte[] ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var bytes = new System.Collections.Generic.List<byte>();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (bytes.Count > 0)
                {
                    bytes.RemoveAt(bytes.Count - 1);
                    Console.Write("\b \b");
                }
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                bytes.Add((byte)key.KeyChar);
                Console.Write('*');
            }
        }

        return bytes.ToArray();
    }

    private static VaultConfig LoadConfig()
    {
        if (!File.Exists(ConfigPath))
            throw new FileNotFoundException("Vault is not initialized.");

        var json = File.ReadAllText(ConfigPath, Encoding.UTF8);
        var config = JsonSerializer.Deserialize<VaultConfig>(json)
                     ?? throw new InvalidDataException("Invalid config file.");

        if (string.IsNullOrWhiteSpace(config.VaultFolder) ||
            string.IsNullOrWhiteSpace(config.PasswordSalt) ||
            string.IsNullOrWhiteSpace(config.PasswordHash) ||
            string.IsNullOrWhiteSpace(config.EncryptedVaultKey) ||
            string.IsNullOrWhiteSpace(config.AutoLockProtectedVaultKey))
        {
            throw new InvalidDataException("Invalid config file.");
        }

        if (config.AutoLockMinutes <= 0)
            config.AutoLockMinutes = (int)DefaultAutoLock.TotalMinutes;

        return config;
    }

    private static void SaveConfig(VaultConfig config)
    {
        var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(ConfigPath, json, Encoding.UTF8);
    }

    private static string GetOpenFolder(string vaultFolder) => Path.Combine(vaultFolder, OpenFolderName);

    private static string GetOpenMarkerPath(string vaultFolder) => Path.Combine(vaultFolder, AutoLockMarkerFileName);

    private static void UpdateOpenMarker(VaultConfig config)
    {
        var markerPath = GetOpenMarkerPath(config.VaultFolder);
        File.WriteAllText(markerPath, DateTime.UtcNow.ToString("O"), Encoding.UTF8);
        File.SetLastWriteTimeUtc(markerPath, DateTime.UtcNow);
    }

    private static void DeleteOpenMarker(VaultConfig config)
    {
        var markerPath = GetOpenMarkerPath(config.VaultFolder);
        if (File.Exists(markerPath))
            File.Delete(markerPath);
    }

    private static void PrintHelp()
    {
        Console.WriteLine("FolderVault commands:");
        Console.WriteLine("  init                 Initialize a new vault folder");
        Console.WriteLine("  open                 Decrypt and open the vault");
        Console.WriteLine("  close                Encrypt and close the vault");
        Console.WriteLine("  status               Show vault status");
        Console.WriteLine("  set-autolock <min>   Set auto-lock time in minutes");
        Console.WriteLine("  startup-on           Start app with Windows for current user");
        Console.WriteLine("  startup-off          Remove startup entry");
        Console.WriteLine("  background           Monitor and auto-lock the vault");
    }

    private sealed class VaultConfig
    {
        public string VaultFolder { get; set; } = string.Empty;
        public string PasswordSalt { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string EncryptedVaultKey { get; set; } = string.Empty;
        public string AutoLockProtectedVaultKey { get; set; } = string.Empty;
        public bool IsOpen { get; set; }
        public DateTime LastOpenedUtc { get; set; }
        public int AutoLockMinutes { get; set; }
    }
}
