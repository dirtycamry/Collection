$key = "coldpizza"

#$buf = [Byte[]] (0x52, 0xa3, 0x66, 0x1b, 0x62, 0x7a, 0x1c, 0x66, 0xbc, 0x9d, 0x8e, 0x63, 0xa0)

[Byte[]] $buf =  0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3

$encoded = [System.Byte[]]::CreateInstance([System.Byte],$buf.length)

for ($i = 0; $i -lt $buf.length; $i++)
{
    $encoded[$i] = [Byte]($buf[$i] -bxor $key[$i % $key.count]);
}

$sb = [System.Text.StringBuilder]::new($encoded.length *2)
foreach ($b in $encoded)
{
   [void]$sb.AppendFormat('0x{0:x2}, ', $b)
}

$sb.ToString()
