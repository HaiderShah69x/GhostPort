# GhostPort - knock_client.ps1
# Version: 3.0 (Milestone 3 - Cryptographic SPA Client)
#
# PURPOSE:
#   Generates a valid HMAC-SHA256 SPA packet and sends it
#   to the GhostPort server for each port in the knock sequence.
#
# USAGE:
#   .\knock_client.ps1
#   .\knock_client.ps1 -ServerIP 192.168.1.10
#   .\knock_client.ps1 -ServerIP 127.0.0.1 -DelayMs 500
#
# MATCHING THE SERVER:
#   The PSK array below MUST exactly match the PSK in main.cpp.
#   The port sequence MUST match KNOCK_SEQUENCE in SequenceValidator.h.

param(
    [Alias("ServerIP")]
    [string] $TargetIP   = "127.0.0.1",
    [int[]]  $KnockPorts = @(7000, 8000, 9000),
    [int]    $DelayMs    = 400
)

# --- Pre-Shared Key ---
# MUST match HmacVerifier::Psk PSK in main.cpp - byte for byte.
$PSK = [byte[]]@(
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22
)

# --- Helper: Compute HMAC-SHA256 ---
# .NET HMACSHA256 uses the same RFC 2104 construction as our C++ HmacVerifier.
function Compute-HmacSha256 {
    param([byte[]] $Key, [byte[]] $Message)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Key
    $result = $hmac.ComputeHash($Message)
    $hmac.Dispose()
    return $result
}

# --- Helper: Write uint32 as big-endian bytes ---
function ToBE32 {
    param([uint32] $v)
    return [byte[]]@(
        [byte](($v -shr 24) -band 0xFF),
        [byte](($v -shr 16) -band 0xFF),
        [byte](($v -shr  8) -band 0xFF),
        [byte]( $v          -band 0xFF)
    )
}

# --- Helper: Write uint16 as big-endian bytes ---
function ToBE16 {
    param([uint16] $v)
    return [byte[]]@(
        [byte](($v -shr 8) -band 0xFF),
        [byte]( $v         -band 0xFF)
    )
}

# --- Build a 42-byte SPA Packet ---
#
#  Wire format:
#    Bytes  0- 3 : Magic 0x47 0x50 0x53 0x41 ("GPSA")
#    Bytes  4- 7 : Timestamp (Unix epoch, big-endian uint32)
#    Bytes  8- 9 : Destination port (big-endian uint16)
#    Bytes 10-41 : HMAC-SHA256 over bytes 0..9
#    Total       : 42 bytes
#
function Build-SpaPacket {
    param([int] $DestPort)

    # Magic header bytes
    $magic = [byte[]](0x47, 0x50, 0x53, 0x41)

    # Timestamp: UTC Unix epoch seconds.
    # IMPORTANT: Use [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - NOT
    # [datetime]::UtcNow minus a "Z"-epoch string. PowerShell's [datetime]
    # cast of "1970-01-01T00:00:00Z" converts to LOCAL time on Windows,
    # causing a skew equal to the local UTC offset (e.g. 18000s for UTC+5).
    # [DateTimeOffset]::UtcNow is timezone-aware and ToUnixTimeSeconds()
    # is guaranteed to match the server's std::time(nullptr) exactly.
    $ts      = [uint32]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $tsBytes = ToBE32 $ts

    # Destination port (big-endian)
    $portBytes = ToBE16 ([uint16]$DestPort)

    # Signed message = magic(4) + timestamp(4) + destPort(2) = 10 bytes
    $signedMsg = $magic + $tsBytes + $portBytes

    # Compute HMAC-SHA256(PSK, signedMsg)
    $hmacBytes = Compute-HmacSha256 -Key $PSK -Message $signedMsg

    # Final packet: signedMsg(10) + HMAC(32) = 42 bytes
    $packet = $signedMsg + $hmacBytes

    return $packet, $ts
}

# --- Main: Send the knock sequence ---
Write-Host ""
Write-Host "  +--------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |  SA // ARCHIVE - GhostPort Cryptographic SPA Client    |" -ForegroundColor Cyan
Write-Host "  |  Milestone 5: Production Dual-Terminal Wrapper Sync    |" -ForegroundColor Cyan
Write-Host "  +--------------------------------------------------------+" -ForegroundColor Cyan
$portsStr = $KnockPorts -join " -> "
Write-Host "  Target: $TargetIP | Ports: $portsStr" -ForegroundColor Cyan
Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

foreach ($port in $KnockPorts) {
    $packet, $ts = Build-SpaPacket -DestPort $port

    # Build hex preview of HMAC (first 16 chars)
    $hmacHex     = ($packet[10..41] | ForEach-Object { "{0:X2}" -f $_ }) -join ""
    $hmacPreview = $hmacHex.Substring(0, 16)

    # Character array rotation loop (animated spinner) for transmission signature alignment
    $spinner = @('|', '/', '-', [char]92)
    for ($i = 0; $i -lt 8; $i++) {
        $char = $spinner[$i % $spinner.Length]
        [Console]::Write([char]13 + "  [$char] Aligning signature & transmitting to port $port...           ")
        Start-Sleep -Milliseconds 50
    }

    # Send UDP datagram
    try {
        $udp  = New-Object System.Net.Sockets.UdpClient
        $sent = $udp.Send($packet, $packet.Length, $TargetIP, $port)
        $udp.Close()
        [Console]::Write([char]13 + "  [+] Sent $sent bytes to ${TargetIP}:$port (ts=$ts, hmac=$hmacPreview...)      `n")
    }
    catch {
        [Console]::Write([char]13 + "  [-] ERROR on port ${port}: " + $_.Message + "`n")
    }

    # Delay between knocks (full sequence must complete within 30-second window)
    if ($port -ne $KnockPorts[-1]) {
        for ($j = 0; $j -lt ($DelayMs / 50); $j++) {
            $char = $spinner[$j % $spinner.Length]
            [Console]::Write([char]13 + "  [$char] Cooling down socket connection...                          ")
            Start-Sleep -Milliseconds 50
        }
        [Console]::Write([char]13 + "                                                                      " + [char]13)
    }
}

Write-Host ""
Write-Host "  [+] Knock sequence fully transmitted! Check GhostPort server status." -ForegroundColor Green
Write-Host ""
