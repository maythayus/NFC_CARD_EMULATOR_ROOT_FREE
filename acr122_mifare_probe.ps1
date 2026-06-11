#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------
# PC/SC (winscard.dll) P/Invoke
# -----------------------------
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WinSCard
{
    public const uint SCARD_SCOPE_USER = 0;
    public const uint SCARD_SCOPE_SYSTEM = 2;

    public const uint SCARD_SHARE_SHARED = 2;

    public const uint SCARD_PROTOCOL_T0 = 1;
    public const uint SCARD_PROTOCOL_T1 = 2;

    public const uint SCARD_LEAVE_CARD = 0;

    public const uint SCARD_S_SUCCESS = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct SCARD_IO_REQUEST
    {
        public uint dwProtocol;
        public uint cbPciLength;
    }

    [DllImport("winscard.dll")]
    public static extern int SCardEstablishContext(
        uint dwScope,
        IntPtr pvReserved1,
        IntPtr pvReserved2,
        out IntPtr phContext
    );

    [DllImport("winscard.dll", CharSet = CharSet.Auto)]
    public static extern int SCardListReaders(
        IntPtr hContext,
        string mszGroups,
        byte[] mszReaders,
        ref int pcchReaders
    );

    [DllImport("winscard.dll", CharSet = CharSet.Auto)]
    public static extern int SCardConnect(
        IntPtr hContext,
        string szReader,
        uint dwShareMode,
        uint dwPreferredProtocols,
        out IntPtr phCard,
        out uint pdwActiveProtocol
    );

    [DllImport("winscard.dll")]
    public static extern int SCardDisconnect(
        IntPtr hCard,
        uint dwDisposition
    );

    [DllImport("winscard.dll")]
    public static extern int SCardReleaseContext(
        IntPtr hContext
    );

    [DllImport("winscard.dll")]
    public static extern int SCardTransmit(
        IntPtr hCard,
        ref SCARD_IO_REQUEST pioSendPci,
        byte[] pbSendBuffer,
        int cbSendLength,
        IntPtr pioRecvPci,
        byte[] pbRecvBuffer,
        ref int pcbRecvLength
    );

    public static string Hex(byte[] data, int len)
    {
        var sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) sb.Append(data[i].ToString("X2"));
        return sb.ToString();
    }

    public static byte[] ParseHex(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\r", "").Replace("\n", "").Trim();
        if (hex.Length % 2 != 0) throw new Exception("Hex length must be even");
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
        {
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return b;
    }
}
"@

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [AllowEmptyString()][string]$Value
    )
    if ($null -eq $Value) { $Value = "" }
    [System.IO.File]::AppendAllText($Path, $Value + [System.Environment]::NewLine, [System.Text.Encoding]::UTF8)
}

function Get-PcscReaders {
    param([IntPtr]$Ctx)

    $len = 0
    $rc = [WinSCard]::SCardListReaders($Ctx, $null, $null, [ref]$len)
    if ($rc -ne 0) { throw "SCardListReaders(len) failed rc=$rc" }

    # $len is number of TCHARs. On Windows with CharSet.Auto, that's typically UTF-16LE (2 bytes per char).
    $buf = New-Object byte[] ($len * 2)
    $rc = [WinSCard]::SCardListReaders($Ctx, $null, $buf, [ref]$len)
    if ($rc -ne 0) { throw "SCardListReaders(buf) failed rc=$rc" }

    $s = [Text.Encoding]::Unicode.GetString($buf, 0, $len * 2)
    $readers = $s.Split([char]0) | Where-Object { $_ -and $_.Trim().Length -gt 0 }
    return $readers
}

function Invoke-Apdu {
    param(
        [IntPtr]$Card,
        [uint32]$Protocol,
        [byte[]]$Apdu,
        [string]$LogPath
    )

    $io = New-Object WinSCard+SCARD_IO_REQUEST
    $io.dwProtocol = $Protocol
    $io.cbPciLength = [Runtime.InteropServices.Marshal]::SizeOf([type]([WinSCard+SCARD_IO_REQUEST]))

    $recv = New-Object byte[] 258
    $recvLen = $recv.Length

    $rc = [WinSCard]::SCardTransmit($Card, [ref]$io, $Apdu, $Apdu.Length, [IntPtr]::Zero, $recv, [ref]$recvLen)
    if ($rc -ne 0) { throw "SCardTransmit failed rc=$rc" }

    $reqHex = [WinSCard]::Hex($Apdu, $Apdu.Length)
    $respHex = [WinSCard]::Hex($recv, $recvLen)

    Write-Log -Path $LogPath -Value ("REQ  {0}" -f $reqHex)
    Write-Log -Path $LogPath -Value ("RESP {0}" -f $respHex)

    if ($recvLen -ge 2) {
        $sw1 = $recv[$recvLen - 2]
        $sw2 = $recv[$recvLen - 1]
        $sw = ("{0:X2}{1:X2}" -f $sw1, $sw2)
        $meaning = Get-Acr122StatusMeaning -Apdu $Apdu -Sw $sw
        if ($meaning) {
            Write-Log -Path $LogPath -Value ("NOTE {0}" -f $meaning)
        }
    }

    Write-Log -Path $LogPath -Value ""

    return ,@($recv, $recvLen)
}

function Get-Acr122StatusMeaning {
    param(
        [Parameter(Mandatory=$true)][byte[]]$Apdu,
        [Parameter(Mandatory=$true)][string]$Sw
    )

    # Generic
    switch ($Sw) {
        "9000" { return $null }
        "6300" { return "SW=6300 (FAIL). On ACR122U this commonly indicates MIFARE Classic Crypto-1 authentication failed (wrong key / wrong sector / card removed)." }
        "6982" { return "SW=6982 (SECURITY STATUS NOT SATISFIED). Often means not authenticated for this block/sector." }
        "6A82" { return "SW=6A82 (FILE/OBJECT NOT FOUND). For ACR122U commands this can indicate invalid block/address." }
        "6700" { return "SW=6700 (WRONG LENGTH)." }
        default { }
    }

    # ACR122U specific hints based on CLA/INS
    if ($Apdu.Length -ge 2) {
        $cla = $Apdu[0]
        $ins = $Apdu[1]
        if ($cla -eq 0xFF) {
            if ($ins -eq 0x86 -and $Sw -ne "9000") {
                return "AUTH (FF86) failed: likely Crypto-1 auth failure (wrong Key A/B for that sector) or card moved. SW=$Sw"
            }
            if ($ins -eq 0xB0 -and ($Sw -eq "6982" -or $Sw -eq "6300")) {
                return "READ (FFB0) failed: you are not authenticated for this block (need successful Crypto-1 auth first). SW=$Sw"
            }
        }
    }

    return $null
}

function New-MifareAuthApdu {
    param(
        [ValidateSet("A","B")]$KeyType,
        [int]$Block,
        [byte[]]$Key6,
        [byte[]]$Uid4
    )
    if ($Key6.Length -ne 6) { throw "Key must be 6 bytes" }
    if ($Uid4.Length -lt 4) { throw "UID must be at least 4 bytes" }

    # ACR122U AUTH: FF 86 00 00 05  01 00 <block> <keyType> 00
    # where keyType: 0x60=KeyA, 0x61=KeyB
    $kt = if ($KeyType -eq "A") { 0x60 } else { 0x61 }

    # Load key into volatile reader memory: FF 82 00 00 06 <6 bytes>
    $loadKey = @(0xFF,0x82,0x00,0x00,0x06) + $Key6
    $auth = @(
        0xFF,0x86,0x00,0x00,0x05,
        0x01,0x00,($Block -band 0xFF),$kt,0x00
    )
    return ,@([byte[]]$loadKey, [byte[]]$auth)
}

function New-MifareReadBlockApdu {
    param([int]$Block)
    # Read Binary: FF B0 00 <block> 10
    return [byte[]]@(0xFF,0xB0,0x00,($Block -band 0xFF),0x10)
}

# -----------------------------
# Main
# -----------------------------
$log = Join-Path $PSScriptRoot ("acr122_probe_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
"Log: $log" | Out-Host

[System.IO.File]::WriteAllText($log, "", [System.Text.Encoding]::UTF8)

$ctx = [IntPtr]::Zero
$card = [IntPtr]::Zero

$rc = [WinSCard]::SCardEstablishContext([WinSCard]::SCARD_SCOPE_SYSTEM, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ctx)
if ($rc -ne 0) { throw "SCardEstablishContext failed rc=$rc" }

try {
    $readers = @(Get-PcscReaders -Ctx $ctx)
    if ($readers.Length -eq 0) { throw "No PC/SC readers found" }

    "Readers:" | Out-Host
    $readers | ForEach-Object { " - $_" | Out-Host }

    # auto-pick ACR122U if present, else first
    $reader = ($readers | Where-Object { $_ -match "ACR122" } | Select-Object -First 1)
    if (-not $reader) { $reader = $readers[0] }

    "Using reader: $reader" | Out-Host

    $activeProto = 0
    $rc = [WinSCard]::SCardConnect(
        $ctx,
        $reader,
        [WinSCard]::SCARD_SHARE_SHARED,
        ([WinSCard]::SCARD_PROTOCOL_T0 -bor [WinSCard]::SCARD_PROTOCOL_T1),
        [ref]$card,
        [ref]$activeProto
    )
    if ($rc -ne 0) { throw "SCardConnect failed rc=$rc" }

    Write-Log -Path $log -Value ("Reader: {0}" -f $reader)
    Write-Log -Path $log -Value ("Protocol: {0}" -f $activeProto)
    Write-Log -Path $log -Value ""

    # 1) Get UID
    $getUid = [byte[]]@(0xFF,0xCA,0x00,0x00,0x00)
    $resp = Invoke-Apdu -Card $card -Protocol $activeProto -Apdu $getUid -LogPath $log
    $rb = $resp[0]; $rlen = $resp[1]

    if ($rlen -lt 2) { throw "UID response too short" }
    $sw1 = $rb[$rlen-2]; $sw2 = $rb[$rlen-1]
    if ($sw1 -ne 0x90 -or $sw2 -ne 0x00) {
        throw ("GET UID failed SW={0:X2}{1:X2}" -f $sw1,$sw2)
    }
    $uid = $rb[0..($rlen-3)]
    "UID: $([WinSCard]::Hex($uid, $uid.Length))" | Out-Host

    # 2) OPTIONAL: try read a few blocks with common keys (EDIT THESE!)
    # Default key A often used: FFFFFFFFFFFF
    $keyA = [WinSCard]::ParseHex("FF FF FF FF FF FF")
    $uid4 = $uid[0..3]

    # Try blocks 4..7 (sector 1) as demo
    foreach ($block in 4..7) {
        $pair = New-MifareAuthApdu -KeyType "A" -Block $block -Key6 $keyA -Uid4 $uid4
        $loadKeyApdu = $pair[0]
        $authApdu = $pair[1]
        [void](Invoke-Apdu -Card $card -Protocol $activeProto -Apdu $loadKeyApdu -LogPath $log)
        $a = Invoke-Apdu -Card $card -Protocol $activeProto -Apdu $authApdu -LogPath $log

        $ab = $a[0]; $alen = $a[1]
        $asw1 = $ab[$alen-2]; $asw2 = $ab[$alen-1]
        if ($asw1 -ne 0x90 -or $asw2 -ne 0x00) {
            "AUTH block $block failed (SW=$('{0:X2}{1:X2}' -f $asw1,$asw2))" | Out-Host
            continue
        }

        $readApdu = New-MifareReadBlockApdu -Block $block
        $r = Invoke-Apdu -Card $card -Protocol $activeProto -Apdu $readApdu -LogPath $log
        $bb = $r[0]; $blen = $r[1]
        $rsw1 = $bb[$blen-2]; $rsw2 = $bb[$blen-1]
        if ($rsw1 -eq 0x90 -and $rsw2 -eq 0x00) {
            $data = $bb[0..($blen-3)]
            ("BLOCK {0}: {1}" -f ${block}, ([WinSCard]::Hex($data, $data.Length))) | Out-Host
        } else {
            ("READ block {0} failed (SW={1})" -f ${block}, ("{0:X2}{1:X2}" -f $rsw1, $rsw2)) | Out-Host
        }
    }

    "Done. Log written to $log" | Out-Host
}
finally {
    if ($card -ne [IntPtr]::Zero) { [void][WinSCard]::SCardDisconnect($card, [WinSCard]::SCARD_LEAVE_CARD) }
    if ($ctx -ne [IntPtr]::Zero) { [void][WinSCard]::SCardReleaseContext($ctx) }
}