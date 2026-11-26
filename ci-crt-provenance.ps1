$ErrorActionPreference = 'Stop'
$roots = $env:LIB -split ';' | Where-Object { $_ }
$files = foreach ($name in 'libcmt.lib','libcpmt.lib','vcruntime.lib','libvcruntime.lib','libucrt.lib') {
    $candidates = @($roots | ForEach-Object { Join-Path $_ $name } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if (!$candidates.Count) { throw "Missing $name" }
    $item = Get-Item -LiteralPath $candidates[0]
    [ordered]@{ name=$name; path=$item.FullName; bytes=$item.Length; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant() }
}
[ordered]@{ architecture=$env:VSCMD_ARG_TGT_ARCH; toolset=$env:VCToolsVersion; sdk=$env:WindowsSDKVersion.TrimEnd('\'); compiler=(Get-Item (Get-Command cl.exe).Source).VersionInfo.FileVersion; libraries=@($files) } | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 provenance.json
