# Windows x64 static runtime reference inputs

Three Windows Server 2022 builds of a small C++ program using
`std::vector<std::string>` produced the same whole-library hashes. The
reference environment was MSVC toolset **14.44.35207**, compiler file version
**19.44.35230.0**, Windows SDK **10.0.26100.0**, targeting **x64**.
The program compiled with `/O2 /MT /EHsc` and executed successfully.

| Library | Bytes | SHA-256 | Distinct object files represented in the fixture's public link map |
|---|---:|---|---:|
| `libcmt.lib` | 6534094 | `8fe40dd342b90b35d62b8f5d55b4e92df7785c122976618365cfe3b014cc857a` | 40 |
| `libcpmt.lib` | 21684758 | `da86944db1497552c378e6252a7177fbefbdaeba4e69a6457de4db7fb2d235de` | 1 |
| `vcruntime.lib` | 285940 | `1acbd98b43a4be8373e25c65dcae4412f36f6111d6b64e47e4a2a97a1d16b27b` | 0 |
| `libvcruntime.lib` | 2087406 | `e4f8daf356d63592ff6d6f7ad90c8c9da4c1230273ad113a9a2b56afd6bfcb04` | 23 |
| `libucrt.lib` | 43370172 | `c3a20426b5142bfd0848468a3b95c47440759f0391ef2764e5020672811803cb` | 132 |

The four Visual C++ libraries are under `VC/Tools/MSVC/14.44.35207/lib/x64`.
The UCRT library is under `Windows Kits/10/Lib/10.0.26100.0/ucrt/x64`.
The linker's search log and public map both identify `libvcruntime.lib`
for this static build. The similarly named `vcruntime.lib` exists in the
same directory. Its members did not appear in the fixture map.

## What the link map establishes

The public-symbol section of this fixture's map has 472 function rows at
440 distinct addresses. Of those addresses, 429 have one public name and 11
have multiple names. Considering the four static CRT libraries in the table,
419 addresses have only CRT owners, 18 have only other owners, and three
have both. These counts use the linker’s function marker and exclude data
symbols. They cover public entries only.

A comparison that counts every map row as a separate function would count
some starts more than once. Assigning each start the first name in the map
would also hide ambiguous cases. Record those cases separately when
reporting name accuracy. Actual false-positive and false-negative rates
still require held-out predictions and ground truth.

## Verify the inputs

With those versions installed, open a command prompt in the Visual Studio
installation directory and select the exact environment:

```bat
call VC\Auxiliary\Build\vcvarsall.bat x64 10.0.26100.0 -vcvars_ver=14.44.35207
powershell -NoProfile
```

In that PowerShell session, print the selected versions and file hashes:

```powershell
$env:VCToolsVersion
$env:WindowsSDKVersion
$env:VSCMD_ARG_TGT_ARCH
(Get-Item (Get-Command cl.exe).Source).VersionInfo.FileVersion
foreach ($name in 'libcmt.lib','libcpmt.lib','vcruntime.lib','libvcruntime.lib','libucrt.lib') {
    $file = $env:LIB -split ';' | Where-Object { $_ } |
        ForEach-Object { Join-Path $_ $name } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if (!$file) { throw "Missing $name" }
    Get-FileHash -Algorithm SHA256 -LiteralPath $file
}
```

The map column counts unique library member names in the public-symbol
section for this source build. Classifier precision and recall require
independent expected names, predictions, and unmatched examples for each
held-out workload. These input hashes identify one reference toolset for
that comparison.

[Fixture source and build procedure](https://github.com/sharifhsn/kuna/tree/af2ae4b555bff739377915476b5801652f2d43f5)
· [Windows build and map](https://github.com/sharifhsn/kuna/actions/runs/45875267182)
· [Explicit version-selection check](https://github.com/sharifhsn/kuna/actions/runs/45881986323)
