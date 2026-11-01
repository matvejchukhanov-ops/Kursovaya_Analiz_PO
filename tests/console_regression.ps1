# Regression test of the ExeIAS console program. Windows PowerShell 5.1, no external modules.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\console_regression.ps1
# Exit code = number of FAIL checks. Everything the run produces stays in $env:TEMP\ExeIAS_regress_<time>.
#
# SAFETY: Whiter.a.rar holds real destructive malware. It is only passed by path to ExeIAS.exe (which reads
# it into memory) or streamed through a cmd.exe pipe. Nothing here extracts it to disk or executes it,
# and sample_*.exe are only analyzed. This file must stay in UTF-8 with BOM: PowerShell 5.1 reads it as ANSI otherwise.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

if ('Балл'.Length -ne 4) { throw 'console_regression.ps1 must be saved as UTF-8 with BOM' }
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false) } catch { }

$script:root    = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:started = Get-Date
$script:runDir  = Join-Path $env:TEMP ('ExeIAS_regress_' + $script:started.ToString('yyyyMMdd_HHmmss'))
$null = New-Item -ItemType Directory -Force -Path $script:runDir
$script:logFile = Join-Path $script:runDir 'results.log'
$script:counts  = @{ PASS = 0; FAIL = 0; SKIP = 0 }
$script:fails   = New-Object Collections.Generic.List[string]
$script:exe64   = $null
$script:exe86   = $null
$script:reports = @{}    # label -> x64 report path

$vcDir         = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build'
$rar           = 'C:\Users\matve\OneDrive\Desktop\INF\Whiter.a.rar'
$samples       = 'C:\Claude pr\pr7\samples'
$xcopy         = 'C:\Windows\SysWOW64\xcopy.exe'
$notepad       = 'C:\Windows\System32\notepad.exe'
$tar           = 'C:\Windows\System32\tar.exe'
$whiterSha256  = 'fe974c995cfb27e8c91123081986847f6d3d4252b6a8d1e1385c558f2aeb7057'   # from README.md

$expected = @(
    @{ Path = $rar;                                Report = 'Whiter.a.exe';       Score = 100; Level = 'CRITICAL' }
    @{ Path = "$samples\sample_dropper.exe";       Report = 'sample_dropper.exe'; Score = 97;  Level = 'CRITICAL' }
    @{ Path = 'C:\Windows\System32\cmd.exe';       Report = 'cmd.exe';            Score = 53;  Level = 'HIGH' }
    @{ Path = $notepad;                            Report = 'notepad.exe';        Score = 32;  Level = 'HIGH' }
    @{ Path = 'C:\netcoreapp3.1\ConsoleApp28.exe'; Report = 'ConsoleApp28.exe';   Score = 20;  Level = 'MEDIUM' }
    @{ Path = "$samples\sample_dotnet.exe";        Report = 'sample_dotnet.exe';  Score = 16;  Level = 'MEDIUM' }
    @{ Path = "$samples\sample_clean.exe";         Report = 'sample_clean.exe';   Score = 10;  Level = 'MEDIUM' }
    @{ Path = $xcopy;                              Report = 'xcopy.exe';          Score = 2;   Level = 'LOW' }
)

# A crash must fail the check, not open a Windows error dialog (the mode is inherited by child processes)
try {
    Add-Type -Namespace ExeIasTest -Name Native -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode);'
    $null = [ExeIasTest.Native]::SetErrorMode(0x8003)
} catch { }

# ---------------------------------------------------------------- output

function Write-Line([string]$text) {
    [Console]::Out.WriteLine($text)
    [IO.File]::AppendAllText($script:logFile, $text + "`r`n", (New-Object Text.UTF8Encoding($false)))
}

function Add-Result([string]$status, [string]$name, [string]$reason) {
    $script:counts[$status]++
    $line = '[{0}] {1} -- {2}' -f $status, $name, $reason
    if ($status -eq 'FAIL') { $script:fails.Add($line) }
    Write-Line $line
}

function Test-That([bool]$ok, [string]$name, [string]$good, [string]$bad) {
    if ($ok) { Add-Result 'PASS' $name $good } else { Add-Result 'FAIL' $name $bad }
}

function Invoke-Section([string]$title, [scriptblock]$body) {
    Write-Line ''
    Write-Line "=== $title"
    try { & $body }
    catch { Add-Result 'FAIL' $title ("section aborted by an exception: " + $_.Exception.Message + " (line " + $_.InvocationInfo.ScriptLineNumber + ")") }
}

# ---------------------------------------------------------------- running programs

function ConvertTo-Arg([string]$a) {
    $s = [regex]::Replace($a, '(\\*)"', '$1$1\"')
    $s = [regex]::Replace($s, '(\\+)$', '$1$1')
    return '"' + $s + '"'
}

function Invoke-Proc([string]$file, [string]$arguments, [string]$cwd, [int]$timeoutSec = 180) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $file
    $psi.Arguments = $arguments
    $psi.WorkingDirectory = $cwd
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $psi.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $timedOut = -not $p.WaitForExit($timeoutSec * 1000)
    if ($timedOut) { try { $p.Kill() } catch { }; $null = $p.WaitForExit(5000) }
    $null = $outTask.Wait(5000); $null = $errTask.Wait(5000)
    return [pscustomobject]@{
        Exit = $(if ($timedOut) { -999 } else { $p.ExitCode })
        TimedOut = $timedOut
        Out = $(if ($outTask.IsCompleted) { $outTask.Result } else { '' })
        Err = $(if ($errTask.IsCompleted) { $errTask.Result } else { '' })
        Dir = $cwd
    }
}

function New-RunDir([string]$name) {
    $d = Join-Path $script:runDir $name
    $null = New-Item -ItemType Directory -Force -Path $d
    return $d
}

# Runs ExeIAS.exe in its own working directory: reports land there
function Invoke-Ias([string]$label, [string[]]$arguments, [string]$exe = $script:exe64) {
    $dir = New-RunDir $label
    return Invoke-Proc $exe ((@($arguments) | ForEach-Object { ConvertTo-Arg $_ }) -join ' ') $dir
}

function Get-Short([string]$text) {
    $t = ($text -replace '\s+', ' ').Trim()
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }
    return $t
}

function Get-ExitInfo($r) {
    $hex = '0x{0:X8}' -f $r.Exit
    return "exit=$($r.Exit) ($hex), timedOut=$($r.TimedOut), stdout: $(Get-Short $r.Out)"
}

# ---------------------------------------------------------------- report helpers

function Read-Report([string]$path) {
    return [IO.File]::ReadAllText($path, (New-Object Text.UTF8Encoding($false))).TrimStart([char]0xFEFF)
}

function Get-Field([string]$text, [string]$pattern) {
    $m = [regex]::Match($text, $pattern, [Text.RegularExpressions.RegexOptions]::Multiline)
    if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

function Get-Score([string]$text) { return Get-Field $text '^Балл риска:\s+(\d+) / 100' }
function Get-Level([string]$text) { return Get-Field $text '^Общий уровень риска:\s+(\S+)' }

# First difference of two files as text for the FAIL message; $null when byte-identical
function Compare-Files([string]$a, [string]$b) {
    $x = [IO.File]::ReadAllBytes($a); $y = [IO.File]::ReadAllBytes($b)
    $same = $x.Length -eq $y.Length
    if ($same) { for ($i = 0; $i -lt $x.Length; $i++) { if ($x[$i] -ne $y[$i]) { $same = $false; break } } }
    if ($same) { return $null }
    $la = (Read-Report $a) -split "`n"; $lb = (Read-Report $b) -split "`n"
    for ($i = 0; $i -lt [Math]::Max($la.Length, $lb.Length); $i++) {
        $p = $(if ($i -lt $la.Length) { $la[$i] } else { '<end of file>' })
        $q = $(if ($i -lt $lb.Length) { $lb[$i] } else { '<end of file>' })
        if ($p -cne $q) { return "sizes $($x.Length)/$($y.Length) bytes; first difference at line $($i + 1): [$p] vs [$q]" }
    }
    return "sizes $($x.Length)/$($y.Length) bytes; line text identical, bytes differ"
}

function Split-CsvLine([string]$line) {
    $fields = New-Object Collections.Generic.List[string]
    $sb = New-Object Text.StringBuilder
    $quoted = $false
    for ($i = 0; $i -lt $line.Length; $i++) {
        $c = $line[$i]
        if ($quoted) {
            if ($c -eq [char]'"') {
                if ($i + 1 -lt $line.Length -and $line[$i + 1] -eq [char]'"') { $null = $sb.Append('"'); $i++ }
                else { $quoted = $false }
            }
            else { $null = $sb.Append($c) }
        }
        elseif ($c -eq [char]'"') { $quoted = $true }
        elseif ($c -eq [char]';') { $fields.Add($sb.ToString()); $null = $sb.Clear() }
        else { $null = $sb.Append($c) }
    }
    $fields.Add($sb.ToString())
    return ,$fields.ToArray()
}

function Write-Utf8([string]$path, [string[]]$lines) {
    [IO.File]::WriteAllText($path, (($lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}

function New-Zip([string]$path, [string[]]$entryNames, [byte[]]$content) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($n in $entryNames) {
            $s = $zip.CreateEntry($n).Open()
            try { $s.Write($content, 0, $content.Length) } finally { $s.Close() }
        }
    } finally { $zip.Dispose() }
}

# ---------------------------------------------------------------- 1. build

function Build-Exe([string]$arch, [string]$vcvars, [int]$machine) {
    $out = New-RunDir "build_$arch"
    $bat = Join-Path $out 'build.cmd'
    Set-Content -LiteralPath $bat -Encoding Ascii -Value @(
        '@echo off'
        'set VSLANG=1033'
        "call `"$vcDir\$vcvars`" >nul"
        "cd /d `"$out`""
        "cl /nologo /utf-8 /EHsc /O2 /W3 /sdl /permissive- /std:c++20 `"$($script:root)\ExeIAS\*.cpp`" /Fe:ExeIAS.exe"
        'exit /b %ERRORLEVEL%'
    )
    $r = Invoke-Proc 'cmd.exe' ('/c "' + (ConvertTo-Arg $bat) + '"') $out 900
    $log = $r.Out + $r.Err
    [IO.File]::WriteAllText((Join-Path $out 'build.log'), $log)
    $exe = Join-Path $out 'ExeIAS.exe'
    $built = $r.Exit -eq 0 -and (Test-Path -LiteralPath $exe)
    $errors = ([regex]::Matches($log, '(?m)^.*\berror\b.*$') | Select-Object -First 5 | ForEach-Object { $_.Value.Trim() }) -join ' | '
    Test-That $built "build $arch" "cl exit 0: $exe" "cl exit=$($r.Exit), timedOut=$($r.TimedOut): $errors (see $out\build.log)"
    if (-not $built) { return $null }

    $warnings = [regex]::Matches($log, 'warning C\d+').Count
    Write-Line "       INFO: $arch build printed $warnings /W3 warning(s)"
    $b = [IO.File]::ReadAllBytes($exe)
    $actual = [BitConverter]::ToUInt16($b, [BitConverter]::ToInt32($b, 0x3C) + 4)
    Test-That ($actual -eq $machine) "build $arch machine type" ('PE machine 0x{0:X4}' -f $actual) ('PE machine 0x{0:X4}, expected 0x{1:X4}' -f $actual, $machine)
    return $exe
}

Write-Line "ExeIAS console regression, project $($script:root)"
Write-Line "Run directory: $($script:runDir)"

Invoke-Section '1. Build' {
    $script:exe64 = Build-Exe 'x64' 'vcvars64.bat' 0x8664
    $script:exe86 = Build-Exe 'x86' 'vcvars32.bat' 0x014C
}

if (-not $script:exe64) {
    Add-Result 'SKIP' 'all run-time checks' 'the x64 console exe was not built'
}
else {

# ---------------------------------------------------------------- 2. expected scores

Invoke-Section '2. Expected scores' {
    foreach ($e in $expected) {
        $name = 'score ' + $e.Report
        if (-not (Test-Path -LiteralPath $e.Path)) { Add-Result 'SKIP' $name "file is missing: $($e.Path)"; continue }
        $r = Invoke-Ias ('score_' + $e.Report) @($e.Path)
        $report = Join-Path $r.Dir ('report_' + $e.Report + '.txt')
        if ($r.Exit -ne 0 -or -not (Test-Path -LiteralPath $report)) {
            Add-Result 'FAIL' $name ("expected a report; " + (Get-ExitInfo $r)); continue
        }
        $script:reports[$e.Report] = $report
        $t = Read-Report $report
        $s = Get-Score $t; $l = Get-Level $t
        Test-That ("$s" -eq "$($e.Score)" -and $l -ceq $e.Level) $name "$s $l" "actual $s $l, expected $($e.Score) $($e.Level)"
    }
}

Invoke-Section '2b. Whiter.a report content' {
    if (-not $script:reports.ContainsKey('Whiter.a.exe')) { Add-Result 'SKIP' 'Whiter content' 'no Whiter report (archive missing or analysis failed)'; return }
    $path = $script:reports['Whiter.a.exe']
    $b = [IO.File]::ReadAllBytes($path)
    Test-That ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) 'Whiter report BOM' 'starts with the UTF-8 BOM' 'no UTF-8 BOM at the start'
    $t = Read-Report $path

    $chains = Get-Field $t '^4\.4 Цепочки поведения \((\d+)\)'
    Test-That ($chains -eq '12') 'Whiter behaviour chains' '12' "actual [$chains], expected 12"

    $damage = Get-Field $t '^(Ущерб за один инцидент:.*)$'
    Test-That ($null -ne $damage -and $damage.Contains('1 228 000')) 'Whiter damage line' "$damage" "actual [$damage], expected to contain 1 228 000"

    $language = Get-Field $t '^Язык:\s+(.*)$'
    Test-That ($null -ne $language -and $language -cmatch '^C(\s+\(|\s*$)') 'Whiter language' "$language" "actual [$language], expected C"

    $sha = Get-Field $t '^SHA-256:\s+(\S+)'
    Test-That ($sha -eq $whiterSha256) 'Whiter SHA-256' 'matches README.md' "actual [$sha], expected $whiterSha256"

    $titles = 'ОБЪЕКТ АНАЛИЗА', 'ПРИЗНАКИ УЯЗВИМОСТЕЙ', 'ИНДИКАТОРЫ КОМПРОМЕТАЦИИ', 'ВЗАИМОДЕЙСТВИЕ С ФАЙЛОВОЙ СИСТЕМОЙ', 'ОЦЕНКА РИСКА', 'РЕКОМЕНДАЦИИ'
    for ($i = 0; $i -lt 6; $i++) {
        $n = $i + 1
        $found = $t.Contains("================ $n. $($titles[$i])")
        Test-That $found "Whiter section $n" $titles[$i] "heading '$n. $($titles[$i])' not found"
    }
}

# ---------------------------------------------------------------- 3. x86 against x64

Invoke-Section '3. x86 against x64' {
    if (-not $script:exe86) { Add-Result 'SKIP' 'x86 comparison' 'the x86 exe was not built'; return }
    foreach ($e in $expected) {
        $name = 'x86 = x64 ' + $e.Report
        if (-not $script:reports.ContainsKey($e.Report)) { Add-Result 'SKIP' $name 'no x64 report to compare with'; continue }
        $r = Invoke-Ias ('x86_' + $e.Report) @($e.Path) $script:exe86
        $report = Join-Path $r.Dir ('report_' + $e.Report + '.txt')
        if ($r.Exit -ne 0 -or -not (Test-Path -LiteralPath $report)) { Add-Result 'FAIL' $name ("x86 run failed; " + (Get-ExitInfo $r)); continue }
        $diff = Compare-Files $script:reports[$e.Report] $report
        Test-That ($null -eq $diff) $name 'reports are byte-identical' "$diff"
    }
}

# ---------------------------------------------------------------- 4. input handling

Invoke-Section '4. Input handling' {
    $data = New-RunDir 'inputs'

    # missing and empty files
    $r = Invoke-Ias 'in_missing' @((Join-Path $data 'no_such_file.exe'))
    Test-That ($r.Exit -eq 1 -and $r.Out -match 'ОШИБКА' -and $r.Out -match 'не существует') 'missing file' 'exit 1 and an error text' (Get-ExitInfo $r)

    $f = Join-Path $data 'empty.exe'
    [IO.File]::WriteAllBytes($f, [byte[]]@())
    $r = Invoke-Ias 'in_empty' @($f)
    Test-That ($r.Exit -eq 1 -and $r.Out -match 'ОШИБКА') 'empty file' 'exit 1 and an error text' (Get-ExitInfo $r)

    # damaged inputs: analysis finishes and the report is complete
    $cases = New-Object Collections.Generic.List[object]
    $cases.Add(@('in_mz2', 'mz2.exe', [byte[]](0x4D, 0x5A), '2-byte MZ'))
    $bytes = New-Object byte[] 4096
    (New-Object Random 20261101).NextBytes($bytes)
    $cases.Add(@('in_random', 'random4k.bin', $bytes, '4 KB random'))
    if (Test-Path -LiteralPath $xcopy) {
        $whole = [IO.File]::ReadAllBytes($xcopy)
        foreach ($n in 300, 1024, 8000) {
            $part = New-Object byte[] $n
            [Array]::Copy($whole, $part, $n)
            $cases.Add(@("in_trunc$n", "xcopy_$n.exe", $part, "xcopy truncated to $n bytes"))
        }
    }
    else { Add-Result 'SKIP' 'truncated xcopy' "file is missing: $xcopy" }

    foreach ($c in $cases) {
        $f = Join-Path $data $c[1]
        [IO.File]::WriteAllBytes($f, [byte[]]$c[2])
        $r = Invoke-Ias $c[0] @($f)
        $report = Join-Path $r.Dir ('report_' + $c[1] + '.txt')
        $complete = (Test-Path -LiteralPath $report) -and (Read-Report $report).Contains('================ 6. ')
        Test-That ($r.Exit -eq 0 -and $complete) $c[3] 'exit 0, complete report' ("complete report=$complete; " + (Get-ExitInfo $r))
    }

    # help
    foreach ($h in '--help', '-h', '/?') {
        $r = Invoke-Ias 'in_help' @($h)
        Test-That ($r.Exit -eq 0 -and $r.Out -match 'Использование') "help $h" 'exit 0, usage printed' (Get-ExitInfo $r)
    }

    # file extension
    if (Test-Path -LiteralPath $xcopy) {
        $f = Join-Path $data 'unknown.xyz'
        Copy-Item -LiteralPath $xcopy -Destination $f
        $r = Invoke-Ias 'in_ext' @($f)
        Test-That ($r.Exit -eq 0 -and $r.Out -match 'Предупреждение: расширение \.xyz') 'unknown extension warns' 'warning printed, exit 0' (Get-ExitInfo $r)
        $f = Join-Path $data 'known.dll'
        Copy-Item -LiteralPath $xcopy -Destination $f
        $r = Invoke-Ias 'in_ext_known' @($f)
        Test-That ($r.Exit -eq 0 -and $r.Out -notmatch 'Предупреждение') 'known extension does not warn' 'no warning, exit 0' (Get-ExitInfo $r)
    }

    # archives
    if ((Test-Path -LiteralPath $xcopy) -and (Test-Path -LiteralPath $notepad)) {
        $zipDir = New-RunDir 'zip_src'
        Copy-Item -LiteralPath $xcopy -Destination (Join-Path $zipDir 'xcopy.exe')
        Copy-Item -LiteralPath $notepad -Destination (Join-Path $zipDir 'notepad.exe')
        $zip = Join-Path $data 'two.zip'
        $r = Invoke-Proc $tar ('-a -c -f ' + (ConvertTo-Arg $zip) + ' xcopy.exe notepad.exe') $zipDir
        if ($r.Exit -ne 0) { Add-Result 'FAIL' 'create two.zip' ("tar exit=$($r.Exit): " + (Get-Short $r.Err)) }
        else {
            $r = Invoke-Ias 'zip_list' @($zip)
            Test-That ($r.Exit -eq 1 -and $r.Out -match 'xcopy\.exe' -and $r.Out -match 'notepad\.exe') 'zip without --member' 'lists both files, exit 1' (Get-ExitInfo $r)

            $r = Invoke-Ias 'zip_member' @($zip, '--member', 'xcopy.exe')
            $report = Join-Path $r.Dir 'report_xcopy.exe.txt'
            $s = $(if (Test-Path -LiteralPath $report) { Get-Score (Read-Report $report) } else { '<no report>' })
            Test-That ($r.Exit -eq 0 -and $s -eq '2') 'zip --member xcopy.exe' 'exit 0, same score as from disk (2)' ("score=$s; " + (Get-ExitInfo $r))

            $r = Invoke-Ias 'zip_nosuch' @($zip, '--member', 'nosuch.exe')
            Test-That ($r.Exit -eq 1 -and $r.Out -match 'ОШИБКА') 'zip --member nonexistent' 'exit 1 and an error text' (Get-ExitInfo $r)

            foreach ($m in '-x', '*', '*.exe', 'xcopy.ex?', '[x]copy.exe', 'sub\xcopy.exe') {
                $r = Invoke-Ias 'zip_badname' @($zip, '--member', $m)
                Test-That ($r.Exit -eq 1 -and $r.Out -match 'недопустимое имя') "zip --member '$m' rejected" 'exit 1, invalid name' (Get-ExitInfo $r)
            }
        }

        # entries with hostile names really stored in an archive, picked automatically as the only member
        $content = [IO.File]::ReadAllBytes($xcopy)
        foreach ($n in '-x.exe', 'a*.exe', 'a[1].exe') {
            $z = Join-Path $data ('hostile_' + ($n -replace '[^a-z0-9.]', '_') + '.zip')
            New-Zip $z @($n) $content
            $r = Invoke-Ias 'zip_hostile' @($z)
            Test-That ($r.Exit -eq 1 -and $r.Out -match 'недопустимое имя') "zip entry '$n' rejected" 'exit 1, invalid name' (Get-ExitInfo $r)
        }

        # the same name twice: tar would stream both files, so it must be refused
        $z = Join-Path $data 'duplicate.zip'
        New-Zip $z @('dup.exe', 'dup.exe') $content
        $r = Invoke-Ias 'zip_dup' @($z, '--member', 'dup.exe')
        Test-That ($r.Exit -eq 1 -and $r.Out -match 'ОШИБКА') 'zip duplicate entry name' 'exit 1 and an error text' (Get-ExitInfo $r)
    }
    else { Add-Result 'SKIP' 'zip tests' 'xcopy.exe or notepad.exe is missing' }

    $f = Join-Path $data 'broken.zip'
    $bytes = New-Object byte[] 2048
    (New-Object Random 7).NextBytes($bytes)
    [IO.File]::WriteAllBytes($f, $bytes)
    $r = Invoke-Ias 'zip_broken' @($f)
    Test-That ($r.Exit -eq 1 -and $r.Out -match 'ОШИБКА') 'corrupt zip' 'exit 1 and an error text' (Get-ExitInfo $r)
}

Invoke-Section '4b. CSV formula escaping' {
    # Strings in the file reach the "Признак" column through the signature rules (examples[0]).
    # Each line triggers its own rule, so each one becomes the first example of a separate finding.
    $data = New-RunDir 'csv'
    $probes = [ordered]@{
        '=' = '=HYPERLINK("http://evil.example/","URLDownloadToFile")'
        '+' = '+Winlogon formula probe'
        '-' = '-Shell Folders formula probe'
        '@' = '@InternetOpen formula probe'
    }
    $control = 'RegSetValueEx plain control line'
    $text = (@($probes.Values) + $control) -join "`0"
    $f = Join-Path $data 'crafted.bin'
    [IO.File]::WriteAllBytes($f, [Text.Encoding]::ASCII.GetBytes("`0" + $text + "`0"))

    $r = Invoke-Ias 'csv_run' @($f)
    $csv = Join-Path $r.Dir 'report_crafted.bin.csv'
    if ($r.Exit -ne 0 -or -not (Test-Path -LiteralPath $csv)) { Add-Result 'FAIL' 'CSV generated' (Get-ExitInfo $r); return }

    $lines = @((Read-Report $csv) -split "`n" | Where-Object { $_ -ne '' })
    $rows = New-Object Collections.Generic.List[object]
    foreach ($l in $lines) { $rows.Add((Split-CsvLine $l)) }
    $columns = $rows[0].Length
    $badWidth = @($rows | Where-Object { $_.Length -ne $columns })
    Test-That ($badWidth.Count -eq 0 -and $columns -eq 17) 'CSV column count' "all $($rows.Count) rows have 17 columns" "header $columns columns, $($badWidth.Count) rows differ"

    $data_rows = @($rows | Select-Object -Skip 1)
    foreach ($lead in $probes.Keys) {
        $probe = $probes[$lead]
        $cell = @($data_rows | ForEach-Object { $_[11] } | Where-Object { $_.Contains($probe) })
        if ($cell.Count -eq 0) { Add-Result 'SKIP' "CSV field starting with $lead" "the crafted line did not reach the CSV: $probe"; continue }
        Test-That ($cell[0] -ceq ("'" + $probe)) "CSV field starting with $lead" "written as $($cell[0])" "actual [$($cell[0])], expected ['$probe]"
    }

    $plain = @($data_rows | ForEach-Object { $_[11] } | Where-Object { $_.Contains($control) })
    if ($plain.Count -eq 0) { Add-Result 'SKIP' 'CSV plain field untouched' 'the control line did not reach the CSV' }
    else { Test-That ($plain[0] -ceq $control) 'CSV plain field untouched' 'no apostrophe added' "actual [$($plain[0])]" }

    # a lone "-" is the "no value" placeholder and is not a formula
    $dangerous = @(foreach ($row in $data_rows) { foreach ($c in $row) { if ($c.Length -gt 0 -and $c -ne '-' -and '=+-@'.IndexOf($c[0]) -ge 0) { $c } } })
    Test-That ($dangerous.Count -eq 0) 'CSV has no formula-like field' 'every field is safe' ("found: " + (Get-Short ($dangerous -join ' | ')))
}

# ---------------------------------------------------------------- 5. economics.ini

Invoke-Section '5. economics.ini' {
    # The target needs a data-loss finding for backupShare to matter
    $target = $null; $reportName = $null
    foreach ($candidate in @(@($rar, 'Whiter.a.exe'), @("$samples\sample_dropper.exe", 'sample_dropper.exe'))) {
        if (Test-Path -LiteralPath $candidate[0]) { $target = $candidate[0]; $reportName = $candidate[1]; break }
    }
    if (-not $target) { Add-Result 'SKIP' 'economics.ini' 'neither Whiter.a.rar nor sample_dropper.exe is present'; return }
    Write-Line "       INFO: target $target"

    function Invoke-Profile([string]$label, [string[]]$ini) {
        $d = New-RunDir "econ_$label"
        $exe = Join-Path $d 'ExeIAS.exe'
        Copy-Item -LiteralPath $script:exe64 -Destination $exe
        Write-Utf8 (Join-Path $d 'economics.ini') $ini
        $work = Join-Path $d 'out'
        $null = New-Item -ItemType Directory -Force -Path $work
        $r = Invoke-Proc $exe (ConvertTo-Arg $target) $work
        return [pscustomobject]@{ Result = $r; Report = (Join-Path $work "report_$reportName.txt") }
    }

    $bad = Invoke-Profile 'invalid' @('name=Банк', 'backupShare=5', 'dataValue=abc', 'hourCost=-1')
    if ($bad.Result.Exit -ne 0 -or -not (Test-Path -LiteralPath $bad.Report)) { Add-Result 'FAIL' 'invalid ini does not crash' (Get-ExitInfo $bad.Result); return }
    Add-Result 'PASS' 'invalid ini does not crash' 'exit 0, report written'
    $t = Read-Report $bad.Report

    $profileLine = Get-Field $t '^(Профиль организации:.*)$'
    Test-That ($profileLine -match 'Банк') 'profile name shown' "$profileLine" "actual [$profileLine], expected to contain Банк"

    $negative = [regex]::Matches($t, '-\d[\d ]*\s*руб')
    Test-That ($negative.Count -eq 0) 'no negative amounts' 'none in the report' "found $($negative.Count), first: $(if ($negative.Count) { $negative[0].Value })"

    # backupShare=5 must act exactly as 1; abc and -1 must act as if the lines were absent
    $clamped = Invoke-Profile 'control_clamped' @('name=Банк', 'backupShare=1')
    $diff = Compare-Files $bad.Report $clamped.Report
    Test-That ($null -eq $diff) 'backupShare clamped, bad values ignored' 'report is byte-identical to backupShare=1 with defaults' "$diff"

    # the comparison above means something only if these parameters change this report
    $sensitive = @(
        @('backupShare', @('name=Банк', 'backupShare=0.5')),
        @('dataValue', @('name=Банк', 'backupShare=1', 'dataValue=900000')),
        @('hourCost', @('name=Банк', 'backupShare=1', 'hourCost=3000'))
    )
    foreach ($s in $sensitive) {
        $other = Invoke-Profile ('sens_' + $s[0]) $s[1]
        $changed = $null -ne (Compare-Files $clamped.Report $other.Report)
        Test-That $changed "report reacts to $($s[0])" 'valid value changes the report' "valid $($s[0]) did not change the report, so the clamp check above proves nothing for it"
    }
}

# ---------------------------------------------------------------- 6. standard input through cmd.exe

Invoke-Section '6. Standard input (cmd.exe pipe)' {
    if (Test-Path -LiteralPath $rar) {
        $d = New-RunDir 'stdin_whiter'
        $cmd = '/c "' + (ConvertTo-Arg $tar) + ' -xOf ' + (ConvertTo-Arg $rar) + ' Whiter.a.exe | ' + (ConvertTo-Arg $script:exe64) + ' - --name Whiter.a.exe"'
        $r = Invoke-Proc 'cmd.exe' $cmd $d
        $report = Join-Path $d 'report_Whiter.a.exe.txt'
        if ($r.Exit -ne 0 -or -not (Test-Path -LiteralPath $report)) { Add-Result 'FAIL' 'stdin Whiter score' (Get-ExitInfo $r) }
        else {
            $t = Read-Report $report
            $s = Get-Score $t; $l = Get-Level $t
            Test-That ($s -eq '100' -and $l -ceq 'CRITICAL') 'stdin Whiter score' "$s $l" "actual $s $l, expected 100 CRITICAL"
            $sha = Get-Field $t '^SHA-256:\s+(\S+)'
            Test-That ($sha -eq $whiterSha256) 'stdin bytes intact' 'SHA-256 matches README.md' "actual [$sha], expected $whiterSha256"
            if ($script:reports.ContainsKey('Whiter.a.exe')) {
                # only the line naming the data source may differ
                $strip = { param($x) @($x -split "`n" | Where-Object { $_ -notmatch 'стандартный ввод|из архива' }) -join "`n" }
                $same = (& $strip $t) -ceq (& $strip (Read-Report $script:reports['Whiter.a.exe']))
                Test-That $same 'stdin report = archive report' 'same apart from the source line' 'reports differ on more than the source line'
            }
        }
    }
    else { Add-Result 'SKIP' 'stdin Whiter score' "file is missing: $rar" }

    $d = New-RunDir 'stdin_empty'
    $cmd = '/c "type nul | ' + (ConvertTo-Arg $script:exe64) + ' -"'
    $r = Invoke-Proc 'cmd.exe' $cmd $d
    Test-That ($r.Exit -eq 1 -and $r.Out -match 'ОШИБКА') 'empty stdin' 'exit 1 and an error text' (Get-ExitInfo $r)
}

# ---------------------------------------------------------------- safety of the run itself

Invoke-Section '7. Nothing left behind' {
    $onDisk = @(Get-ChildItem -LiteralPath $script:runDir -Recurse -Force -File | Where-Object { $_.Name -eq 'Whiter.a.exe' })
    Test-That ($onDisk.Count -eq 0) 'sample not on disk' 'no Whiter.a.exe under the run directory' ("found: " + (($onDisk | ForEach-Object { $_.FullName }) -join ', '))

    $snapshots = @(Get-ChildItem -LiteralPath $env:TEMP -Force -File -Filter 'ias*' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $script:started.AddSeconds(-2) -and $_.Extension -match '\.(rar|zip|tmp)$' })
    Test-That ($snapshots.Count -eq 0) 'archive snapshots removed' 'no ias* files of this run in TEMP' ("left: " + (($snapshots | ForEach-Object { $_.Name }) -join ', '))

    $inProject = @(Get-ChildItem -LiteralPath $script:root -Force -File | Where-Object { $_.Name -match '^(report|strings)_' -and $_.LastWriteTime -ge $script:started })
    Test-That ($inProject.Count -eq 0) 'no outputs in the project' 'project root is clean' ("found: " + (($inProject | ForEach-Object { $_.Name }) -join ', '))
}

}

# ---------------------------------------------------------------- summary

Write-Line ''
Write-Line ('=== SUMMARY: PASS={0} FAIL={1} SKIP={2} (total {3}), {4:N0} s' -f $script:counts.PASS, $script:counts.FAIL, $script:counts.SKIP,
    ($script:counts.PASS + $script:counts.FAIL + $script:counts.SKIP), ((Get-Date) - $script:started).TotalSeconds)
foreach ($f in $script:fails) { Write-Line $f }
Write-Line "Outputs: $($script:runDir)"
exit $script:counts.FAIL
