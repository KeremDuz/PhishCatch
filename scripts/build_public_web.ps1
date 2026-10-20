param(
    [Parameter(Mandatory = $true)][string]$PhishCatchApiBaseUrl,
    [string]$FlutterExecutable = 'flutter',
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [switch]$StaticPages,
    [string]$BaseHref = ''
)
$ErrorActionPreference = 'Stop'
$server = [Uri]$PhishCatchApiBaseUrl
if (!$server.IsAbsoluteUri -or $server.Scheme -ne 'https' -or $server.IsLoopback -or
    $server.UserInfo -or $server.Query -or $server.Fragment -or $server.AbsolutePath -ne '/' -or
    $server.Host -eq 'phishcatch-p4jc.onrender.com') {
    throw 'Use the verified HTTPS origin of the independent PhishCatch service.'
}
if (!$BaseHref) { $BaseHref = if ($StaticPages) { '/PhishCatch/' } else { '/' } }
if ($BaseHref -notmatch '^/(?:[A-Za-z0-9._~-]+/)*$' -or
    ($BaseHref.Split('/') | Where-Object { $_ -in '.', '..' })) {
    throw 'BaseHref must be an absolute application path starting and ending with /.'
}
$apiOrigin = $server.GetLeftPart([UriPartial]::Authority)
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if ((Test-Path -LiteralPath $destination) -and (Get-ChildItem -LiteralPath $destination -Force | Select-Object -First 1)) {
    throw 'Choose a new, empty staging directory.'
}
Push-Location (Join-Path $PSScriptRoot '../apps/flutter_app')
try {
    & $FlutterExecutable pub get --enforce-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Locked dependency installation failed.' }
    $buildArguments = @(
        'build', 'web', '--release', '--no-pub', '--no-web-resources-cdn', '--pwa-strategy=none',
        '--dart-define=PHISHCATCH_CONSUMER_MODE=true',
        "--dart-define=PHISHCATCH_API_BASE_URL=$apiOrigin", "--base-href=$BaseHref", "--output=$destination"
    )
    if ($StaticPages) { $buildArguments += "--dart-define=PHISHCATCH_PUBLIC_API_ORIGIN=$apiOrigin" }
    & $FlutterExecutable @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Consumer web build failed.' }
    Write-Output "PhishCatch web: $destination"
} finally { Pop-Location }
