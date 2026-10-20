param(
    [Parameter(Mandatory = $true)][string]$AllsafeApiBaseUrl,
    [string]$FlutterExecutable = 'flutter',
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$server = [Uri]$AllsafeApiBaseUrl
if (!$server.IsAbsoluteUri -or $server.Scheme -ne 'https' -or $server.IsLoopback -or
    $server.UserInfo -or $server.Query -or $server.Fragment -or $server.AbsolutePath -ne '/' -or
    $server.Host -eq 'phishcatch-p4jc.onrender.com') {
    throw 'Use the verified HTTPS origin of your ALLSAFE server.'
}
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if ((Test-Path -LiteralPath $destination) -and (Get-ChildItem -LiteralPath $destination -Force | Select-Object -First 1)) {
    throw 'OutputDirectory must be empty. Choose a new staging directory to avoid retaining obsolete web files.'
}
Push-Location (Join-Path $PSScriptRoot '../apps/flutter_app')
try {
    & $FlutterExecutable pub get --enforce-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Locked dependency installation failed.' }
    & $FlutterExecutable build web --release --no-web-resources-cdn --pwa-strategy=none --dart-define=ALLSAFE_MANAGED_MODE=true "--dart-define=ALLSAFE_API_BASE_URL=$($server.GetLeftPart([UriPartial]::Authority))" "--output=$destination"
    if ($LASTEXITCODE -ne 0) { throw 'Managed Flutter web build failed.' }
    Write-Output "Managed web client: $destination"
} finally { Pop-Location }
