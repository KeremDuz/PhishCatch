param(
    [Parameter(Mandatory = $true)]
    [string]$AllsafeApiBaseUrl,
    [string]$FlutterExecutable = 'flutter',
    [string]$AndroidSdkRoot = $env:ANDROID_HOME,
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$appRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../apps/flutter_app'))
$serverUri = $null
if (![System.Uri]::TryCreate($AllsafeApiBaseUrl, [System.UriKind]::Absolute, [ref]$serverUri) -or
    $serverUri.Scheme -ne 'https' -or $serverUri.IsLoopback -or
    ![string]::IsNullOrEmpty($serverUri.UserInfo) -or
    ![string]::IsNullOrEmpty($serverUri.Query) -or
    ![string]::IsNullOrEmpty($serverUri.Fragment) -or
    $serverUri.AbsolutePath -ne '/') {
    throw 'ALLSAFE_API_BASE_URL must be the HTTPS origin of your ALLSAFE server.'
}
if ($serverUri.Host -eq 'phishcatch-p4jc.onrender.com') {
    throw 'Use the managed ALLSAFE server origin, not the old standalone Render service.'
}
$serverOrigin = $serverUri.GetLeftPart([System.UriPartial]::Authority)

if (![string]::IsNullOrWhiteSpace($AndroidSdkRoot)) {
    $env:ANDROID_HOME = [System.IO.Path]::GetFullPath($AndroidSdkRoot)
    $env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
}
if (![string]::IsNullOrWhiteSpace($JavaHome)) {
    $env:JAVA_HOME = [System.IO.Path]::GetFullPath($JavaHome)
}
if (!(Test-Path -LiteralPath (Join-Path $appRoot 'android/key.properties'))) {
    throw 'Restore your existing ignored android/key.properties and signing keystore before a release build.'
}
if (![string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
}

Push-Location $appRoot
try {
    & $FlutterExecutable pub get --enforce-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Flutter dependency resolution failed.' }
    & $FlutterExecutable build apk --release '--dart-define=ALLSAFE_MANAGED_MODE=true' "--dart-define=ALLSAFE_API_BASE_URL=$serverOrigin"
    if ($LASTEXITCODE -ne 0) { throw 'Signed Android release build failed.' }
    $apkPath = Join-Path $appRoot 'build/app/outputs/flutter-apk/app-release.apk'
    if (![string]::IsNullOrWhiteSpace($OutputDirectory)) {
        New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
        $apkPath = (Copy-Item -LiteralPath $apkPath -Destination (Join-Path $OutputDirectory 'PhishCatch-ALLSAFE-release.apk') -PassThru).FullName
    }
    Get-FileHash -LiteralPath $apkPath -Algorithm SHA256
    Write-Output "Signed release APK: $apkPath"
} finally {
    Pop-Location
}
