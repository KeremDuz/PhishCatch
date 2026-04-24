# PhishCatch Flutter App

Flutter client for the PhishCatch backend.

## Backend URL

The app picks a development backend URL automatically:

- Web: `http://localhost:8001`
- Android emulator: `http://10.0.2.2:8001`
- Other platforms: `http://localhost:8001`

For release builds, the app defaults to the Render backend:

- `https://phishcatch-p4jc.onrender.com`

Override it with a dart define when needed:

```bash
flutter run --dart-define=PHISHCATCH_API_BASE_URL=http://YOUR_HOST:8001
```

For a physical phone, use the backend machine's LAN IP address and make sure the phone can reach that port.

## Build For Deploy

Web:

```bash
flutter build web --release --dart-define=PHISHCATCH_API_BASE_URL=https://phishcatch-p4jc.onrender.com
```

Android APK:

```bash
flutter build apk --release --dart-define=PHISHCATCH_API_BASE_URL=https://phishcatch-p4jc.onrender.com
```
