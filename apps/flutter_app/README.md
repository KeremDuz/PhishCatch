# PhishCatch Flutter App

Flutter client for the PhishCatch backend.

## Backend URL

The app picks a development backend URL automatically:

- Web: `http://localhost:8001`
- Android emulator: `http://10.0.2.2:8001`
- Other platforms: `http://localhost:8001`

Override it with a dart define when needed:

```bash
flutter run --dart-define=PHISHCATCH_API_BASE_URL=http://YOUR_HOST:8001
```

For a physical phone, use the backend machine's LAN IP address and make sure the phone can reach that port.
