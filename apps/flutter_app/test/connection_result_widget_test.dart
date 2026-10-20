import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:phishcatch/screens/connection_screen.dart';
import 'package:phishcatch/screens/history_screen.dart';
import 'package:phishcatch/screens/home_screen.dart';
import 'package:phishcatch/screens/qr_scanner_screen.dart';
import 'package:phishcatch/screens/result_screen.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';
import 'package:phishcatch/services/api_service.dart';
import 'package:phishcatch/theme/app_theme.dart';

Widget _app(Widget screen) =>
    MaterialApp(theme: AppTheme.lightTheme, home: screen);
ApiService _api(http.Client client) => ApiService(
  client: client,
  standaloneBaseUrl: 'https://standalone.example.test',
);
http.Response _login() => http.Response(
  jsonEncode({
    'access_token': 'test-only-app-session',
    'token_type': 'bearer',
    'expires_in': 3600,
    'user': {'email': 'member@example.test'},
  }),
  200,
);

void main() {
  testWidgets(
    'failed scan shows failure and unavailable scores without zero percentages',
    (tester) async {
      await tester.pumpWidget(
        _app(
          ResultScreen(
            result: AnalysisResult.unavailable('https://example.test/'),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Analiz tamamlanamadı'), findsOneWidget);
      expect(find.text('Risk sinyali bulunmadı'), findsNothing);
      expect(find.text('—'), findsNWidgets(2));
      expect(find.text('0.0%'), findsNothing);
    },
  );

  testWidgets(
    'partial malicious result keeps warning and withholds even supplied probabilities',
    (tester) async {
      await tester.pumpWidget(
        _app(
          ResultScreen(
            result: AnalysisResult(
              url: 'https://example.test',
              normalizedUrl: 'https://example.test',
              finalVerdict: 'malicious',
              maliciousProbability: 0.99,
              cleanProbability: 0.01,
              decidedBy: 'test',
              stages: [],
              scanStatus: 'partial',
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Riskli bağlantı'), findsOneWidget);
      expect(find.text('Kısmi sonuç'), findsOneWidget);
      expect(find.text('—'), findsNWidgets(2));
      expect(find.text('99.0%'), findsNothing);
    },
  );

  testWidgets(
    'complete clean and unknown verdicts remain distinct and show true probabilities',
    (tester) async {
      for (final verdict in ['clean', 'unknown']) {
        await tester.pumpWidget(
          _app(
            ResultScreen(
              result: AnalysisResult(
                url: 'https://example.test',
                normalizedUrl: 'https://example.test',
                finalVerdict: verdict,
                maliciousProbability: 0.123,
                cleanProbability: 0.877,
                decidedBy: 'test',
                stages: [],
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(
          find.text(
            verdict == 'clean' ? 'Risk sinyali bulunmadı' : 'Belirsiz sonuç',
          ),
          findsOneWidget,
        );
        expect(find.text('12.3%'), findsOneWidget);
        expect(find.text('87.7%'), findsOneWidget);
      }
    },
  );

  testWidgets(
    'connection signs in, clears password and revokes session on logout',
    (tester) async {
      final api = _api(
        MockClient(
          (request) async => request.url.path.endsWith('/logout')
              ? http.Response('', 204)
              : _login(),
        ),
      );
      addTearDown(api.dispose);
      api.useAllsafe('https://allsafe.example.test');
      await tester.pumpWidget(_app(ConnectionScreen(api: api)));
      await tester.enterText(
        find.byType(TextField).at(1),
        'member@example.test',
      );
      await tester.enterText(find.byType(TextField).at(2), 'test-password');
      await tester.ensureVisible(find.text('Giriş yap'));
      await tester.tap(find.text('Giriş yap'));
      await tester.pumpAndSettle();
      expect(api.isSignedIn, isTrue);
      expect(find.text('Giriş yapıldı: member@example.test'), findsOneWidget);
      expect(find.text('test-password'), findsNothing);
      await tester.ensureVisible(find.text('Çıkış yap'));
      await tester.tap(find.text('Çıkış yap'));
      await tester.pumpAndSettle();
      expect(api.isSignedIn, isFalse);
      expect(find.text('Kurum hesabıyla giriş yapın.'), findsOneWidget);
    },
  );

  testWidgets('server selection preserves browser session if logout fails', (
    tester,
  ) async {
    final api = ApiService(
      allsafeBaseUrl: 'https://allsafe.example.test',
      browserOrigin: 'https://allsafe.example.test',
      csrfToken: () => 'test-csrf',
      standaloneBaseUrl: 'https://standalone.example.test',
      client: MockClient(
        (request) async => request.url.path.endsWith('/me')
            ? http.Response(jsonEncode({'email': 'member@example.test'}), 200)
            : http.Response('', 503),
      ),
    );
    addTearDown(api.dispose);
    await api.restoreWebSession();
    await tester.pumpWidget(_app(ConnectionScreen(api: api)));
    await tester.ensureVisible(find.text('Sunucu adresini uygula'));
    await tester.tap(find.text('Sunucu adresini uygula'));
    await tester.pumpAndSettle();
    expect(api.isSignedIn, isTrue);
    expect(find.text('Giriş yapıldı: member@example.test'), findsOneWidget);
    expect(find.textContaining('503'), findsOneWidget);
  });

  testWidgets('history request failure is not reported as an empty history', (
    tester,
  ) async {
    final api = _api(
      MockClient(
        (request) async => request.url.path.endsWith('/login')
            ? _login()
            : http.Response('', 503),
      ),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await api.login(email: 'member@example.test', password: 'test');
    await tester.pumpWidget(_app(HistoryScreen(api: api)));
    await tester.pumpAndSettle();
    expect(find.text('Henüz tarama kaydı yok'), findsNothing);
    expect(find.text('Yeniden dene'), findsOneWidget);
    expect(find.textContaining('503'), findsOneWidget);
  });

  testWidgets('history preserves partial scan status when opening the result', (
    tester,
  ) async {
    final api = _api(
      MockClient((request) async {
        if (request.url.path.endsWith('/login')) return _login();
        return http.Response(
          jsonEncode([
            {
              'id': 'test-scan',
              'url': 'https://example.test',
              'source': 'qr',
              'created_at': '2026-10-20T10:00:00Z',
              'scan_status': 'partial',
              'analysis': {
                'contract_version': '2',
                'scan_status': 'partial',
                'url': 'https://example.test',
                'normalized_url': 'https://example.test',
                'final_verdict': 'clean',
                'stages': [],
              },
            },
          ]),
          200,
        );
      }),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await api.login(email: 'member@example.test', password: 'test');
    await tester.pumpWidget(_app(HistoryScreen(api: api)));
    await tester.pumpAndSettle();
    expect(find.text('Kısmi'), findsOneWidget);
    await tester.tap(find.text('https://example.test'));
    await tester.pumpAndSettle();
    expect(find.text('Analiz kısmen tamamlandı'), findsOneWidget);
    expect(find.text('Risk sinyali bulunmadı'), findsNothing);
  });

  testWidgets(
    'camera stops in background, restarts on resume and disposes on exit',
    (tester) async {
      final original = MobileScannerPlatform.instance;
      final camera = _CameraPlatform();
      MobileScannerPlatform.instance = camera;
      addTearDown(() {
        MobileScannerPlatform.instance = original;
        camera.barcodes.close();
      });
      await tester.pumpWidget(_app(const QrScannerScreen()));
      await tester.pumpAndSettle();
      expect(camera.starts, 1);
      expect(camera.lastDirection, CameraFacing.back);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await tester.pumpAndSettle();
      expect(camera.stops, 1);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(camera.starts, 2);
      await tester.pumpWidget(_app(const SizedBox()));
      await tester.pumpAndSettle();
      expect(camera.disposed, isTrue);
    },
  );

  testWidgets('QR home action submits URL with qr source to ALLSAFE', (
    tester,
  ) async {
    final original = MobileScannerPlatform.instance;
    final camera = _CameraPlatform();
    MobileScannerPlatform.instance = camera;
    addTearDown(() {
      MobileScannerPlatform.instance = original;
      camera.barcodes.close();
    });
    Map<String, dynamic>? payload;
    final api = _api(
      MockClient((request) async {
        if (request.url.path.endsWith('/login')) return _login();
        expect(request.url.path, '/api/v1/phishcatch/scans');
        payload = jsonDecode(request.body) as Map<String, dynamic>;
        return http.Response(
          jsonEncode({
            'id': 'qr-scan-test',
            'scan_status': 'complete',
            'analysis': {
              'contract_version': '2',
              'scan_status': 'complete',
              'url': 'https://example.test/qr',
              'normalized_url': 'https://example.test/qr',
              'final_verdict': 'clean',
              'stages': [
                {
                  'scanner': 'url_model',
                  'verdict': 'clean',
                  'status': 'completed',
                },
              ],
            },
          }),
          201,
        );
      }),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await api.login(email: 'member@example.test', password: 'test');
    await tester.pumpWidget(_app(HomeScreen(api: api)));
    await tester.ensureVisible(find.text('QR kod tara'));
    await tester.tap(find.text('QR kod tara'));
    await tester.pumpAndSettle();
    camera.barcodes.add(
      const BarcodeCapture(
        barcodes: [Barcode(rawValue: 'https://example.test/qr')],
      ),
    );
    await tester.pumpAndSettle();
    expect(payload?['url'], 'https://example.test/qr');
    expect(payload?['source'], 'qr');
    expect(payload?['client_request_id'], isNotEmpty);
    expect(find.text('Risk sinyali bulunmadı'), findsOneWidget);
    expect(find.text('qr-scan-test'), findsOneWidget);
    expect(camera.disposed, isTrue);
  });

  testWidgets('camera permission denial can be retried', (tester) async {
    final original = MobileScannerPlatform.instance;
    final camera = _CameraPlatform()..denyNextStart = true;
    MobileScannerPlatform.instance = camera;
    addTearDown(() {
      MobileScannerPlatform.instance = original;
      camera.barcodes.close();
    });
    await tester.pumpWidget(_app(const QrScannerScreen()));
    await tester.pumpAndSettle();
    expect(find.text('Kamera kullanılamıyor'), findsOneWidget);
    expect(find.textContaining('Kamera izni verilmedi.'), findsWidgets);
    await tester.ensureVisible(find.text('Kamerayı yeniden dene'));
    await tester.tap(find.text('Kamerayı yeniden dene'));
    await tester.pumpAndSettle();
    expect(camera.starts, 2);
    expect(find.text('Kamera kullanılamıyor'), findsNothing);
    await tester.pumpWidget(_app(const SizedBox()));
    await tester.pumpAndSettle();
  });

  testWidgets('a camera start completing in background is stopped', (
    tester,
  ) async {
    final original = MobileScannerPlatform.instance;
    final gate = Completer<void>();
    final camera = _CameraPlatform()..startGate = gate;
    MobileScannerPlatform.instance = camera;
    addTearDown(() {
      MobileScannerPlatform.instance = original;
      camera.barcodes.close();
    });
    await tester.pumpWidget(_app(const QrScannerScreen()));
    await tester.pump();
    expect(camera.starts, 1);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    gate.complete();
    await tester.pumpAndSettle();
    expect(camera.stops, 1);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(camera.starts, 2);
    await tester.pumpWidget(_app(const SizedBox()));
    await tester.pumpAndSettle();
  });

  testWidgets('non-URL QR stays on camera and valid QR closes it once', (
    tester,
  ) async {
    final original = MobileScannerPlatform.instance;
    final camera = _CameraPlatform();
    MobileScannerPlatform.instance = camera;
    addTearDown(() {
      MobileScannerPlatform.instance = original;
      camera.barcodes.close();
    });
    String? scanned;
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        home: Builder(
          builder: (context) => TextButton(
            onPressed: () async {
              scanned = await Navigator.of(context).push<String>(
                MaterialPageRoute(builder: (_) => const QrScannerScreen()),
              );
            },
            child: const Text('Open camera'),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Open camera'));
    await tester.pumpAndSettle();
    camera.barcodes.add(
      const BarcodeCapture(barcodes: [Barcode(rawValue: 'WIFI:T:WPA;S:test;')]),
    );
    await tester.pumpAndSettle();
    expect(
      find.text(
        'Bu QR kod bir web bağlantısı içermiyor. Başka bir kod okutun.',
      ),
      findsOneWidget,
    );
    expect(scanned, isNull);
    camera.barcodes.add(
      const BarcodeCapture(
        barcodes: [Barcode(rawValue: 'https://example.test/path')],
      ),
    );
    await tester.pumpAndSettle();
    expect(scanned, 'https://example.test/path');
    expect(camera.stops, 1);
    expect(camera.disposed, isTrue);
  });
}

class _CameraPlatform extends MobileScannerPlatform {
  final barcodes = StreamController<BarcodeCapture?>.broadcast();
  int starts = 0;
  int stops = 0;
  bool disposed = false;
  bool denyNextStart = false;
  Completer<void>? startGate;
  CameraFacing? lastDirection;
  @override
  Stream<BarcodeCapture?> get barcodesStream => barcodes.stream;
  @override
  Stream<TorchState> get torchStateStream => const Stream.empty();
  @override
  Stream<double> get zoomScaleStateStream => const Stream.empty();
  @override
  Widget buildCameraView() => const ColoredBox(color: Colors.black);
  @override
  Future<MobileScannerViewAttributes> start(StartOptions options) async {
    starts++;
    if (startGate != null) await startGate!.future;
    if (denyNextStart) {
      denyNextStart = false;
      throw const MobileScannerException(
        errorCode: MobileScannerErrorCode.permissionDenied,
      );
    }
    lastDirection = options.cameraDirection;
    return const MobileScannerViewAttributes(
      cameraDirection: CameraFacing.back,
      currentTorchMode: TorchState.unavailable,
      size: Size(640, 480),
      numberOfCameras: 2,
    );
  }

  @override
  Future<void> stop() async {
    stops++;
  }

  @override
  Future<void> dispose() async {
    disposed = true;
  }
}
