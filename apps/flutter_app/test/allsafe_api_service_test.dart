import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';
import 'package:phishcatch/services/api_service.dart';

const _token = 'test-only-opaque-app-session-aaaaaaaaaaaaaaaaaaaaaaaa';
const _requestId = '291cb4b4-011c-42da-ae08-9069fe97ce27';

Map<String, dynamic> _analysis({
  String status = 'complete',
  String verdict = 'clean',
}) => {
  'contract_version': '2',
  'scan_status': status,
  'url': 'https://example.test/',
  'normalized_url': 'https://example.test/',
  'final_verdict': verdict,
  'decided_by': 'test',
  'stages': [
    {
      'scanner': 'test',
      'verdict': verdict,
      'status': status == 'complete' ? 'completed' : 'unavailable',
    },
  ],
};

http.Response _login() => http.Response(
  jsonEncode({
    'access_token': _token,
    'token_type': 'bearer',
    'expires_in': 3600,
    'user': {
      'id': 'test-user',
      'email': 'member@example.test',
      'display_name': 'Test member',
    },
  }),
  200,
);

http.Response _scan({
  String status = 'complete',
  Map<String, dynamic>? analysis,
}) => http.Response(
  jsonEncode({
    'id': 'cbfb7a6c-c012-4417-91fc-3a70e9d5a9a9',
    'scan_status': status,
    'analysis': analysis ?? _analysis(status: status),
  }),
  201,
);

ApiService _service(http.Client client) => ApiService(
  client: client,
  standaloneBaseUrl: 'https://standalone.example.test/',
);

void main() {
  test(
    'login uses password payload without bearer and token only goes to ALLSAFE',
    () async {
      final requests = <http.Request>[];
      final client = MockClient((request) async {
        requests.add(request);
        if (request.url.path.endsWith('/login')) return _login();
        if (request.url.path.endsWith('/logout')) return http.Response('', 204);
        if (request.url.host == 'standalone.example.test') {
          return http.Response(jsonEncode(_analysis()), 200);
        }
        return _scan();
      });
      final api = _service(client);
      addTearDown(api.dispose);
      api.useAllsafe('https://allsafe.example.test');
      await api.login(email: 'member@example.test', password: 'test-password');
      await api.analyzeUrl(
        'https://example.test/',
        source: 'qr',
        clientRequestId: _requestId,
      );
      await api.logout();
      api.useStandalone();
      await api.analyzeUrl('https://example.test/');

      expect(requests.first.url.path, '/api/v1/auth/mobile/login');
      expect(jsonDecode(requests.first.body), {
        'email': 'member@example.test',
        'password': 'test-password',
      });
      expect(requests.first.headers['Authorization'], isNull);
      expect(requests[1].headers['Authorization'], 'Bearer $_token');
      expect(requests[2].url.path, '/api/v1/auth/mobile/logout');
      expect(requests[2].headers['Authorization'], 'Bearer $_token');
      expect(requests.last.url.path, '/api/v1/analyze');
      expect(requests.last.headers['Authorization'], isNull);
      expect(
        requests
            .where((request) => request.headers.containsKey('Authorization'))
            .every((request) => request.url.host == 'allsafe.example.test'),
        isTrue,
      );
      expect(requests.every((request) => !request.followRedirects), isTrue);
      expect(api.isSignedIn, isFalse);
    },
  );

  for (final source in ['qr', 'url']) {
    test(
      '$source scan includes exact source and stable caller request id',
      () async {
        final requests = <http.Request>[];
        final client = MockClient((request) async {
          requests.add(request);
          return request.url.path.endsWith('/login') ? _login() : _scan();
        });
        final api = _service(client);
        addTearDown(api.dispose);
        api.useAllsafe('https://allsafe.example.test');
        await api.login(
          email: 'member@example.test',
          password: 'test-password',
        );
        final result = await api.analyzeUrl(
          'https://example.test/',
          source: source,
          clientRequestId: _requestId,
        );

        expect(requests.last.url.path, '/api/v1/phishcatch/scans');
        expect(jsonDecode(requests.last.body), {
          'url': 'https://example.test/',
          'source': source,
          'client_request_id': _requestId,
        });
        expect(result.centralScanId, 'cbfb7a6c-c012-4417-91fc-3a70e9d5a9a9');
        expect(result.isClean, isTrue);
      },
    );
  }

  test(
    '401 clears session and prevents a scan from falling back to standalone',
    () async {
      final requests = <http.Request>[];
      final api = _service(
        MockClient((request) async {
          requests.add(request);
          return request.url.path.endsWith('/login')
              ? _login()
              : http.Response('unsafe server body $_token', 401);
        }),
      );
      addTearDown(api.dispose);
      api.useAllsafe('https://allsafe.example.test');
      await api.login(email: 'member@example.test', password: 'test-password');

      await expectLater(
        api.analyzeUrl('https://example.test/'),
        throwsA(
          isA<ApiException>()
              .having((e) => e.statusCode, 'status', 401)
              .having(
                (e) => e.toString().contains(_token),
                'no token disclosure',
                isFalse,
              ),
        ),
      );
      expect(api.isSignedIn, isFalse);
      await expectLater(
        api.analyzeUrl('https://example.test/'),
        throwsA(isA<ApiException>()),
      );
      expect(requests, hasLength(2));
      expect(
        requests.every((request) => request.url.host == 'allsafe.example.test'),
        isTrue,
      );
    },
  );

  test('logout clears local session even if remote logout fails', () async {
    final api = _service(
      MockClient(
        (request) async => request.url.path.endsWith('/login')
            ? _login()
            : http.Response('private body', 503),
      ),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await api.login(email: 'member@example.test', password: 'test-password');

    await expectLater(api.logout(), throwsA(isA<ApiException>()));
    expect(api.isSignedIn, isFalse);
    expect(api.currentUser, isNull);
  });

  test(
    'mode and server changes clear session; a new instance has no session',
    () async {
      final client = MockClient((_) async => _login());
      final api = _service(client);
      final restarted = _service(client);
      addTearDown(api.dispose);
      addTearDown(restarted.dispose);
      api.useAllsafe('https://allsafe.example.test');
      await api.login(email: 'member@example.test', password: 'test-password');
      expect(restarted.isSignedIn, isFalse);
      api.useAllsafe('https://other.example.test');
      expect(api.isSignedIn, isFalse);
      await api.login(email: 'member@example.test', password: 'test-password');
      api.useStandalone();
      expect(api.isSignedIn, isFalse);
    },
  );

  test(
    'late login response cannot restore a session after connection changes',
    () async {
      final response = Completer<http.Response>();
      final started = Completer<void>();
      final api = _service(
        MockClient((_) {
          started.complete();
          return response.future;
        }),
      );
      addTearDown(api.dispose);
      api.useAllsafe('https://allsafe.example.test');
      final login = api.login(
        email: 'member@example.test',
        password: 'test-password',
      );
      await started.future;
      api.useStandalone();
      response.complete(_login());

      await expectLater(login, throwsA(isA<ApiException>()));
      expect(api.isSignedIn, isFalse);
    },
  );

  test('retry is explicit and can reuse the same client request id', () async {
    final scans = <http.Request>[];
    final api = _service(
      MockClient((request) async {
        if (request.url.path.endsWith('/login')) return _login();
        scans.add(request);
        if (scans.length == 1) {
          throw http.ClientException('unsafe details $_token');
        }
        return _scan();
      }),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await api.login(email: 'member@example.test', password: 'test-password');

    await expectLater(
      api.analyzeUrl('https://example.test/', clientRequestId: _requestId),
      throwsA(isA<ApiException>()),
    );
    expect(scans, hasLength(1));
    await api.analyzeUrl('https://example.test/', clientRequestId: _requestId);
    expect(scans, hasLength(2));
    expect(
      scans.map((request) => jsonDecode(request.body)['client_request_id']),
      everyElement(_requestId),
    );
  });

  test(
    'missing central analysis is a failed unknown scan with no probabilities',
    () async {
      final api = _service(
        MockClient(
          (request) async => request.url.path.endsWith('/login')
              ? _login()
              : http.Response(
                  jsonEncode({
                    'id': 'test-scan',
                    'scan_status': 'failed',
                    'analysis': null,
                  }),
                  201,
                ),
        ),
      );
      addTearDown(api.dispose);
      api.useAllsafe('https://allsafe.example.test');
      await api.login(email: 'member@example.test', password: 'test-password');

      final result = await api.analyzeUrl('https://example.test/');
      expect(result.isUnknown, isTrue);
      expect(result.isClean, isFalse);
      expect(result.scanStatus, 'failed');
      expect(result.maliciousPercent, isNull);
      expect(result.cleanPercent, isNull);
    },
  );

  test('account lookup uses shared auth/me endpoint', () async {
    final requests = <http.Request>[];
    final api = _service(
      MockClient((request) async {
        requests.add(request);
        return request.url.path.endsWith('/login')
            ? _login()
            : http.Response('{"email":"member@example.test"}', 200);
      }),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await api.login(email: 'member@example.test', password: 'test-password');
    expect((await api.me())['email'], 'member@example.test');
    expect(requests.last.url.path, '/api/v1/auth/me');
    expect(requests.last.method, 'GET');
  });

  test('unavailable probability does not become a zero score', () {
    final result = AnalysisResult.fromJson(_analysis());
    expect(result.maliciousProbability, isNull);
    expect(result.maliciousPercent, isNull);
    expect(result.cleanPercent, isNull);
  });

  test('partial clean verdict is downgraded and its scores are discarded', () {
    final data = _analysis(status: 'partial')
      ..addAll({
        'malicious_probability': 0.0,
        'clean_probability': 1.0,
        'confidence': 1.0,
      });
    final result = AnalysisResult.fromJson(data);
    expect(result.finalVerdict, 'unknown');
    expect(result.isClean, isFalse);
    expect(result.confidencePercent, isNull);
    expect(result.cleanPercent, isNull);
  });

  test('central partial status overrides upstream clean result', () {
    final result = AnalysisResult.fromJson(
      _analysis(),
      scanStatusOverride: 'partial',
    );
    expect(result.isClean, isFalse);
    expect(result.isUnknown, isTrue);
  });

  test('legacy response without completion contract cannot assert clean', () {
    final data = _analysis()..remove('contract_version');
    expect(AnalysisResult.fromJson(data).isClean, isFalse);
  });

  test('completed header with unavailable stage cannot assert clean', () {
    final data = _analysis();
    data['stages'] = [
      {'scanner': 'test', 'verdict': 'clean', 'status': 'unavailable'},
    ];
    expect(AnalysisResult.fromJson(data).isClean, isFalse);
  });

  test('completed ML with skipped HTML cannot assert clean or show scores', () {
    final data = _analysis()
      ..addAll({
        'malicious_probability': 0.0,
        'clean_probability': 1.0,
        'confidence': 1.0,
      });
    data['stages'] = [
      {'scanner': 'ML', 'verdict': 'clean', 'status': 'completed'},
      {'scanner': 'HTML', 'verdict': 'unknown', 'status': 'skipped'},
    ];
    final result = AnalysisResult.fromJson(data);
    expect(result.isClean, isFalse);
    expect(result.finalVerdict, 'unknown');
    expect(result.scanStatus, 'partial');
    expect(result.confidencePercent, isNull);
    expect(result.maliciousPercent, isNull);
    expect(result.cleanPercent, isNull);
  });

  test(
    'credible malicious verdict remains visible when another stage failed',
    () {
      final result = AnalysisResult.fromJson(
        _analysis(status: 'partial', verdict: 'malicious'),
      );
      expect(result.isMalicious, isTrue);
      expect(result.isClean, isFalse);
      expect(result.cleanPercent, isNull);
    },
  );

  test('missing batch or observation risk does not become zero', () {
    expect(
      BatchAnalysisItem.fromJson({
        'index': 0,
        'input': 'example.test',
        'final_verdict': 'unknown',
      }).riskPercent,
      isNull,
    );
    expect(
      AdminObservationItem.fromJson({
        'id': 1,
        'url': 'example.test',
        'final_verdict': 'unknown',
      }).riskPercent,
      isNull,
    );
  });

  for (final server in [
    'http://allsafe.example',
    'https://user:pass@allsafe.example',
    'https://allsafe.example/api',
    'https://allsafe.example?token=secret',
    'https://allsafe.example#fragment',
  ]) {
    test('unsafe server origin is rejected: $server', () {
      expect(
        () => ApiService.parseServerOrigin(server, allowDevelopmentHttp: true),
        throwsA(isA<ApiException>()),
      );
    });
  }

  test('Android emulator HTTP requires explicit development opt-in', () {
    expect(
      () => ApiService.parseServerOrigin('http://10.0.2.2:8000'),
      throwsA(isA<ApiException>()),
    );
    expect(
      ApiService.parseServerOrigin(
        'http://10.0.2.2:8000',
        allowDevelopmentHttp: true,
      ).host,
      '10.0.2.2',
    );
  });

  test('new request ids use UUID version 4 format', () {
    final first = ApiService.newClientRequestId();
    expect(
      first,
      matches(
        RegExp(
          r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        ),
      ),
    );
    expect(ApiService.newClientRequestId(), isNot(first));
  });
}
