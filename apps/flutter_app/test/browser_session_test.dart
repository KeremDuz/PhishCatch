import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';

const _origin = 'https://allsafe.example.test';
const _user = {'id': 'test-user', 'email': 'member@example.test'};

void main() {
  test(
    'browser logout failure keeps session until revocation is confirmed',
    () async {
      var unavailable = true;
      final api = ApiService(
        managedOnly: true,
        allsafeBaseUrl: _origin,
        browserOrigin: _origin,
        client: MockClient((request) async {
          if (request.url.path.endsWith('/me')) {
            return http.Response(jsonEncode(_user), 200);
          }
          return http.Response('', unavailable ? 503 : 204);
        }),
      );
      addTearDown(api.dispose);
      await api.restoreWebSession();
      await expectLater(api.logout(), throwsA(isA<ApiException>()));
      expect(api.isSignedIn, isTrue);
      unavailable = false;
      await api.logout();
      expect(api.isSignedIn, isFalse);
    },
  );
  test(
    'managed client starts at configured ALLSAFE and cannot use standalone',
    () {
      final api = ApiService(managedOnly: true, allsafeBaseUrl: _origin);
      addTearDown(api.dispose);
      expect(api.isAllsafe, isTrue);
      expect(api.allsafeServer!.origin, _origin);
      expect(api.isSignedIn, isFalse);
      expect(api.useStandalone, throwsA(isA<ApiException>()));
      expect(api.isAllsafe, isTrue);
    },
  );

  test(
    'browser uses current origin, cookie login and CSRF, never bearer',
    () async {
      final requests = <http.Request>[];
      final api = ApiService(
        managedOnly: true,
        allsafeBaseUrl: 'https://unused-native-origin.example.test',
        browserOrigin: _origin,
        csrfToken: () => 'test-csrf-cookie',
        client: MockClient((request) async {
          requests.add(request);
          if (request.url.path.endsWith('/login')) {
            return http.Response(jsonEncode(_user), 200);
          }
          if (request.url.path.endsWith('/logout')) {
            return http.Response('', 204);
          }
          return http.Response(
            jsonEncode({'id': 'scan', 'analysis': null}),
            201,
          );
        }),
      );
      addTearDown(api.dispose);
      await api.login(email: 'member@example.test', password: 'test-password');
      await api.analyzeUrl('https://example.test', source: 'qr');
      await api.logout();
      expect(requests.map((r) => r.url.path), [
        '/api/v1/auth/login',
        '/api/v1/phishcatch/scans',
        '/api/v1/auth/logout',
      ]);
      expect(requests.every((r) => r.url.origin == _origin), isTrue);
      expect(
        requests.every((r) => !r.headers.containsKey('Authorization')),
        isTrue,
      );
      expect(requests[1].headers['X-CSRF-Token'], 'test-csrf-cookie');
      expect(requests[2].headers['X-CSRF-Token'], 'test-csrf-cookie');
      expect(api.isSignedIn, isFalse);
      expect(
        () => api.useAllsafe('https://other.example.test'),
        throwsA(isA<ApiException>()),
      );
    },
  );

  test(
    'browser restores only a server-confirmed session and handles revocation',
    () async {
      var revoked = false;
      final api = ApiService(
        managedOnly: true,
        allsafeBaseUrl: _origin,
        browserOrigin: _origin,
        client: MockClient(
          (request) async => revoked
              ? http.Response('', 401)
              : http.Response(jsonEncode(_user), 200),
        ),
      );
      addTearDown(api.dispose);
      await api.restoreWebSession();
      expect(api.isSignedIn, isTrue);
      revoked = true;
      await expectLater(api.me(), throwsA(isA<ApiException>()));
      expect(api.isSignedIn, isFalse);
    },
  );

  test(
    'server outage does not select a fallback or create a session',
    () async {
      final requests = <Uri>[];
      final api = ApiService(
        managedOnly: true,
        allsafeBaseUrl: _origin,
        client: MockClient((request) async {
          requests.add(request.url);
          throw http.ClientException('offline');
        }),
      );
      addTearDown(api.dispose);
      await expectLater(
        api.login(email: 'a@b.test', password: 'test-password'),
        throwsA(isA<ApiException>()),
      );
      expect(api.isSignedIn, isFalse);
      expect(api.isAllsafe, isTrue);
      expect(requests.single.origin, _origin);
      await expectLater(api.scanHistory(), throwsA(isA<ApiException>()));
      expect(requests, hasLength(1));
    },
  );

  test(
    'history uses authenticated API and never converts failure into empty data',
    () async {
      final requests = <http.Request>[];
      var denied = false;
      final api = ApiService(
        managedOnly: true,
        allsafeBaseUrl: _origin,
        browserOrigin: _origin,
        client: MockClient((request) async {
          requests.add(request);
          if (request.url.path.endsWith('/me')) {
            return http.Response(jsonEncode(_user), 200);
          }
          return denied
              ? http.Response('', 403)
              : http.Response('[{"id":"scan"}]', 200);
        }),
      );
      addTearDown(api.dispose);
      await api.restoreWebSession();
      expect((await api.scanHistory()).single['id'], 'scan');
      expect(requests.last.url.path, '/api/v1/phishcatch/scans');
      expect(requests.last.url.queryParameters['limit'], '50');
      denied = true;
      await expectLater(
        api.scanHistory(),
        throwsA(isA<ApiException>().having((e) => e.statusCode, 'status', 403)),
      );
    },
  );
}
