import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';
import 'package:phishcatch/services/api_service.dart';

void main() {
  test(
    'anonymous URL and QR use only the consumer origin without credentials',
    () async {
      final requests = <http.Request>[];
      final api = ApiService(
        consumerMode: true,
        standaloneBaseUrl: 'https://public.example.test:8443',
        allsafeBaseUrl: 'https://private.example.test',
        client: MockClient((request) async {
          requests.add(request);
          return http.Response(
            jsonEncode({
              'contract_version': 'consumer-1',
              'url': 'https://example.com/',
              'final_verdict': 'clean',
              'scan_status': 'complete',
            }),
            200,
          );
        }),
      );
      addTearDown(api.dispose);
      for (final source in ['url', 'qr']) {
        final result = await api.analyzeUrl(
          'https://example.com/',
          source: source,
          clientRequestId: 'a4223910-6f0d-4f5e-95ce-e94e3fd272c7',
        );
        expect(result.isClean, isTrue);
        expect(result.stages, isEmpty);
        expect(result.maliciousProbability, isNull);
        expect(jsonDecode(requests.last.body)['source'], source);
      }
      expect(api.isAllsafe, isFalse);
      expect(api.isSignedIn, isFalse);
      expect(
        requests.every(
          (r) =>
              r.url.origin == 'https://public.example.test:8443' &&
              r.url.path == '/api/v1/public/analyze' &&
              !r.followRedirects &&
              !r.headers.containsKey('Authorization') &&
              !r.headers.containsKey('X-Integration-Key') &&
              !r.headers.containsKey('X-CSRF-Token'),
        ),
        isTrue,
      );
      expect(
        () => api.useAllsafe('https://private.example.test'),
        throwsA(isA<ApiException>()),
      );
    },
  );

  test(
    'consumer browser uses its own origin and never restores an ALLSAFE session',
    () async {
      final requests = <http.Request>[];
      final api = ApiService(
        consumerMode: true,
        browserOrigin: 'https://public.example.test:8443',
        standaloneBaseUrl: 'https://different.example.test',
        allsafeBaseUrl: 'https://private.example.test',
        client: MockClient((request) async {
          requests.add(request);
          return http.Response(
            jsonEncode({
              'contract_version': 'consumer-1',
              'url': 'https://example.com/',
              'final_verdict': 'unknown',
              'scan_status': 'partial',
            }),
            200,
          );
        }),
      );
      addTearDown(api.dispose);
      await api.restoreWebSession();
      expect(requests, isEmpty);
      await api.analyzeUrl('https://example.com/');
      expect(requests.single.url.origin, 'https://public.example.test:8443');
    },
  );

  test(
    'Pages consumer uses only the explicit HTTPS API without account credentials',
    () async {
      final requests = <http.Request>[];
      final api = ApiService(
        consumerMode: true,
        browserOrigin: 'https://keremduz.github.io',
        publicApiOrigin: 'https://public.example.test:8443',
        standaloneBaseUrl: 'https://ignored.example.test',
        allsafeBaseUrl: 'https://private.example.test',
        csrfToken: () => 'must-not-leave-managed-session',
        client: MockClient((request) async {
          requests.add(request);
          return http.Response(
            jsonEncode({
              'contract_version': 'consumer-1',
              'url': 'https://example.com/',
              'final_verdict': 'unknown',
              'scan_status': 'partial',
            }),
            200,
          );
        }),
      );
      addTearDown(api.dispose);
      await api.restoreWebSession();
      expect(requests, isEmpty);
      for (final source in ['url', 'qr']) {
        await api.analyzeUrl(
          'https://example.com/',
          source: source,
          clientRequestId: 'a4223910-6f0d-4f5e-95ce-e94e3fd272c7',
        );
        final request = requests.last;
        expect(request.url.origin, 'https://public.example.test:8443');
        expect(request.url.path, '/api/v1/public/analyze');
        expect(request.followRedirects, isFalse);
        expect(jsonDecode(request.body)['source'], source);
        expect(
          jsonDecode(request.body)['client_request_id'],
          'a4223910-6f0d-4f5e-95ce-e94e3fd272c7',
        );
        for (final name in [
          'authorization',
          'cookie',
          'x-integration-key',
          'x-csrf-token',
        ]) {
          expect(request.headers.containsKey(name), isFalse);
        }
      }
      expect(api.isSignedIn, isFalse);
      expect(api.isAllsafe, isFalse);
      expect(
        () => api.useAllsafe('https://different.example.test'),
        throwsA(isA<ApiException>()),
      );
    },
  );

  test('explicit public browser API requires a bare HTTPS origin', () {
    for (final origin in [
      'http://localhost:8001',
      'https://user:password@public.example.test',
      'https://public.example.test/api',
      'https://public.example.test?server=other',
      'https://public.example.test#server',
    ]) {
      expect(
        () => ApiService(
          consumerMode: true,
          allowDevelopmentHttp: true,
          browserOrigin: 'https://keremduz.github.io',
          publicApiOrigin: origin,
          client: MockClient((_) async => http.Response('', 500)),
        ),
        throwsA(isA<ApiException>()),
      );
    }
  });

  test(
    'managed browser ignores the public override and keeps its own origin',
    () async {
      final requests = <http.Request>[];
      final api = ApiService(
        managedOnly: true,
        browserOrigin: 'https://private.example.test',
        allsafeBaseUrl: 'https://ignored.example.test',
        publicApiOrigin: 'https://public.example.test:8443',
        client: MockClient((request) async {
          requests.add(request);
          return http.Response(
            jsonEncode({'email': 'member@example.test'}),
            200,
          );
        }),
      );
      addTearDown(api.dispose);
      await api.restoreWebSession();
      expect(api.allsafeServer!.origin, 'https://private.example.test');
      expect(requests.single.url.origin, 'https://private.example.test');
      expect(
        () => api.useAllsafe('https://public.example.test:8443'),
        throwsA(isA<ApiException>()),
      );
    },
  );

  test(
    'native consumer keeps its APK origin when a web override is present',
    () async {
      final requests = <http.Request>[];
      final api = ApiService(
        consumerMode: true,
        standaloneBaseUrl: 'https://native.example.test:8443',
        publicApiOrigin: 'https://web-only.example.test',
        client: MockClient((request) async {
          requests.add(request);
          return http.Response(
            jsonEncode({
              'contract_version': 'consumer-1',
              'url': 'https://example.com/',
              'final_verdict': 'unknown',
              'scan_status': 'partial',
            }),
            200,
          );
        }),
      );
      addTearDown(api.dispose);
      await api.analyzeUrl('https://example.com/', source: 'qr');
      expect(requests.single.url.origin, 'https://native.example.test:8443');
      expect(jsonDecode(requests.single.body)['source'], 'qr');
    },
  );

  test(
    'consumer response never turns incomplete or invalid data into clean',
    () {
      for (final status in ['partial', 'failed', 'invalid']) {
        final result = AnalysisResult.fromConsumerJson({
          'contract_version': 'consumer-1',
          'url': 'https://example.com/',
          'final_verdict': 'clean',
          'scan_status': status,
        });
        expect(result.isClean, isFalse);
        expect(result.isUnknown, isTrue);
      }
      final wrong = AnalysisResult.fromConsumerJson({
        'contract_version': '2',
        'url': 'https://example.com/',
        'final_verdict': 'clean',
        'scan_status': 'complete',
      });
      expect(wrong.isClean, isFalse);
      expect(wrong.scanStatus, 'failed');
      final malicious = AnalysisResult.fromConsumerJson({
        'contract_version': 'consumer-1',
        'url': 'https://example.com/',
        'final_verdict': 'malicious',
        'scan_status': 'partial',
      });
      expect(malicious.isMalicious, isTrue);
    },
  );
}
