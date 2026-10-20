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
