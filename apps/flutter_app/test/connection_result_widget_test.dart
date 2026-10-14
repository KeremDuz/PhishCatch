import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:phishcatch/screens/connection_screen.dart';
import 'package:phishcatch/screens/result_screen.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';
import 'package:phishcatch/services/api_service.dart';

void main() {
  testWidgets('failed scan shows incomplete warning and unavailable scores', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: ResultScreen(
          result: AnalysisResult.unavailable('https://example.test/'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Tarama tamamlanamadi'), findsOneWidget);
    expect(find.text('Guvenli gorunuyor'), findsNothing);
    expect(find.text('—'), findsNWidgets(2));
    expect(find.text('0.0%'), findsNothing);
  });

  testWidgets('connection screen signs in and clears session on logout', (
    tester,
  ) async {
    final api = ApiService(
      client: MockClient((request) async {
        if (request.url.path.endsWith('/logout')) return http.Response('', 204);
        return http.Response(
          jsonEncode({
            'access_token': 'test-only-app-session',
            'token_type': 'bearer',
            'expires_in': 3600,
            'user': {'email': 'member@example.test'},
          }),
          200,
        );
      }),
    );
    addTearDown(api.dispose);
    api.useAllsafe('https://allsafe.example.test');
    await tester.pumpWidget(MaterialApp(home: ConnectionScreen(api: api)));
    await tester.enterText(find.byType(TextField).at(1), 'member@example.test');
    await tester.enterText(find.byType(TextField).at(2), 'test-password');
    await tester.ensureVisible(find.text('Giris yap'));
    await tester.tap(find.text('Giris yap'));
    await tester.pumpAndSettle();

    expect(api.isSignedIn, isTrue);
    expect(find.text('Giris yapildi: member@example.test'), findsOneWidget);
    await tester.ensureVisible(find.text('Cikis yap'));
    await tester.tap(find.text('Cikis yap'));
    await tester.pumpAndSettle();
    expect(api.isSignedIn, isFalse);
    expect(find.text('Kurum hesabiyla giris yapin.'), findsOneWidget);
  });
}
