import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phishcatch/screens/home_screen.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';
import 'package:phishcatch/theme/app_theme.dart';

void main() {
  for (final width in [320.0, 390.0, 768.0, 1440.0]) {
    testWidgets('URL and QR actions fit a $width logical-pixel viewport', (
      tester,
    ) async {
      tester.view.physicalSize = Size(width, 920);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final api = ApiService(
        standaloneBaseUrl: 'https://standalone.example.test',
      );
      addTearDown(api.dispose);
      api.useAllsafe('https://allsafe.example.test');
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.lightTheme,
          home: HomeScreen(api: api),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('PhishCatch'), findsOneWidget);
      expect(find.text('Bağlantıyı analiz et'), findsOneWidget);
      expect(find.text('QR kod tara'), findsOneWidget);
      expect(find.text('Giriş gerekli'), findsOneWidget);
      expect(find.byTooltip('Tarama geçmişi'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('large text and reduced motion retain the form and validation', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(320, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = ApiService(
      standaloneBaseUrl: 'https://standalone.example.test',
    );
    addTearDown(api.dispose);
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context).copyWith(
            textScaler: const TextScaler.linear(1.5),
            disableAnimations: true,
          ),
          child: child!,
        ),
        home: HomeScreen(api: api),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Bağlantıyı analiz et'));
    await tester.tap(find.text('Bağlantıyı analiz et'));
    await tester.pumpAndSettle();
    expect(
      find.text('Kontrol etmek istediğiniz bağlantıyı girin.'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });
}
