import 'dart:async';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phishcatch/screens/home_screen.dart';
import 'package:phishcatch/screens/standalone_tools_screen.dart';
import 'package:phishcatch/screens/batch_result_screen.dart';
import 'package:phishcatch/services/allsafe_api_service.dart';
import 'package:phishcatch/services/api_service.dart';
import 'package:phishcatch/theme/app_theme.dart';

void main() {
  testWidgets(
    'legacy tools retain batch analysis and a separate administration route',
    (tester) async {
      final api = ApiService(
        standaloneBaseUrl: 'https://standalone.example.test',
      );
      addTearDown(api.dispose);
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.lightTheme,
          home: StandaloneToolsScreen(api: api),
          routes: {
            '/admin': (_) =>
                const Scaffold(body: Text('Standalone admin route')),
          },
        ),
      );
      expect(find.text('Toplu URL analizi'), findsOneWidget);
      expect(find.text('Bağımsız yönetim'), findsOneWidget);
      await tester.ensureVisible(find.text('Bağımsız yönetim'));
      await tester.tap(find.text('Bağımsız yönetim'));
      await tester.pumpAndSettle();
      expect(find.text('Standalone admin route'), findsOneWidget);
    },
  );

  for (final managedOnly in [false, true]) {
    testWidgets(
      'ALLSAFE hides standalone actions when managedOnly=$managedOnly',
      (tester) async {
        final api = ApiService(
          managedOnly: managedOnly,
          allsafeBaseUrl: 'https://allsafe.example.test',
          standaloneBaseUrl: 'https://standalone.example.test',
        );
        addTearDown(api.dispose);
        await tester.pumpWidget(
          MaterialApp(
            theme: AppTheme.lightTheme,
            home: StandaloneToolsScreen(api: api),
          ),
        );
        expect(find.text('Toplu URL analizi'), findsNothing);
        expect(find.text('Bağımsız yönetim'), findsNothing);
      },
    );
  }

  testWidgets(
    'standalone file selection analyzes its bounded bytes and opens batch results',
    (tester) async {
      final bytes = Uint8List.fromList('https://example.test/\n'.codeUnits);
      final picker = _Picker(
        () async => FilePickerResult([
          PlatformFile(
            name: 'urls.csv',
            size: bytes.length,
            readStream: Stream.value(bytes),
          ),
        ]),
      );
      final api = ApiService(
        standaloneBaseUrl: 'https://standalone.example.test',
      );
      addTearDown(api.dispose);
      var analyzed = false;
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.lightTheme,
          home: StandaloneToolsScreen(
            api: api,
            filePicker: picker,
            analyzeUrlFile: ({required bytes, required filename}) async {
              analyzed = true;
              expect(filename, 'urls.csv');
              expect(String.fromCharCodes(bytes), 'https://example.test/\n');
              return BatchAnalysisResult(
                filename: filename,
                summary: BatchAnalysisSummary(
                  submitted: 1,
                  analyzed: 1,
                  malicious: 0,
                  clean: 1,
                  unknown: 0,
                  invalid: 0,
                ),
                results: [],
              );
            },
          ),
        ),
      );
      await tester.ensureVisible(find.text('Toplu URL analizi'));
      await tester.tap(find.text('Toplu URL analizi'));
      await tester.pumpAndSettle();
      expect(picker.type, FileType.custom);
      expect(picker.extensions, ['txt', 'csv']);
      expect(picker.streamRequested, isTrue);
      expect(picker.dataRequested, isFalse);
      expect(analyzed, isTrue);
      expect(find.byType(BatchResultScreen), findsOneWidget);
      expect(find.text('urls.csv'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'cancelled selection restores standalone controls without a request',
    (tester) async {
      final api = ApiService(
        standaloneBaseUrl: 'https://standalone.example.test',
      );
      addTearDown(api.dispose);
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.lightTheme,
          home: StandaloneToolsScreen(
            api: api,
            filePicker: _Picker(() async => null),
            analyzeUrlFile: ({required bytes, required filename}) async =>
                throw StateError('Cancelled selection must not upload'),
          ),
        ),
      );
      await tester.ensureVisible(find.text('Toplu URL analizi'));
      await tester.tap(find.text('Toplu URL analizi'));
      await tester.pumpAndSettle();
      expect(find.text('Toplu URL analizi'), findsOneWidget);
      expect(find.text('Dosya işleniyor…'), findsNothing);
      expect(
        tester
            .widget<OutlinedButton>(
              find.widgetWithText(OutlinedButton, 'Toplu URL analizi'),
            )
            .onPressed,
        isNotNull,
      );
    },
  );

  testWidgets('oversized file is rejected before uploading', (tester) async {
    final api = ApiService(
      standaloneBaseUrl: 'https://standalone.example.test',
    );
    addTearDown(api.dispose);
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        home: StandaloneToolsScreen(
          api: api,
          filePicker: _Picker(
            () async => FilePickerResult([
              PlatformFile(name: 'urls.txt', size: 512 * 1024 + 1),
            ]),
          ),
          analyzeUrlFile: ({required bytes, required filename}) async =>
              throw StateError('Oversized file must not upload'),
        ),
      ),
    );
    await tester.ensureVisible(find.text('Toplu URL analizi'));
    await tester.tap(find.text('Toplu URL analizi'));
    await tester.pumpAndSettle();
    expect(find.text('Dosya en fazla 512 KB olmalıdır.'), findsOneWidget);
    expect(find.byType(BatchResultScreen), findsNothing);
  });

  testWidgets('disposed home never uploads a delayed file selection', (
    tester,
  ) async {
    final selection = Completer<FilePickerResult?>();
    final api = ApiService(
      standaloneBaseUrl: 'https://standalone.example.test',
    );
    addTearDown(api.dispose);
    var uploads = 0;
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        home: StandaloneToolsScreen(
          api: api,
          filePicker: _Picker(() => selection.future),
          analyzeUrlFile: ({required bytes, required filename}) async {
            uploads++;
            throw StateError('Disposed home must not upload');
          },
        ),
      ),
    );
    await tester.ensureVisible(find.text('Toplu URL analizi'));
    await tester.tap(find.text('Toplu URL analizi'));
    await tester.pump();
    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    selection.complete(
      FilePickerResult([
        PlatformFile(name: 'urls.txt', size: 1, bytes: Uint8List.fromList([1])),
      ]),
    );
    await tester.pumpAndSettle();
    expect(uploads, 0);
    expect(tester.takeException(), isNull);
  });

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
      expect(find.text('Analiz et'), findsOneWidget);
      expect(find.text('QR kod tara'), findsOneWidget);
      expect(find.text('Giriş gerekli'), findsNothing);
      expect(find.byTooltip('Tarama geçmişi'), findsNothing);
      expect(find.text('ALLSAFE'), findsNothing);
      expect(find.text('allsafe.example.test'), findsNothing);
      expect(find.byTooltip('Bağlantı ve hesap'), findsNothing);
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
    await tester.ensureVisible(find.text('Analiz et'));
    await tester.tap(find.text('Analiz et'));
    await tester.pumpAndSettle();
    expect(
      find.text('Kontrol etmek istediğiniz bağlantıyı girin.'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });
}

class _Picker extends FilePicker {
  final Future<FilePickerResult?> Function() select;
  FileType? type;
  List<String>? extensions;
  bool? dataRequested;
  bool? streamRequested;
  _Picker(this.select);
  @override
  Future<FilePickerResult?> pickFiles({
    String? dialogTitle,
    String? initialDirectory,
    FileType type = FileType.any,
    List<String>? allowedExtensions,
    Function(FilePickerStatus)? onFileLoading,
    bool allowCompression = false,
    int compressionQuality = 0,
    bool allowMultiple = false,
    bool withData = false,
    bool withReadStream = false,
    bool lockParentWindow = false,
    bool readSequential = false,
  }) {
    this.type = type;
    extensions = allowedExtensions;
    dataRequested = withData;
    streamRequested = withReadStream;
    return select();
  }
}
