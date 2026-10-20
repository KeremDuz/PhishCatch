import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../services/allsafe_api_service.dart';
import '../services/api_service.dart';
import '../widgets/common_widgets.dart';
import 'batch_result_screen.dart';

/// Legacy standalone tools stay separate from the consumer scan flow.
class StandaloneToolsScreen extends StatefulWidget {
  final ApiService? api;
  final FilePicker? filePicker;
  final Future<BatchAnalysisResult> Function({
    required Uint8List bytes,
    required String filename,
  })?
  analyzeUrlFile;
  const StandaloneToolsScreen({
    super.key,
    this.api,
    this.filePicker,
    this.analyzeUrlFile,
  });
  @override
  State<StandaloneToolsScreen> createState() => _StandaloneToolsScreenState();
}

class _StandaloneToolsScreenState extends State<StandaloneToolsScreen> {
  bool _isLoading = false;
  String? _errorMessage;
  ApiService get _api => widget.api ?? ApiService.shared;
  bool get _canUseStandalone => !_api.isAllsafe && !_api.managedOnly;
  static const _maxBatchBytes = 512 * 1024;

  Future<void> _pickAndAnalyzeFile() async {
    if (_isLoading || !_canUseStandalone) return;
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      final picked = await (widget.filePicker ?? FilePicker.platform).pickFiles(
        type: FileType.custom,
        allowedExtensions: const ['txt', 'csv'],
        allowMultiple: false,
        withData: false,
        withReadStream: true,
      );
      if (!mounted ||
          !_canUseStandalone ||
          picked == null ||
          picked.files.isEmpty) {
        return;
      }
      final file = picked.files.single;
      if (!const ['txt', 'csv'].contains(file.extension?.toLowerCase())) {
        throw const ApiException(
          'TXT veya CSV biçiminde bir URL listesi seçin.',
        );
      }
      if (file.size > _maxBatchBytes) {
        throw const ApiException('Dosya en fazla 512 KB olmalıdır.');
      }
      final content = BytesBuilder(copy: false);
      if (file.bytes != null) {
        if (file.bytes!.length > _maxBatchBytes) {
          throw const ApiException('Dosya en fazla 512 KB olmalıdır.');
        }
        content.add(file.bytes!);
      } else if (file.readStream != null) {
        await for (final chunk in file.readStream!) {
          if (!mounted || !_canUseStandalone) return;
          if (content.length + chunk.length > _maxBatchBytes) {
            throw const ApiException('Dosya en fazla 512 KB olmalıdır.');
          }
          content.add(chunk);
        }
      } else {
        throw const ApiException('Dosya okunamadı. Başka bir dosya seçin.');
      }
      if (content.isEmpty) throw const ApiException('Seçilen dosya boş.');
      if (!mounted || !_canUseStandalone) return;
      final analyze =
          widget.analyzeUrlFile ?? PhishCatchApiService.analyzeUrlFile;
      final result = await analyze(
        bytes: content.takeBytes(),
        filename: file.name,
      );
      if (!mounted || !_canUseStandalone) return;
      setState(() => _isLoading = false);
      Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (_) => BatchResultScreen(result: result),
        ),
      );
    } catch (error) {
      if (mounted) {
        setState(
          () => _errorMessage = error is ApiException
              ? error.message
              : 'Toplu analiz tamamlanamadı. Dosyayı ve sunucu bağlantısını kontrol edin.',
        );
      }
    } finally {
      if (mounted && _isLoading) {
        setState(() => _isLoading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Araçlar')),
    body: SafeArea(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: AnimatedBuilder(
              animation: _api,
              builder: (context, _) => Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (_canUseStandalone) ...[
                    OutlinedButton.icon(
                      onPressed: _isLoading ? null : _pickAndAnalyzeFile,
                      icon: _isLoading
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.upload_file_outlined),
                      label: Text(
                        _isLoading ? 'Dosya işleniyor…' : 'Toplu URL analizi',
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'TXT / CSV · En fazla 512 KB',
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 16),
                    TextButton(
                      onPressed: _isLoading
                          ? null
                          : () => Navigator.of(context).pushNamed('/admin'),
                      child: const Text('Bağımsız yönetim'),
                    ),
                  ],
                  if (_errorMessage != null) ...[
                    const SizedBox(height: 16),
                    NoticeCard(message: _errorMessage!),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    ),
  );
}
