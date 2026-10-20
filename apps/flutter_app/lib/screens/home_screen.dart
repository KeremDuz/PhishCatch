import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../services/allsafe_api_service.dart';
import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';
import 'qr_scanner_screen.dart';
import 'result_screen.dart';

class HomeScreen extends StatefulWidget {
  final ApiService? api;
  final FilePicker? filePicker;
  final Future<BatchAnalysisResult> Function({
    required Uint8List bytes,
    required String filename,
  })?
  analyzeUrlFile;
  const HomeScreen({super.key, this.api, this.filePicker, this.analyzeUrlFile});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _urlController = TextEditingController();
  final _urlFocusNode = FocusNode();
  bool _isLoading = false;
  String? _errorMessage;
  String? _pendingRequestId;
  String? _pendingRequestUrl;
  String? _pendingRequestSource;
  String _inputSource = 'url';
  ApiService get _api => widget.api ?? ApiService.shared;

  @override
  void dispose() {
    _urlController.dispose();
    _urlFocusNode.dispose();
    super.dispose();
  }

  Future<void> _analyzeUrl(String input, {String? source}) async {
    final url = input.trim();
    final scanSource = source ?? _inputSource;
    if (url.isEmpty) {
      setState(
        () => _errorMessage = 'Kontrol etmek istediğiniz bağlantıyı girin.',
      );
      _urlFocusNode.requestFocus();
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      if (_pendingRequestUrl != url || _pendingRequestSource != scanSource) {
        _pendingRequestId = ApiService.newClientRequestId();
        _pendingRequestUrl = url;
        _pendingRequestSource = scanSource;
      }
      final result = await _api.analyzeUrl(
        url,
        source: scanSource,
        clientRequestId: _pendingRequestId ??= ApiService.newClientRequestId(),
      );
      _pendingRequestId = _pendingRequestUrl = _pendingRequestSource = null;
      if (!mounted) return;
      setState(() => _isLoading = false);
      await Navigator.of(context).push(
        MaterialPageRoute<void>(builder: (_) => ResultScreen(result: result)),
      );
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _errorMessage = error is ApiException
            ? error.message
            : 'Analiz tamamlanamadı. Bağlantınızı kontrol edip yeniden deneyin.';
      });
    }
  }

  Future<void> _openQrScanner() async {
    if (_isLoading) return;
    final value = await Navigator.of(
      context,
    ).push<String>(MaterialPageRoute(builder: (_) => const QrScannerScreen()));
    if (!mounted || value == null) return;
    _urlController.text = value;
    _inputSource = 'qr';
    await _analyzeUrl(value, source: 'qr');
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: SafeArea(
      child: LayoutBuilder(
        builder: (context, constraints) => Align(
          alignment: Alignment.topCenter,
          child: SingleChildScrollView(
            padding: EdgeInsets.fromLTRB(
              24,
              constraints.maxWidth >= 700 ? 72 : 36,
              24,
              36,
            ),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Align(
                    alignment: Alignment.centerLeft,
                    child: AppBrand(),
                  ),
                  const SizedBox(height: 48),
                  const Text(
                    'Bağlantıyı kontrol et',
                    style: TextStyle(
                      fontSize: 28,
                      height: 1.2,
                      fontWeight: FontWeight.w700,
                      letterSpacing: -0.7,
                    ),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Bir adres gir veya QR kod okut.',
                    style: TextStyle(
                      fontSize: 15,
                      height: 1.5,
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 28),
                  TextField(
                    key: const ValueKey('url-input'),
                    controller: _urlController,
                    focusNode: _urlFocusNode,
                    enabled: !_isLoading,
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    enableSuggestions: false,
                    textInputAction: TextInputAction.search,
                    decoration: const InputDecoration(
                      labelText: 'Bağlantı',
                      hintText: 'https://example.com',
                    ),
                    onChanged: (_) => _inputSource = 'url',
                    onSubmitted: _isLoading
                        ? null
                        : (value) => _analyzeUrl(value),
                  ),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: _isLoading
                        ? null
                        : () => _analyzeUrl(_urlController.text),
                    child: _isLoading
                        ? Semantics(
                            liveRegion: true,
                            child: const Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                ),
                                SizedBox(width: 12),
                                Text('Analiz ediliyor…'),
                              ],
                            ),
                          )
                        : const Text('Analiz et'),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: _isLoading ? null : _openQrScanner,
                    icon: const Icon(Icons.qr_code_scanner, size: 20),
                    label: const Text('QR kod tara'),
                  ),
                  if (_errorMessage != null) ...[
                    const SizedBox(height: 20),
                    NoticeCard(
                      message: _errorMessage!,
                      color: AppColors.danger,
                      icon: Icons.error_outline,
                    ),
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
