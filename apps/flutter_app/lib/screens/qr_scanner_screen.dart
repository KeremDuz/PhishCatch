import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});
  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen>
    with WidgetsBindingObserver {
  late final MobileScannerController _controller;
  bool _hasResult = false;
  bool _foreground = true;
  Future<void> _cameraOperation = Future<void>.value();
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _controller = MobileScannerController(
      autoStart: false,
      facing: CameraFacing.back,
      formats: const [BarcodeFormat.qrCode],
      detectionSpeed: DetectionSpeed.noDuplicates,
    );
    WidgetsBinding.instance.addPostFrameCallback(
      (_) => unawaited(_startCamera()),
    );
  }

  Future<void> _startCamera() {
    // Serialize lifecycle changes, permission prompts, retry and result closure.
    // A late start must never leave the camera active in the background.
    _cameraOperation = _cameraOperation.then((_) async {
      if (!mounted || _hasResult || !_foreground) {
        await _stopCamera();
        return;
      }
      try {
        await _controller.start();
        if (!mounted || !_foreground || _hasResult) await _stopCamera();
        if (mounted) {
          setState(
            () => _errorMessage = _controller.value.error == null
                ? null
                : _cameraErrorText(_controller.value.error!),
          );
        }
      } on MobileScannerException catch (error) {
        if (mounted) setState(() => _errorMessage = _cameraErrorText(error));
      } catch (_) {
        if (mounted) {
          setState(
            () => _errorMessage =
                'Kamera başlatılamadı. İzinleri kontrol edip yeniden deneyin.',
          );
        }
      }
    });
    return _cameraOperation;
  }

  Future<void> _stopCamera() async {
    try {
      await _controller.stop();
    } on MobileScannerException {
      /* The camera may already be stopped by the platform. */
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _foreground = state == AppLifecycleState.resumed;
    unawaited(_startCamera());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _hasResult = true;
    unawaited(_cameraOperation.whenComplete(() => _controller.dispose()));
    super.dispose();
  }

  Future<void> _handleDetect(BarcodeCapture capture) async {
    if (_hasResult || !_foreground) return;
    String? value;
    for (final code in capture.barcodes) {
      final raw = code.rawValue?.trim();
      if (raw != null && raw.isNotEmpty) {
        value = raw;
        break;
      }
    }
    if (value == null) return;
    final uri = Uri.tryParse(value.contains('://') ? value : 'https://$value');
    if (uri == null ||
        !['http', 'https'].contains(uri.scheme.toLowerCase()) ||
        uri.host.isEmpty ||
        !uri.host.contains('.') ||
        RegExp(r'\s').hasMatch(value)) {
      setState(
        () => _errorMessage =
            'Bu QR kod bir web bağlantısı içermiyor. Başka bir kod okutun.',
      );
      return;
    }
    _hasResult = true;
    await _startCamera();
    if (mounted) Navigator.of(context).pop(value);
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('QR kod tara'),
      leading: IconButton(
        tooltip: 'Kapat',
        onPressed: () => Navigator.of(context).pop(),
        icon: const Icon(Icons.close),
      ),
    ),
    body: SafeArea(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 16, 20, 32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'Kodu çerçeveye yerleştirin',
                  style: TextStyle(
                    fontSize: 23,
                    fontWeight: FontWeight.w700,
                    letterSpacing: -0.5,
                  ),
                ),
                const SizedBox(height: 24),
                AspectRatio(
                  aspectRatio: 1,
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(20),
                    child: Stack(
                      fit: StackFit.expand,
                      children: [
                        MobileScanner(
                          controller: _controller,
                          fit: BoxFit.cover,
                          onDetect: _handleDetect,
                          onDetectError: (_, _) {
                            if (mounted) {
                              setState(
                                () => _errorMessage =
                                    'QR kod okunamadı. Kodu aydınlık bir ortamda sabit tutun.',
                              );
                            }
                          },
                          errorBuilder: (_, error) => _cameraError(error),
                          placeholderBuilder: (_) => const ColoredBox(
                            color: AppColors.bgCardLight,
                            child: Center(child: CircularProgressIndicator()),
                          ),
                          overlayBuilder: (_, _) => IgnorePointer(
                            child: Padding(
                              padding: const EdgeInsets.all(36),
                              child: DecoratedBox(
                                decoration: BoxDecoration(
                                  borderRadius: BorderRadius.circular(16),
                                  border: Border.all(
                                    color: Colors.white.withValues(alpha: 0.85),
                                    width: 2,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                        Positioned(
                          top: 12,
                          right: 12,
                          child: ValueListenableBuilder<MobileScannerState>(
                            valueListenable: _controller,
                            builder: (context, state, _) => IconButton.filled(
                              tooltip: 'Kamera değiştir',
                              onPressed:
                                  state.isInitialized &&
                                      state.hasCameraPermission &&
                                      (state.availableCameras ?? 2) > 1
                                  ? () async {
                                      try {
                                        await _controller.switchCamera();
                                      } on MobileScannerException {
                                        if (mounted) {
                                          setState(
                                            () => _errorMessage =
                                                'Diğer kamera açılamadı.',
                                          );
                                        }
                                      }
                                    }
                                  : null,
                              style: IconButton.styleFrom(
                                backgroundColor: Colors.black.withValues(
                                  alpha: 0.65,
                                ),
                                foregroundColor: Colors.white,
                              ),
                              icon: const Icon(Icons.cameraswitch_outlined),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                if (_errorMessage != null &&
                    _controller.value.error == null) ...[
                  const SizedBox(height: 16),
                  NoticeCard(message: _errorMessage!),
                ],
                if (_errorMessage != null) ...[
                  const SizedBox(height: 20),
                  OutlinedButton.icon(
                    onPressed: _startCamera,
                    icon: const Icon(Icons.refresh, size: 20),
                    label: const Text('Kamerayı yeniden dene'),
                  ),
                ],
                const SizedBox(height: 8),
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Bağlantıyı elle gir'),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );

  String _cameraErrorText(MobileScannerException error) =>
      error.errorCode == MobileScannerErrorCode.permissionDenied
      ? 'Kamera izni verilmedi. Cihaz veya tarayıcı ayarlarından kamera iznini açın, ardından yeniden deneyin.'
      : 'Kamera açılamadı. Kameranın başka bir uygulamada kullanılmadığını kontrol edin.';
  Widget _cameraError(MobileScannerException error) => ColoredBox(
    color: AppColors.bgCardLight,
    child: Padding(
      padding: const EdgeInsets.all(28),
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(
              Icons.videocam_off_outlined,
              color: AppColors.textMuted,
              size: 40,
            ),
            const SizedBox(height: 16),
            const Text(
              'Kamera kullanılamıyor',
              style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 10),
            Text(
              _cameraErrorText(error),
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.6,
              ),
            ),
          ],
        ),
      ),
    ),
  );
}
