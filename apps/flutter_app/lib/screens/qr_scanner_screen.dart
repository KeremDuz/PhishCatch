import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter/foundation.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen> {
  late final MobileScannerController _controller;
  bool _hasResult = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _controller = MobileScannerController(
      facing: kIsWeb ? CameraFacing.front : CameraFacing.back,
      formats: const [BarcodeFormat.qrCode],
      detectionSpeed: DetectionSpeed.normal,
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _handleDetect(BarcodeCapture capture) async {
    if (_hasResult) return;

    String? value;
    for (final barcode in capture.barcodes) {
      final rawValue = barcode.rawValue?.trim();
      if (rawValue != null && rawValue.isNotEmpty) {
        value = rawValue;
        break;
      }
    }

    if (value == null) return;

    _hasResult = true;
    await _controller.stop();
    if (!mounted) return;
    Navigator.of(context).pop(value);
  }

  void _handleDetectError(Object error, StackTrace stackTrace) {
    if (!mounted) return;
    setState(() {
      _errorMessage = 'QR kod okunamadi. Kamerayi koda dogru tut.';
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bgDark,
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        leading: IconButton(
          onPressed: () => Navigator.of(context).pop(),
          icon: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppColors.bgSurface.withValues(alpha: 0.72),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.glassBorder),
            ),
            child: const Icon(Icons.close_rounded, size: 20),
          ),
        ),
        title: Text(
          'QR Tara',
          style: GoogleFonts.inter(fontWeight: FontWeight.w700),
        ),
      ),
      body: CyberBackdrop(
        dense: MediaQuery.of(context).size.width < 720,
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final isWide = constraints.maxWidth >= 720;
              return Center(
                child: SingleChildScrollView(
                  padding: EdgeInsets.fromLTRB(
                    isWide ? 48 : 24,
                    80,
                    isWide ? 48 : 24,
                    32,
                  ),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 520),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _buildScannerFrame(isWide),
                        const SizedBox(height: 18),
                        _buildScannerHint(),
                        if (_errorMessage != null) ...[
                          const SizedBox(height: 14),
                          _buildErrorMessage(),
                        ],
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Widget _buildScannerFrame(bool isWide) {
    final size = isWide ? 380.0 : 310.0;
    return Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            color: AppColors.bgCard.withValues(alpha: 0.82),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(color: Colors.white.withValues(alpha: 0.16)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.36),
                blurRadius: 34,
                offset: const Offset(0, 18),
              ),
              BoxShadow(
                color: AppColors.electric.withValues(alpha: 0.14),
                blurRadius: 34,
              ),
            ],
          ),
          clipBehavior: Clip.antiAlias,
          child: Stack(
            fit: StackFit.expand,
            children: [
              MobileScanner(
                controller: _controller,
                fit: BoxFit.cover,
                onDetect: _handleDetect,
                onDetectError: _handleDetectError,
                errorBuilder: (context, error) => _buildCameraError(error),
                placeholderBuilder: (context) => _buildCameraPlaceholder(),
              ),
              _buildScannerOverlay(),
              _buildScannerActions(),
            ],
          ),
        )
        .animate()
        .fadeIn(duration: 260.ms)
        .scale(
          begin: const Offset(0.96, 0.96),
          duration: 340.ms,
          curve: Curves.easeOutCubic,
        );
  }

  Widget _buildScannerOverlay() {
    return IgnorePointer(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: DecoratedBox(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: AppColors.electric.withValues(alpha: 0.72),
              width: 2,
            ),
          ),
          child: Center(
            child: Container(
              height: 2,
              margin: const EdgeInsets.symmetric(horizontal: 18),
              decoration: BoxDecoration(
                color: AppColors.electric.withValues(alpha: 0.78),
                boxShadow: [
                  BoxShadow(
                    color: AppColors.electric.withValues(alpha: 0.44),
                    blurRadius: 18,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildScannerActions() {
    return Positioned(
      right: 14,
      top: 14,
      child: ValueListenableBuilder<MobileScannerState>(
        valueListenable: _controller,
        builder: (context, state, child) {
          final canSwitch =
              state.isInitialized &&
              state.hasCameraPermission &&
              (state.availableCameras == null || state.availableCameras! > 1);
          return IconButton(
            tooltip: 'Kamera degistir',
            onPressed: canSwitch ? () => _controller.switchCamera() : null,
            style: IconButton.styleFrom(
              backgroundColor: Colors.black.withValues(alpha: 0.52),
              foregroundColor: Colors.white,
              disabledForegroundColor: Colors.white.withValues(alpha: 0.34),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            icon: const Icon(Icons.cameraswitch_rounded, size: 20),
          );
        },
      ),
    );
  }

  Widget _buildScannerHint() {
    return Text(
      'QR kodu kameranin ortasina getir.',
      textAlign: TextAlign.center,
      style: GoogleFonts.inter(
        color: AppColors.textSecondary,
        fontSize: 14,
        fontWeight: FontWeight.w600,
        height: 1.45,
      ),
    );
  }

  Widget _buildCameraPlaceholder() {
    return Container(
      color: AppColors.bgSurface,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 28,
              height: 28,
              child: CircularProgressIndicator(
                strokeWidth: 2.4,
                color: AppColors.electric.withValues(alpha: 0.86),
              ),
            ),
            const SizedBox(height: 14),
            Text(
              'Kamera baslatiliyor...',
              style: GoogleFonts.inter(
                color: AppColors.textSecondary,
                fontSize: 13,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCameraError(MobileScannerException error) {
    return Container(
      color: AppColors.bgSurface,
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.videocam_off_rounded, color: AppColors.danger, size: 42),
          const SizedBox(height: 14),
          Text(
            'Kamera acilamadi',
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(
              color: AppColors.textPrimary,
              fontSize: 16,
              fontWeight: FontWeight.w900,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Kamera iznini kontrol edip tekrar dene.',
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(
              color: AppColors.textSecondary,
              fontSize: 13,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorMessage() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: AppColors.danger.withValues(alpha: 0.09),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.danger.withValues(alpha: 0.28)),
      ),
      child: Row(
        children: [
          Icon(Icons.error_outline_rounded, color: AppColors.danger, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              _errorMessage!,
              style: GoogleFonts.inter(color: AppColors.danger, fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}
