import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:google_fonts/google_fonts.dart';
import '../theme/app_theme.dart';

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen>
    with SingleTickerProviderStateMixin {
  late MobileScannerController _cameraController;
  late AnimationController _animController;
  late Animation<double> _scanLineAnimation;
  bool _hasScanned = false;

  @override
  void initState() {
    super.initState();
    _cameraController = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
    );
    _animController = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);
    _scanLineAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(parent: _animController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _cameraController.dispose();
    _animController.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_hasScanned) return;
    final barcodes = capture.barcodes;
    if (barcodes.isEmpty) return;

    final rawValue = barcodes.first.rawValue;
    if (rawValue == null || rawValue.isEmpty) return;

    setState(() => _hasScanned = true);
    _cameraController.stop();
    Navigator.of(context).pop(rawValue);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bgDark,
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        leading: IconButton(
          icon: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppColors.glassWhite,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppColors.glassBorder),
            ),
            child: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          ),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: Text(
          'QR Scanner',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
        actions: [
          IconButton(
            icon: Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppColors.glassWhite,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.glassBorder),
              ),
              child: ValueListenableBuilder(
                valueListenable: _cameraController,
                builder: (context, state, child) {
                  return Icon(
                    state.torchState == TorchState.on
                        ? Icons.flash_on_rounded
                        : Icons.flash_off_rounded,
                    size: 18,
                    color: state.torchState == TorchState.on
                        ? AppColors.warning
                        : AppColors.textSecondary,
                  );
                },
              ),
            ),
            onPressed: () => _cameraController.toggleTorch(),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: Stack(
        children: [
          // Camera
          MobileScanner(
            controller: _cameraController,
            onDetect: _onDetect,
          ),

          // Dark overlay with transparent center
          _buildOverlay(),

          // Scan line animation
          _buildScanLine(),

          // Bottom instructions
          _buildBottomBar(),
        ],
      ),
    );
  }

  Widget _buildOverlay() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final scanSize = constraints.maxWidth * 0.7;
        final left = (constraints.maxWidth - scanSize) / 2;
        final top = (constraints.maxHeight - scanSize) / 2 - 40;

        return Stack(
          children: [
            // Top dark
            Positioned(
              top: 0, left: 0, right: 0, height: top,
              child: Container(color: AppColors.bgDark.withValues(alpha: 0.7)),
            ),
            // Bottom dark
            Positioned(
              top: top + scanSize, left: 0, right: 0, bottom: 0,
              child: Container(color: AppColors.bgDark.withValues(alpha: 0.7)),
            ),
            // Left dark
            Positioned(
              top: top, left: 0, width: left, height: scanSize,
              child: Container(color: AppColors.bgDark.withValues(alpha: 0.7)),
            ),
            // Right dark
            Positioned(
              top: top, right: 0, width: left, height: scanSize,
              child: Container(color: AppColors.bgDark.withValues(alpha: 0.7)),
            ),
            // Corner brackets
            Positioned(
              top: top, left: left,
              child: _buildCorner(Alignment.topLeft),
            ),
            Positioned(
              top: top, right: left,
              child: _buildCorner(Alignment.topRight),
            ),
            Positioned(
              top: top + scanSize - 40, left: left,
              child: _buildCorner(Alignment.bottomLeft),
            ),
            Positioned(
              top: top + scanSize - 40, right: left,
              child: _buildCorner(Alignment.bottomRight),
            ),
          ],
        );
      },
    );
  }

  Widget _buildCorner(Alignment alignment) {
    final isTop = alignment == Alignment.topLeft || alignment == Alignment.topRight;
    final isLeft = alignment == Alignment.topLeft || alignment == Alignment.bottomLeft;

    return SizedBox(
      width: 40,
      height: 40,
      child: CustomPaint(
        painter: _CornerPainter(
          isTop: isTop,
          isLeft: isLeft,
          color: AppColors.accent,
        ),
      ),
    );
  }

  Widget _buildScanLine() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final scanSize = constraints.maxWidth * 0.7;
        final left = (constraints.maxWidth - scanSize) / 2;
        final top = (constraints.maxHeight - scanSize) / 2 - 40;

        return AnimatedBuilder(
          animation: _scanLineAnimation,
          builder: (context, child) {
            return Positioned(
              top: top + (scanSize * _scanLineAnimation.value),
              left: left + 10,
              child: Container(
                width: scanSize - 20,
                height: 2,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      Colors.transparent,
                      AppColors.accent.withValues(alpha: 0.8),
                      AppColors.accent,
                      AppColors.accent.withValues(alpha: 0.8),
                      Colors.transparent,
                    ],
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: AppColors.accent.withValues(alpha: 0.5),
                      blurRadius: 12,
                      spreadRadius: 4,
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildBottomBar() {
    return Positioned(
      bottom: 0,
      left: 0,
      right: 0,
      child: Container(
        padding: const EdgeInsets.fromLTRB(24, 30, 24, 48),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Colors.transparent,
              AppColors.bgDark.withValues(alpha: 0.9),
              AppColors.bgDark,
            ],
          ),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
              decoration: BoxDecoration(
                color: AppColors.glassWhite,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: AppColors.glassBorder),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.qr_code_scanner_rounded,
                      color: AppColors.accent, size: 20),
                  const SizedBox(width: 10),
                  Text(
                    'Align QR code within the frame',
                    style: GoogleFonts.inter(
                      color: AppColors.textSecondary,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CornerPainter extends CustomPainter {
  final bool isTop;
  final bool isLeft;
  final Color color;

  _CornerPainter({
    required this.isTop,
    required this.isLeft,
    required this.color,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = 3
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;

    final path = Path();
    const length = 25.0;

    if (isTop && isLeft) {
      path.moveTo(0, length);
      path.lineTo(0, 5);
      path.quadraticBezierTo(0, 0, 5, 0);
      path.lineTo(length, 0);
    } else if (isTop && !isLeft) {
      path.moveTo(size.width - length, 0);
      path.lineTo(size.width - 5, 0);
      path.quadraticBezierTo(size.width, 0, size.width, 5);
      path.lineTo(size.width, length);
    } else if (!isTop && isLeft) {
      path.moveTo(0, size.height - length);
      path.lineTo(0, size.height - 5);
      path.quadraticBezierTo(0, size.height, 5, size.height);
      path.lineTo(length, size.height);
    } else {
      path.moveTo(size.width, size.height - length);
      path.lineTo(size.width, size.height - 5);
      path.quadraticBezierTo(size.width, size.height, size.width - 5, size.height);
      path.lineTo(size.width - length, size.height);
    }

    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
