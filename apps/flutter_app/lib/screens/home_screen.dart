import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:google_fonts/google_fonts.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';
import 'qr_scanner_screen.dart';
import 'result_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  final TextEditingController _urlController = TextEditingController();
  final FocusNode _urlFocusNode = FocusNode();
  bool _isLoading = false;
  String? _errorMessage;

  // Web'de sürekli animasyon = kasma. Sadece mobilde kullan.
  AnimationController? _bgAnimController;

  @override
  void initState() {
    super.initState();
    if (!kIsWeb) {
      _bgAnimController = AnimationController(
        duration: const Duration(seconds: 8),
        vsync: this,
      )..repeat();
    }
  }

  @override
  void dispose() {
    _urlController.dispose();
    _urlFocusNode.dispose();
    _bgAnimController?.dispose();
    super.dispose();
  }

  Future<void> _analyzeUrl(String url) async {
    if (url.trim().isEmpty) {
      setState(() => _errorMessage = 'Please enter a URL');
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final result = await PhishCatchApiService.analyzeUrl(url.trim());
      if (!mounted) return;
      setState(() => _isLoading = false);
      Navigator.of(context).push(
        PageRouteBuilder(
          pageBuilder: (context, animation, secondaryAnimation) =>
              ResultScreen(result: result),
          transitionsBuilder: (context, animation, secondaryAnimation, child) {
            return FadeTransition(
              opacity: animation,
              child: SlideTransition(
                position: Tween<Offset>(
                  begin: const Offset(0, 0.05),
                  end: Offset.zero,
                ).animate(CurvedAnimation(
                  parent: animation,
                  curve: Curves.easeOut,
                )),
                child: child,
              ),
            );
          },
          transitionDuration: const Duration(milliseconds: 400),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _errorMessage = e.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  Future<void> _openQrScanner() async {
    final scannedUrl = await Navigator.of(context).push<String>(
      PageRouteBuilder(
        pageBuilder: (context, animation, secondaryAnimation) =>
            const QrScannerScreen(),
        transitionsBuilder: (context, animation, secondaryAnimation, child) {
          return FadeTransition(opacity: animation, child: child);
        },
        transitionDuration: const Duration(milliseconds: 300),
      ),
    );

    if (scannedUrl != null && scannedUrl.isNotEmpty && mounted) {
      _urlController.text = scannedUrl;
      _analyzeUrl(scannedUrl);
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final isWide = size.width > 700;

    return Scaffold(
      backgroundColor: AppColors.bgDark,
      body: Stack(
        children: [
          // Background — web'de statik, mobilde animasyonlu
          _buildBackground(size),

          // Main content
          SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: EdgeInsets.symmetric(
                  horizontal: isWide ? size.width * 0.15 : 24,
                  vertical: 24,
                ),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 600),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      _buildLogo(),
                      const SizedBox(height: 12),
                      _buildTitle(),
                      const SizedBox(height: 8),
                      _buildSubtitle(),
                      const SizedBox(height: 48),
                      _buildUrlInput(),
                      const SizedBox(height: 16),
                      _buildActionButtons(),
                      if (_errorMessage != null) ...[
                        const SizedBox(height: 16),
                        _buildErrorMessage(),
                      ],
                      const SizedBox(height: 48),
                      _buildFeatureCards(isWide),
                      const SizedBox(height: 32),
                      _buildFooter(),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBackground(Size size) {
    // Orb widget'ları bir kere oluştur
    final orb1 = RepaintBoundary(
      child: Container(
        width: 350,
        height: 350,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: RadialGradient(
            colors: [
              AppColors.primary.withValues(alpha: 0.12),
              Colors.transparent,
            ],
          ),
        ),
      ),
    );

    final orb2 = RepaintBoundary(
      child: Container(
        width: 400,
        height: 400,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: RadialGradient(
            colors: [
              AppColors.accent.withValues(alpha: 0.08),
              Colors.transparent,
            ],
          ),
        ),
      ),
    );

    final centerGlow = Container(
      width: 200,
      height: 200,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: RadialGradient(
          colors: [
            AppColors.primary.withValues(alpha: 0.05),
            Colors.transparent,
          ],
        ),
      ),
    );

    // Web'de animasyon yok — statik pozisyonlarda dur
    if (kIsWeb) {
      return Stack(
        clipBehavior: Clip.none,
        children: [
          Positioned(top: -100, right: -80, child: orb1),
          Positioned(bottom: -120, left: -100, child: orb2),
          Positioned(
            top: size.height * 0.3,
            left: size.width * 0.3,
            child: centerGlow,
          ),
        ],
      );
    }

    // Mobilde hafif animasyon
    return Stack(
      clipBehavior: Clip.none,
      children: [
        Positioned(
          top: size.height * 0.3,
          left: size.width * 0.3,
          child: centerGlow,
        ),
        AnimatedBuilder(
          animation: _bgAnimController!,
          builder: (context, child) {
            return Stack(
              clipBehavior: Clip.none,
              children: [
                Positioned(
                  top: -100,
                  right: -80,
                  child: Transform.translate(
                    offset: Offset(
                      math.cos(_bgAnimController!.value * 2 * math.pi) * 20,
                      math.sin(_bgAnimController!.value * 2 * math.pi) * 30,
                    ),
                    child: orb1,
                  ),
                ),
                Positioned(
                  bottom: -120,
                  left: -100,
                  child: Transform.translate(
                    offset: Offset(
                      math.sin(_bgAnimController!.value * 2 * math.pi) * 15,
                      math.cos(_bgAnimController!.value * 2 * math.pi) * 25,
                    ),
                    child: orb2,
                  ),
                ),
              ],
            );
          },
        ),
      ],
    );
  }

  Widget _buildLogo() {
    return Container(
      width: 80,
      height: 80,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: AppColors.primaryGradient,
        boxShadow: [
          BoxShadow(
            color: AppColors.primary.withValues(alpha: 0.4),
            blurRadius: 30,
            spreadRadius: 5,
          ),
        ],
      ),
      child: const Icon(
        Icons.shield_rounded,
        size: 42,
        color: Colors.white,
      ),
    )
        .animate()
        .scale(begin: const Offset(0, 0), duration: 800.ms, curve: Curves.elasticOut)
        .fadeIn(duration: 400.ms);
  }

  Widget _buildTitle() {
    return GradientText(
      text: 'PhishCatch',
      style: GoogleFonts.inter(
        fontSize: 36,
        fontWeight: FontWeight.w800,
        letterSpacing: -0.5,
      ),
    )
        .animate()
        .fadeIn(delay: 200.ms, duration: 600.ms)
        .slideY(begin: 0.3, duration: 600.ms);
  }

  Widget _buildSubtitle() {
    return Text(
      'Protect yourself from phishing attacks.\nPaste a URL or scan a QR code to analyze.',
      textAlign: TextAlign.center,
      style: GoogleFonts.inter(
        fontSize: 15,
        color: AppColors.textSecondary,
        height: 1.6,
      ),
    )
        .animate()
        .fadeIn(delay: 400.ms, duration: 600.ms)
        .slideY(begin: 0.2, duration: 600.ms);
  }

  Widget _buildUrlInput() {
    return GlassCard(
      padding: const EdgeInsets.all(6),
      borderRadius: 20,
      borderColor: _urlFocusNode.hasFocus ? AppColors.primary : null,
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _urlController,
              focusNode: _urlFocusNode,
              style: GoogleFonts.firaCode(
                color: AppColors.textPrimary,
                fontSize: 14,
              ),
              decoration: InputDecoration(
                hintText: 'Enter URL to analyze...',
                prefixIcon: Padding(
                  padding: const EdgeInsets.only(left: 12, right: 8),
                  child: Icon(
                    Icons.link_rounded,
                    color: AppColors.textMuted,
                    size: 20,
                  ),
                ),
                border: InputBorder.none,
                enabledBorder: InputBorder.none,
                focusedBorder: InputBorder.none,
                filled: false,
                contentPadding: const EdgeInsets.symmetric(vertical: 16),
              ),
              onSubmitted: _isLoading ? null : (value) => _analyzeUrl(value),
              textInputAction: TextInputAction.search,
            ),
          ),
          // QR button
          _buildQrButton(),
        ],
      ),
    )
        .animate()
        .fadeIn(delay: 600.ms, duration: 600.ms)
        .slideY(begin: 0.2, duration: 600.ms);
  }

  Widget _buildQrButton() {
    // On web, camera QR scanning not supported natively
    if (kIsWeb) {
      return Tooltip(
        message: 'QR Scanner (mobile only)',
        child: Container(
          margin: const EdgeInsets.only(right: 4),
          child: Material(
            color: AppColors.bgCardLight,
            borderRadius: BorderRadius.circular(14),
            child: InkWell(
              borderRadius: BorderRadius.circular(14),
              onTap: () {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(
                      'QR scanning available on mobile app',
                      style: GoogleFonts.inter(),
                    ),
                    backgroundColor: AppColors.bgCard,
                    behavior: SnackBarBehavior.floating,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                );
              },
              child: Container(
                padding: const EdgeInsets.all(12),
                child: Icon(
                  Icons.qr_code_scanner_rounded,
                  color: AppColors.textMuted,
                  size: 22,
                ),
              ),
            ),
          ),
        ),
      );
    }

    return Container(
      margin: const EdgeInsets.only(right: 4),
      child: Material(
        color: Colors.transparent,
        borderRadius: BorderRadius.circular(14),
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: _isLoading ? null : _openQrScanner,
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              gradient: AppColors.primaryGradient,
              borderRadius: BorderRadius.circular(14),
              boxShadow: [
                BoxShadow(
                  color: AppColors.primary.withValues(alpha: 0.3),
                  blurRadius: 12,
                ),
              ],
            ),
            child: const Icon(
              Icons.qr_code_scanner_rounded,
              color: Colors.white,
              size: 22,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildActionButtons() {
    return SizedBox(
      width: double.infinity,
      height: 56,
      child: Container(
        decoration: BoxDecoration(
          gradient: AppColors.primaryGradient,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: AppColors.primary.withValues(alpha: 0.35),
              blurRadius: 20,
              offset: const Offset(0, 8),
            ),
          ],
        ),
        child: ElevatedButton(
          onPressed: _isLoading ? null : () => _analyzeUrl(_urlController.text),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.transparent,
            shadowColor: Colors.transparent,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
            ),
          ),
          child: _isLoading
              ? Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2.5,
                        color: Colors.white.withValues(alpha: 0.9),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Text(
                      'Analyzing...',
                      style: GoogleFonts.inter(
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                  ],
                )
              : Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(Icons.security_rounded, size: 20),
                    const SizedBox(width: 10),
                    Text(
                      'Analyze URL',
                      style: GoogleFonts.inter(
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
        ),
      ),
    )
        .animate()
        .fadeIn(delay: 700.ms, duration: 600.ms)
        .slideY(begin: 0.2, duration: 600.ms);
  }

  Widget _buildErrorMessage() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: AppColors.danger.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.danger.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          Icon(Icons.error_outline_rounded, color: AppColors.danger, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              _errorMessage!,
              style: GoogleFonts.inter(
                color: AppColors.danger,
                fontSize: 13,
              ),
            ),
          ),
        ],
      ),
    ).animate().fadeIn(duration: 300.ms).shake(hz: 2, duration: 400.ms);
  }

  Widget _buildFeatureCards(bool isWide) {
    final features = [
      _FeatureItem(
        icon: Icons.psychology_rounded,
        title: 'ML Detection',
        description: 'Machine learning model analyzes 48 URL features',
        color: AppColors.primary,
      ),
      _FeatureItem(
        icon: Icons.security_rounded,
        title: 'VirusTotal',
        description: 'Cross-reference with VirusTotal threat database',
        color: AppColors.accent,
      ),
      _FeatureItem(
        icon: Icons.qr_code_scanner_rounded,
        title: 'QR Scanner',
        description: 'Scan QR codes to check URLs instantly',
        color: AppColors.safe,
      ),
    ];

    if (isWide) {
      return Row(
        children: features.asMap().entries.map((entry) {
          return Expanded(
            child: Padding(
              padding: EdgeInsets.only(
                left: entry.key == 0 ? 0 : 8,
                right: entry.key == features.length - 1 ? 0 : 8,
              ),
              child: _buildFeatureCard(entry.value, entry.key),
            ),
          );
        }).toList(),
      );
    }

    return Column(
      children: features.asMap().entries.map((entry) {
        return Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: _buildFeatureCard(entry.value, entry.key),
        );
      }).toList(),
    );
  }

  Widget _buildFeatureCard(_FeatureItem feature, int index) {
    return GlassCard(
      padding: const EdgeInsets.all(20),
      child: Row(
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: feature.color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(feature.icon, color: feature.color, size: 22),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  feature.title,
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  feature.description,
                  style: GoogleFonts.inter(
                    color: AppColors.textMuted,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    )
        .animate()
        .fadeIn(delay: Duration(milliseconds: 900 + index * 150), duration: 500.ms)
        .slideY(begin: 0.2, duration: 500.ms);
  }

  Widget _buildFooter() {
    return Column(
      children: [
        Divider(color: AppColors.glassBorder),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.shield_outlined,
                color: AppColors.textMuted, size: 14),
            const SizedBox(width: 6),
            Text(
              'PhishCatch v1.0 — Stay safe online',
              style: GoogleFonts.inter(
                color: AppColors.textMuted,
                fontSize: 12,
              ),
            ),
          ],
        ),
      ],
    ).animate().fadeIn(delay: 1400.ms, duration: 500.ms);
  }
}

class _FeatureItem {
  final IconData icon;
  final String title;
  final String description;
  final Color color;

  _FeatureItem({
    required this.icon,
    required this.title,
    required this.description,
    required this.color,
  });
}
