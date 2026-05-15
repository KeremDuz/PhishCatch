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

class _HomeScreenState extends State<HomeScreen> {
  final TextEditingController _urlController = TextEditingController();
  final FocusNode _urlFocusNode = FocusNode();
  bool _isLoading = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _urlFocusNode.addListener(_handleFocusChanged);
  }

  @override
  void dispose() {
    _urlFocusNode.removeListener(_handleFocusChanged);
    _urlController.dispose();
    _urlFocusNode.dispose();
    super.dispose();
  }

  void _handleFocusChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  Future<void> _analyzeUrl(String url) async {
    if (url.trim().isEmpty) {
      setState(() => _errorMessage = 'Lutfen bir baglanti gir.');
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
                position:
                    Tween<Offset>(
                      begin: const Offset(0, 0.04),
                      end: Offset.zero,
                    ).animate(
                      CurvedAnimation(parent: animation, curve: Curves.easeOut),
                    ),
                child: child,
              ),
            );
          },
          transitionDuration: const Duration(milliseconds: 280),
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
    if (_isLoading) return;

    final scannedValue = await Navigator.of(context).push<String>(
      PageRouteBuilder(
        pageBuilder: (context, animation, secondaryAnimation) =>
            const QrScannerScreen(),
        transitionsBuilder: (context, animation, secondaryAnimation, child) {
          return FadeTransition(
            opacity: animation,
            child: SlideTransition(
              position:
                  Tween<Offset>(
                    begin: const Offset(0, 0.04),
                    end: Offset.zero,
                  ).animate(
                    CurvedAnimation(parent: animation, curve: Curves.easeOut),
                  ),
              child: child,
            ),
          );
        },
        transitionDuration: const Duration(milliseconds: 240),
      ),
    );

    if (!mounted || scannedValue == null) return;
    _urlController.text = scannedValue;
    await _analyzeUrl(scannedValue);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bgDark,
      body: CyberBackdrop(
        dense: MediaQuery.of(context).size.width < 720,
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final isWide = constraints.maxWidth >= 720;
              return Center(
                child: SingleChildScrollView(
                  padding: EdgeInsets.symmetric(
                    horizontal: isWide ? 48 : 24,
                    vertical: isWide ? 32 : 24,
                  ),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 600),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _buildIdentity(isWide),
                        SizedBox(height: isWide ? 48 : 34),
                        _buildCommandSurface(isWide),
                        if (_errorMessage != null) ...[
                          const SizedBox(height: 16),
                          _buildErrorMessage(),
                        ],
                        SizedBox(height: isWide ? 52 : 42),
                        _buildFooter(),
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

  Widget _buildIdentity(bool isWide) {
    return Column(
          children: [
            _buildLogo(isWide),
            const SizedBox(height: 20),
            GradientText(
              text: 'PhishCatch',
              style: GoogleFonts.inter(
                fontSize: isWide ? 38 : 34,
                fontWeight: FontWeight.w900,
                letterSpacing: 0,
                height: 1,
              ),
            ),
            const SizedBox(height: 16),
            Text(
              'Protect yourself from phishing attacks.',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(
                color: AppColors.textSecondary,
                fontSize: isWide ? 16 : 14,
                fontWeight: FontWeight.w500,
                height: 1.45,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'Paste a URL or scan a QR code to analyze.',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(
                color: AppColors.textSecondary,
                fontSize: isWide ? 16 : 14,
                fontWeight: FontWeight.w500,
                height: 1.45,
              ),
            ),
          ],
        )
        .animate()
        .fadeIn(duration: 320.ms)
        .slideY(begin: 0.05, duration: 420.ms, curve: Curves.easeOutCubic);
  }

  Widget _buildLogo(bool isWide) {
    final size = isWide ? 84.0 : 76.0;
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        children: [
          Positioned.fill(
            child: DecoratedBox(
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: AppColors.primaryGradient,
                boxShadow: [
                  BoxShadow(
                    color: AppColors.electric.withValues(alpha: 0.28),
                    blurRadius: 34,
                    offset: const Offset(0, 16),
                  ),
                ],
              ),
            ),
          ),
          Positioned.fill(
            child: Padding(
              padding: const EdgeInsets.all(2),
              child: DecoratedBox(
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppColors.bgSurface.withValues(alpha: 0.38),
                  border: Border.all(
                    color: Colors.white.withValues(alpha: 0.18),
                  ),
                ),
              ),
            ),
          ),
          Center(
            child: Icon(
              Icons.shield_rounded,
              color: Colors.white,
              size: isWide ? 42 : 38,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCommandSurface(bool isWide) {
    final borderColor = _urlFocusNode.hasFocus
        ? AppColors.electric
        : Colors.white.withValues(alpha: 0.16);

    return Column(
          children: [
            Container(
              height: isWide ? 62 : 58,
              decoration: BoxDecoration(
                color: AppColors.bgCardLight.withValues(alpha: 0.78),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: borderColor),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.30),
                    blurRadius: 24,
                    offset: const Offset(0, 16),
                  ),
                  if (_urlFocusNode.hasFocus)
                    BoxShadow(
                      color: AppColors.electric.withValues(alpha: 0.16),
                      blurRadius: 30,
                    ),
                ],
              ),
              child: _buildUrlInput(),
            ),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: _buildActionButton()),
          ],
        )
        .animate()
        .fadeIn(delay: 140.ms, duration: 300.ms)
        .slideY(begin: 0.04, duration: 360.ms, curve: Curves.easeOutCubic);
  }

  Widget _buildUrlInput() {
    return TextField(
      controller: _urlController,
      focusNode: _urlFocusNode,
      style: GoogleFonts.firaCode(
        color: AppColors.textPrimary,
        fontSize: 15,
        fontWeight: FontWeight.w500,
      ),
      decoration: InputDecoration(
        hintText: 'example.com',
        prefixIcon: Padding(
          padding: const EdgeInsets.only(left: 16, right: 8),
          child: Icon(Icons.link_rounded, color: AppColors.textMuted, size: 20),
        ),
        suffixIcon: Padding(
          padding: const EdgeInsets.only(right: 8),
          child: IconButton(
            tooltip: 'QR tara',
            onPressed: _isLoading ? null : _openQrScanner,
            style: IconButton.styleFrom(
              backgroundColor: AppColors.bgSurface.withValues(alpha: 0.38),
              foregroundColor: AppColors.textSecondary,
              disabledForegroundColor: AppColors.textMuted,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
            ),
            icon: const Icon(Icons.qr_code_scanner_rounded, size: 20),
          ),
        ),
        border: InputBorder.none,
        enabledBorder: InputBorder.none,
        focusedBorder: InputBorder.none,
        filled: false,
        contentPadding: const EdgeInsets.symmetric(vertical: 18),
      ),
      onSubmitted: _isLoading ? null : (value) => _analyzeUrl(value),
      enabled: !_isLoading,
      textInputAction: TextInputAction.search,
    );
  }

  Widget _buildActionButton() {
    return SizedBox(
      height: 56,
      child: DecoratedBox(
        decoration: BoxDecoration(
          gradient: AppColors.primaryGradient,
          borderRadius: BorderRadius.circular(14),
          boxShadow: [
            BoxShadow(
              color: AppColors.primary.withValues(alpha: 0.28),
              blurRadius: 24,
              offset: const Offset(0, 14),
            ),
          ],
        ),
        child: ElevatedButton(
          onPressed: _isLoading ? null : () => _analyzeUrl(_urlController.text),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.transparent,
            disabledBackgroundColor: Colors.transparent,
            shadowColor: Colors.transparent,
            padding: EdgeInsets.zero,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(14),
            ),
          ),
          child: AnimatedSwitcher(
            duration: const Duration(milliseconds: 140),
            child: _isLoading
                ? Row(
                    key: const ValueKey('loading'),
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                          strokeWidth: 2.4,
                          color: Colors.white.withValues(alpha: 0.9),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        'Analyzing...',
                        style: GoogleFonts.inter(
                          fontSize: 14,
                          fontWeight: FontWeight.w700,
                          color: Colors.white,
                        ),
                      ),
                    ],
                  )
                : Row(
                    key: const ValueKey('ready'),
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.security_rounded, size: 20),
                      const SizedBox(width: 8),
                      Text(
                        'Analyze URL',
                        style: GoogleFonts.inter(
                          fontSize: 15,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ],
                  ),
          ),
        ),
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

  Widget _buildFooter() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.only(top: 22),
      decoration: BoxDecoration(
        border: Border(
          top: BorderSide(color: Colors.white.withValues(alpha: 0.10)),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.shield_outlined,
            color: AppColors.textMuted.withValues(alpha: 0.78),
            size: 14,
          ),
          const SizedBox(width: 8),
          Text(
            'PhishCatch v1.0',
            style: GoogleFonts.inter(
              color: AppColors.textMuted.withValues(alpha: 0.78),
              fontSize: 12,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }
}
