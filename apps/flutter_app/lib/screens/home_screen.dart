import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:file_picker/file_picker.dart';
import 'package:google_fonts/google_fonts.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';
import 'batch_result_screen.dart';
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
  bool _isBatchLoading = false;
  String? _errorMessage;

  bool get _isBusy => _isLoading || _isBatchLoading;

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

  Future<void> _pickAndAnalyzeFile() async {
    if (_isBusy) return;

    setState(() {
      _isBatchLoading = true;
      _errorMessage = null;
    });

    try {
      final picked = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: const ['txt', 'csv'],
        withData: true,
      );

      if (!mounted) return;
      if (picked == null || picked.files.isEmpty) {
        setState(() => _isBatchLoading = false);
        return;
      }

      final file = picked.files.single;
      final bytes = file.bytes;
      if (bytes == null) {
        setState(() {
          _isBatchLoading = false;
          _errorMessage = 'Dosya okunamadi.';
        });
        return;
      }

      final result = await PhishCatchApiService.analyzeUrlFile(
        bytes: bytes,
        filename: file.name,
      );

      if (!mounted) return;
      setState(() => _isBatchLoading = false);
      Navigator.of(context).push(
        PageRouteBuilder(
          pageBuilder: (context, animation, secondaryAnimation) =>
              BatchResultScreen(result: result),
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
        _isBatchLoading = false;
        _errorMessage = e.toString().replaceFirst('Exception: ', '');
      });
    }
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
                    horizontal: isWide ? 48 : 22,
                    vertical: 28,
                  ),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 760),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _buildIdentity(isWide),
                        SizedBox(height: isWide ? 50 : 38),
                        _buildCommandSurface(isWide),
                        const SizedBox(height: 14),
                        _buildBatchUploadSurface(isWide),
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

  Widget _buildIdentity(bool isWide) {
    return Column(
          children: [
            _buildLogo(isWide),
            const SizedBox(height: 22),
            GradientText(
              text: 'PhishCatch',
              style: GoogleFonts.inter(
                fontSize: isWide ? 64 : 42,
                fontWeight: FontWeight.w900,
                letterSpacing: 0,
                height: 0.92,
              ),
            ),
            const SizedBox(height: 18),
            Container(
              width: isWide ? 180 : 126,
              height: 3,
              decoration: const BoxDecoration(
                gradient: AppColors.primaryGradient,
              ),
            ),
          ],
        )
        .animate()
        .fadeIn(duration: 320.ms)
        .slideY(begin: 0.05, duration: 420.ms, curve: Curves.easeOutCubic);
  }

  Widget _buildLogo(bool isWide) {
    final size = isWide ? 94.0 : 78.0;
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        children: [
          Positioned.fill(
            child: DecoratedBox(
              decoration: BoxDecoration(
                gradient: AppColors.primaryGradient,
                borderRadius: BorderRadius.circular(8),
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
                  color: AppColors.bgSurface.withValues(alpha: 0.38),
                  borderRadius: BorderRadius.circular(7),
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
              size: isWide ? 46 : 38,
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

    return Container(
          decoration: BoxDecoration(
            color: AppColors.bgSurface.withValues(alpha: 0.82),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: borderColor),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.34),
                blurRadius: 34,
                offset: const Offset(0, 22),
              ),
              if (_urlFocusNode.hasFocus)
                BoxShadow(
                  color: AppColors.electric.withValues(alpha: 0.14),
                  blurRadius: 34,
                ),
            ],
          ),
          child: isWide
              ? Row(
                  children: [
                    Expanded(child: _buildUrlInput()),
                    _buildDivider(vertical: true),
                    SizedBox(width: 190, child: _buildActionButton()),
                  ],
                )
              : Column(
                  children: [
                    _buildUrlInput(),
                    _buildDivider(vertical: false),
                    SizedBox(
                      width: double.infinity,
                      child: _buildActionButton(),
                    ),
                  ],
                ),
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
        fontSize: 14,
        fontWeight: FontWeight.w500,
      ),
      decoration: InputDecoration(
        hintText: 'https://example.com',
        prefixIcon: Padding(
          padding: const EdgeInsets.only(left: 14, right: 8),
          child: Icon(Icons.link_rounded, color: AppColors.textMuted, size: 20),
        ),
        border: InputBorder.none,
        enabledBorder: InputBorder.none,
        focusedBorder: InputBorder.none,
        filled: false,
        contentPadding: const EdgeInsets.symmetric(vertical: 20),
      ),
      onSubmitted: _isBusy ? null : (value) => _analyzeUrl(value),
      enabled: !_isBatchLoading,
      textInputAction: TextInputAction.search,
    );
  }

  Widget _buildActionButton() {
    return SizedBox(
      height: 62,
      child: DecoratedBox(
        decoration: const BoxDecoration(gradient: AppColors.primaryGradient),
        child: ElevatedButton(
          onPressed: _isBusy ? null : () => _analyzeUrl(_urlController.text),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.transparent,
            disabledBackgroundColor: Colors.transparent,
            shadowColor: Colors.transparent,
            padding: EdgeInsets.zero,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(0),
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
                        'Kontrol...',
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
                        'Kontrol et',
                        style: GoogleFonts.inter(
                          fontSize: 14,
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

  Widget _buildBatchUploadSurface(bool isWide) {
    return Container(
          decoration: BoxDecoration(
            color: AppColors.bgSurface.withValues(alpha: 0.66),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.white.withValues(alpha: 0.14)),
          ),
          padding: EdgeInsets.all(isWide ? 14 : 12),
          child: isWide
              ? Row(
                  children: [
                    _buildUploadIcon(),
                    const SizedBox(width: 14),
                    Expanded(child: _buildUploadCopy()),
                    const SizedBox(width: 14),
                    SizedBox(width: 170, child: _buildUploadButton()),
                  ],
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        _buildUploadIcon(),
                        const SizedBox(width: 12),
                        Expanded(child: _buildUploadCopy()),
                      ],
                    ),
                    const SizedBox(height: 12),
                    _buildUploadButton(),
                  ],
                ),
        )
        .animate()
        .fadeIn(delay: 220.ms, duration: 300.ms)
        .slideY(begin: 0.04, duration: 360.ms, curve: Curves.easeOutCubic);
  }

  Widget _buildUploadIcon() {
    return Container(
      width: 42,
      height: 42,
      decoration: BoxDecoration(
        color: AppColors.accent.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.accent.withValues(alpha: 0.28)),
      ),
      child: const Icon(
        Icons.upload_file_rounded,
        color: AppColors.accent,
        size: 24,
      ),
    );
  }

  Widget _buildUploadCopy() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Toplu analiz',
          style: GoogleFonts.inter(
            color: AppColors.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w900,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          'TXT veya CSV',
          style: GoogleFonts.inter(
            color: AppColors.textMuted,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _buildUploadButton() {
    return SizedBox(
      height: 44,
      child: OutlinedButton(
        onPressed: _isBusy ? null : _pickAndAnalyzeFile,
        style: OutlinedButton.styleFrom(
          side: BorderSide(color: AppColors.accent.withValues(alpha: 0.42)),
          foregroundColor: AppColors.accent,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
        child: AnimatedSwitcher(
          duration: const Duration(milliseconds: 140),
          child: _isBatchLoading
              ? Row(
                  key: const ValueKey('batch-loading'),
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2.2,
                        color: AppColors.accent.withValues(alpha: 0.9),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'Analiz...',
                      style: GoogleFonts.inter(
                        fontSize: 13,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ],
                )
              : Row(
                  key: const ValueKey('batch-ready'),
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(Icons.folder_open_rounded, size: 18),
                    const SizedBox(width: 8),
                    Text(
                      'Dosya sec',
                      style: GoogleFonts.inter(
                        fontSize: 13,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                  ],
                ),
        ),
      ),
    );
  }

  Widget _buildDivider({required bool vertical}) {
    return Container(
      width: vertical ? 1 : double.infinity,
      height: vertical ? 62 : 1,
      color: Colors.white.withValues(alpha: 0.12),
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
