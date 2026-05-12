import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:google_fonts/google_fonts.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class ResultScreen extends StatefulWidget {
  final AnalysisResult result;

  const ResultScreen({super.key, required this.result});

  @override
  State<ResultScreen> createState() => _ResultScreenState();
}

class _ResultScreenState extends State<ResultScreen> {
  bool _showTechnicalDetails = false;

  Color get _verdictColor {
    if (widget.result.isMalicious) return AppColors.danger;
    if (widget.result.isClean) return AppColors.safe;
    return AppColors.warning;
  }

  IconData get _verdictIcon {
    if (widget.result.isMalicious) return Icons.gpp_bad_rounded;
    if (widget.result.isClean) return Icons.verified_user_rounded;
    return Icons.shield_rounded;
  }

  String get _verdictTitle {
    if (widget.result.isMalicious) return 'Riskli baglanti';
    if (widget.result.isClean) return 'Guvenli gorunuyor';
    return 'Emin degiliz';
  }

  String get _verdictDescription {
    if (widget.result.isMalicious) {
      return 'Bu baglanti riskli gorunuyor. Kisisel bilgi girme.';
    }
    if (widget.result.isClean) {
      return 'Belirgin bir risk sinyali bulunmadi.';
    }
    return 'Sonuc net degil. Acmadan once dikkatli olmak iyi olur.';
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
              color: AppColors.bgSurface.withValues(alpha: 0.72),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.glassBorder),
            ),
            child: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          ),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: Text(
          'Sonuc',
          style: GoogleFonts.inter(fontWeight: FontWeight.w700),
        ),
      ),
      body: CyberBackdrop(
        dense: MediaQuery.of(context).size.width < 720,
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final isWide = constraints.maxWidth >= 760;
              return Center(
                child: SingleChildScrollView(
                  padding: EdgeInsets.fromLTRB(
                    isWide ? 44 : 22,
                    24,
                    isWide ? 44 : 22,
                    32,
                  ),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 860),
                    child: _buildFlowSurface(isWide),
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Widget _buildFlowSurface(bool isWide) {
    return Container(
          decoration: BoxDecoration(
            color: AppColors.bgSurface.withValues(alpha: 0.76),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: _verdictColor.withValues(alpha: 0.28)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.34),
                blurRadius: 36,
                offset: const Offset(0, 22),
              ),
            ],
          ),
          child: Column(
            children: [
              _buildHero(isWide),
              _buildDivider(),
              _buildUrlLine(),
              _buildDivider(),
              _buildRiskFlow(),
              _buildDivider(),
              _buildTechnicalToggle(),
            ],
          ),
        )
        .animate()
        .fadeIn(duration: 280.ms)
        .slideY(begin: 0.04, duration: 360.ms, curve: Curves.easeOutCubic);
  }

  Widget _buildHero(bool isWide) {
    return Padding(
      padding: EdgeInsets.fromLTRB(
        isWide ? 34 : 22,
        isWide ? 34 : 28,
        isWide ? 34 : 22,
        isWide ? 30 : 24,
      ),
      child: isWide
          ? Row(
              children: [
                _buildVerdictMark(isWide),
                const SizedBox(width: 28),
                Expanded(child: _buildVerdictCopy(isWide)),
              ],
            )
          : Column(
              children: [
                _buildVerdictMark(isWide),
                const SizedBox(height: 22),
                _buildVerdictCopy(isWide),
              ],
            ),
    );
  }

  Widget _buildVerdictMark(bool isWide) {
    final size = isWide ? 104.0 : 92.0;
    return Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            color: _verdictColor.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: _verdictColor.withValues(alpha: 0.36)),
            boxShadow: [
              BoxShadow(
                color: _verdictColor.withValues(alpha: 0.16),
                blurRadius: 30,
              ),
            ],
          ),
          child: Icon(
            _verdictIcon,
            color: _verdictColor,
            size: isWide ? 58 : 50,
          ),
        )
        .animate()
        .scale(
          begin: const Offset(0.72, 0.72),
          duration: 420.ms,
          curve: Curves.easeOutBack,
        )
        .fadeIn(duration: 220.ms);
  }

  Widget _buildVerdictCopy(bool isWide) {
    return Column(
      crossAxisAlignment: isWide
          ? CrossAxisAlignment.start
          : CrossAxisAlignment.center,
      children: [
        Text(
          _verdictTitle,
          textAlign: isWide ? TextAlign.left : TextAlign.center,
          style: GoogleFonts.inter(
            fontSize: isWide ? 34 : 26,
            fontWeight: FontWeight.w900,
            color: _verdictColor,
            letterSpacing: 0,
            height: 1.02,
          ),
        ),
        const SizedBox(height: 10),
        Text(
          _verdictDescription,
          textAlign: isWide ? TextAlign.left : TextAlign.center,
          style: GoogleFonts.inter(
            fontSize: 14,
            color: AppColors.textSecondary,
            height: 1.5,
          ),
        ),
      ],
    );
  }

  Widget _buildUrlLine() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
      child: Row(
        children: [
          Icon(Icons.link_rounded, color: AppColors.accent, size: 18),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              widget.result.originalInput ?? widget.result.url,
              style: GoogleFonts.firaCode(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontWeight: FontWeight.w500,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRiskFlow() {
    final malicious = widget.result.maliciousPercent;
    final clean = widget.result.cleanPercent;

    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 18, 18, 20),
      child: Column(
        children: [
          _buildRiskRow('Riskli', malicious, AppColors.danger),
          const SizedBox(height: 16),
          _buildRiskRow('Temiz', clean, AppColors.safe),
        ],
      ),
    );
  }

  Widget _buildRiskRow(String label, double value, Color color) {
    return Row(
      children: [
        SizedBox(
          width: 58,
          child: Text(
            label,
            style: GoogleFonts.inter(
              color: AppColors.textSecondary,
              fontSize: 13,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
        Expanded(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final width =
                  constraints.maxWidth * (value / 100).clamp(0.0, 1.0);
              return Stack(
                children: [
                  Container(
                    height: 8,
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(4),
                    ),
                  ),
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 520),
                    curve: Curves.easeOutCubic,
                    width: width,
                    height: 8,
                    decoration: BoxDecoration(
                      color: color,
                      borderRadius: BorderRadius.circular(4),
                    ),
                  ),
                ],
              );
            },
          ),
        ),
        const SizedBox(width: 14),
        SizedBox(
          width: 54,
          child: Text(
            '${value.toStringAsFixed(1)}%',
            textAlign: TextAlign.right,
            style: GoogleFonts.firaCode(
              color: color,
              fontSize: 13,
              fontWeight: FontWeight.w800,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildTechnicalToggle() {
    return Column(
      children: [
        InkWell(
          onTap: () {
            setState(() {
              _showTechnicalDetails = !_showTechnicalDetails;
            });
          },
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
            child: Row(
              children: [
                Icon(Icons.tune_rounded, color: AppColors.accent, size: 18),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Teknik detaylar',
                    style: GoogleFonts.inter(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
                Icon(
                  _showTechnicalDetails
                      ? Icons.keyboard_arrow_up_rounded
                      : Icons.keyboard_arrow_down_rounded,
                  color: AppColors.accent,
                ),
              ],
            ),
          ),
        ),
        AnimatedCrossFade(
          firstChild: const SizedBox.shrink(),
          secondChild: Padding(
            padding: const EdgeInsets.fromLTRB(18, 0, 18, 18),
            child: Column(
              children: widget.result.stages.asMap().entries.map((entry) {
                final idx = entry.key;
                return _buildStageItem(
                  entry.value,
                  idx == widget.result.stages.length - 1,
                );
              }).toList(),
            ),
          ),
          crossFadeState: _showTechnicalDetails
              ? CrossFadeState.showSecond
              : CrossFadeState.showFirst,
          duration: const Duration(milliseconds: 160),
        ),
      ],
    );
  }

  Widget _buildStageItem(StageResult stage, bool isLast) {
    final color = _stageColor(stage.verdict);
    return Padding(
      padding: EdgeInsets.only(bottom: isLast ? 0 : 14),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 9,
            height: 9,
            margin: const EdgeInsets.only(top: 5),
            decoration: BoxDecoration(
              color: color,
              borderRadius: BorderRadius.circular(3),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        stage.scanner,
                        style: GoogleFonts.inter(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ),
                    Text(
                      _stageVerdictLabel(stage.verdict),
                      style: GoogleFonts.firaCode(
                        color: color,
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ],
                ),
                if (stage.reason != null) ...[
                  const SizedBox(height: 4),
                  Text(
                    stage.reason!,
                    style: GoogleFonts.inter(
                      color: AppColors.textMuted,
                      fontSize: 12,
                      height: 1.35,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDivider() {
    return Container(height: 1, color: Colors.white.withValues(alpha: 0.10));
  }

  Color _stageColor(String verdict) {
    switch (verdict) {
      case 'malicious':
        return AppColors.danger;
      case 'clean':
        return AppColors.safe;
      default:
        return AppColors.warning;
    }
  }

  String _stageVerdictLabel(String verdict) {
    switch (verdict) {
      case 'malicious':
        return 'RISKLI';
      case 'clean':
        return 'TEMIZ';
      default:
        return 'BELIRSIZ';
    }
  }
}
