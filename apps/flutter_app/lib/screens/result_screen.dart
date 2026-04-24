import 'dart:math' as math;

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

class _ResultScreenState extends State<ResultScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _ringController;

  @override
  void initState() {
    super.initState();
    _ringController = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    )..repeat();
  }

  @override
  void dispose() {
    _ringController.dispose();
    super.dispose();
  }

  Color get _verdictColor {
    if (widget.result.isMalicious) return AppColors.danger;
    if (widget.result.isClean) return AppColors.safe;
    return AppColors.warning;
  }

  String get _verdictTitle {
    if (widget.result.isMalicious) return 'PHISHING DETECTED';
    if (widget.result.isClean) return 'URL IS SAFE';
    return 'UNKNOWN STATUS';
  }

  String get _verdictDescription {
    if (widget.result.isMalicious) {
      return 'This URL has been identified as a phishing attempt. Do NOT enter any personal information.';
    }
    if (widget.result.isClean) {
      return 'This URL appears to be legitimate and safe to visit. Always stay cautious.';
    }
    return 'Could not determine the safety of this URL. Proceed with caution.';
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
          'Analysis Result',
          style: GoogleFonts.inter(fontWeight: FontWeight.w600),
        ),
      ),
      body: Stack(
        children: [
          // Background gradient orbs
          _buildBackgroundOrbs(),

          // Content
          SafeArea(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
              child: Column(
                children: [
                  const SizedBox(height: 20),
                  _buildVerdictHeader(),
                  const SizedBox(height: 28),
                  _buildUrlCard(),
                  const SizedBox(height: 16),
                  _buildConfidenceCard(),
                  const SizedBox(height: 16),
                  _buildStagesCard(),
                  const SizedBox(height: 32),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBackgroundOrbs() {
    return Stack(
      children: [
        Positioned(
          top: -80,
          right: -60,
          child: Container(
            width: 250,
            height: 250,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(
                colors: [
                  _verdictColor.withValues(alpha: 0.15),
                  Colors.transparent,
                ],
              ),
            ),
          ),
        ),
        Positioned(
          bottom: 100,
          left: -80,
          child: Container(
            width: 200,
            height: 200,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(
                colors: [
                  AppColors.primary.withValues(alpha: 0.1),
                  Colors.transparent,
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildVerdictHeader() {
    return Column(
      children: [
        // Animated ring + shield
        SizedBox(
          width: 150,
          height: 150,
          child: Stack(
            alignment: Alignment.center,
            children: [
              // Rotating ring
              AnimatedBuilder(
                animation: _ringController,
                builder: (context, child) {
                  return Transform.rotate(
                    angle: _ringController.value * 2 * math.pi,
                    child: Container(
                      width: 140,
                      height: 140,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: Colors.transparent,
                          width: 2,
                        ),
                        gradient: SweepGradient(
                          colors: [
                            Colors.transparent,
                            _verdictColor.withValues(alpha: 0.5),
                            _verdictColor,
                            _verdictColor.withValues(alpha: 0.5),
                            Colors.transparent,
                          ],
                        ),
                      ),
                    ),
                  );
                },
              ),
              // Inner circle
              Container(
                width: 130,
                height: 130,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppColors.bgDark,
                ),
              ),
              VerdictShield(
                verdict: widget.result.finalVerdict,
                size: 64,
              ),
            ],
          ),
        )
            .animate()
            .scale(begin: const Offset(0.5, 0.5), duration: 600.ms, curve: Curves.elasticOut)
            .fadeIn(duration: 400.ms),

        const SizedBox(height: 20),

        Text(
          _verdictTitle,
          style: GoogleFonts.inter(
            fontSize: 24,
            fontWeight: FontWeight.w800,
            color: _verdictColor,
            letterSpacing: 2,
          ),
        )
            .animate()
            .fadeIn(delay: 300.ms, duration: 500.ms)
            .slideY(begin: 0.3, duration: 500.ms),

        const SizedBox(height: 8),

        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20),
          child: Text(
            _verdictDescription,
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(
              fontSize: 14,
              color: AppColors.textSecondary,
              height: 1.5,
            ),
          ),
        )
            .animate()
            .fadeIn(delay: 500.ms, duration: 500.ms),
      ],
    );
  }

  Widget _buildUrlCard() {
    return GlassCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.link_rounded, color: AppColors.accent, size: 18),
              const SizedBox(width: 8),
              Text(
                'Analyzed URL',
                style: GoogleFonts.inter(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: AppColors.bgDark.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              widget.result.originalInput ?? widget.result.url,
              style: GoogleFonts.firaCode(
                color: AppColors.textPrimary,
                fontSize: 13,
              ),
              maxLines: 3,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (widget.result.originalInput != null &&
              widget.result.originalInput != widget.result.normalizedUrl) ...[
            const SizedBox(height: 8),
            Row(
              children: [
                Icon(Icons.arrow_forward_rounded,
                    color: AppColors.textMuted, size: 14),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    widget.result.normalizedUrl,
                    style: GoogleFonts.firaCode(
                      color: AppColors.textMuted,
                      fontSize: 11,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    )
        .animate()
        .fadeIn(delay: 400.ms, duration: 500.ms)
        .slideX(begin: -0.1, duration: 500.ms);
  }

  Widget _buildConfidenceCard() {
    final malicious = widget.result.maliciousPercent;
    final clean = widget.result.cleanPercent;

    return GlassCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.insights_rounded, color: AppColors.accent, size: 18),
              const SizedBox(width: 8),
              Text(
                'Confidence Analysis',
                style: GoogleFonts.inter(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Malicious bar
          _buildConfidenceBar(
            label: 'Malicious',
            value: malicious,
            color: AppColors.danger,
          ),
          const SizedBox(height: 14),

          // Clean bar
          _buildConfidenceBar(
            label: 'Clean',
            value: clean,
            color: AppColors.safe,
          ),

          const SizedBox(height: 16),
          Divider(color: AppColors.glassBorder),
          const SizedBox(height: 12),

          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Decided by',
                style: GoogleFonts.inter(
                  color: AppColors.textMuted,
                  fontSize: 12,
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: AppColors.primary.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  widget.result.decidedBy,
                  style: GoogleFonts.firaCode(
                    color: AppColors.primaryLight,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    )
        .animate()
        .fadeIn(delay: 600.ms, duration: 500.ms)
        .slideX(begin: 0.1, duration: 500.ms);
  }

  Widget _buildConfidenceBar({
    required String label,
    required double value,
    required Color color,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Row(
              children: [
                Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                    color: color,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  label,
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
            Text(
              '${value.toStringAsFixed(1)}%',
              style: GoogleFonts.firaCode(
                color: color,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Stack(
          children: [
            Container(
              height: 6,
              decoration: BoxDecoration(
                color: AppColors.bgDark,
                borderRadius: BorderRadius.circular(3),
              ),
            ),
            AnimatedContainer(
              duration: const Duration(milliseconds: 1200),
              curve: Curves.easeOutCubic,
              height: 6,
              width: (MediaQuery.of(context).size.width - 80) * (value / 100).clamp(0.0, 1.0),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [color, color.withValues(alpha: 0.7)],
                ),
                borderRadius: BorderRadius.circular(3),
                boxShadow: [
                  BoxShadow(
                    color: color.withValues(alpha: 0.4),
                    blurRadius: 6,
                  ),
                ],
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStagesCard() {
    return GlassCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.timeline_rounded, color: AppColors.accent, size: 18),
              const SizedBox(width: 8),
              Text(
                'Scan Pipeline',
                style: GoogleFonts.inter(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          ...widget.result.stages.asMap().entries.map((entry) {
            final idx = entry.key;
            final stage = entry.value;
            return _buildStageItem(stage, idx == widget.result.stages.length - 1);
          }),
        ],
      ),
    )
        .animate()
        .fadeIn(delay: 800.ms, duration: 500.ms)
        .slideY(begin: 0.1, duration: 500.ms);
  }

  Widget _buildStageItem(StageResult stage, bool isLast) {
    Color verdictColor;
    switch (stage.verdict) {
      case 'malicious':
        verdictColor = AppColors.danger;
        break;
      case 'clean':
        verdictColor = AppColors.safe;
        break;
      default:
        verdictColor = AppColors.warning;
    }

    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Timeline
          Column(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: verdictColor,
                  boxShadow: [
                    BoxShadow(
                      color: verdictColor.withValues(alpha: 0.5),
                      blurRadius: 6,
                    ),
                  ],
                ),
              ),
              if (!isLast)
                Expanded(
                  child: Container(
                    width: 1.5,
                    color: AppColors.glassBorder,
                  ),
                ),
            ],
          ),
          const SizedBox(width: 14),
          // Content
          Expanded(
            child: Padding(
              padding: EdgeInsets.only(bottom: isLast ? 0 : 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        stage.scanner,
                        style: GoogleFonts.inter(
                          color: AppColors.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: verdictColor.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          stage.verdict.toUpperCase(),
                          style: GoogleFonts.firaCode(
                            color: verdictColor,
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                          ),
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
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
