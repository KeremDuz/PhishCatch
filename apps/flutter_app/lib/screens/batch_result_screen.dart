import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:google_fonts/google_fonts.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class BatchResultScreen extends StatelessWidget {
  final BatchAnalysisResult result;

  const BatchResultScreen({super.key, required this.result});

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
          'Toplu sonuc',
          style: GoogleFonts.inter(fontWeight: FontWeight.w700),
        ),
      ),
      body: CyberBackdrop(
        dense: MediaQuery.of(context).size.width < 720,
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final isWide = constraints.maxWidth >= 820;
              return Center(
                child: SingleChildScrollView(
                  padding: EdgeInsets.fromLTRB(
                    isWide ? 44 : 22,
                    24,
                    isWide ? 44 : 22,
                    32,
                  ),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 980),
                    child: _buildSurface(isWide),
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Widget _buildSurface(bool isWide) {
    return Container(
          decoration: BoxDecoration(
            color: AppColors.bgSurface.withValues(alpha: 0.76),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppColors.glassBorder),
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
              _buildHeader(isWide),
              _divider(),
              _buildStats(isWide),
              _divider(),
              _buildResultList(),
            ],
          ),
        )
        .animate()
        .fadeIn(duration: 280.ms)
        .slideY(begin: 0.04, duration: 360.ms, curve: Curves.easeOutCubic);
  }

  Widget _buildHeader(bool isWide) {
    return Padding(
      padding: EdgeInsets.fromLTRB(
        isWide ? 34 : 22,
        isWide ? 32 : 26,
        isWide ? 34 : 22,
        isWide ? 28 : 24,
      ),
      child: isWide
          ? Row(
              children: [
                _headerIcon(),
                const SizedBox(width: 24),
                Expanded(child: _headerCopy(isWide)),
              ],
            )
          : Column(
              children: [
                _headerIcon(),
                const SizedBox(height: 18),
                _headerCopy(isWide),
              ],
            ),
    );
  }

  Widget _headerIcon() {
    return Container(
      width: 88,
      height: 88,
      decoration: BoxDecoration(
        color: AppColors.electric.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.electric.withValues(alpha: 0.34)),
      ),
      child: const Icon(
        Icons.file_present_rounded,
        color: AppColors.electric,
        size: 48,
      ),
    );
  }

  Widget _headerCopy(bool isWide) {
    return Column(
      crossAxisAlignment: isWide
          ? CrossAxisAlignment.start
          : CrossAxisAlignment.center,
      children: [
        Text(
          'Toplu analiz',
          textAlign: isWide ? TextAlign.left : TextAlign.center,
          style: GoogleFonts.inter(
            fontSize: isWide ? 34 : 26,
            fontWeight: FontWeight.w900,
            color: AppColors.textPrimary,
            letterSpacing: 0,
            height: 1.02,
          ),
        ),
        const SizedBox(height: 10),
        Text(
          result.filename,
          textAlign: isWide ? TextAlign.left : TextAlign.center,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: GoogleFonts.firaCode(
            fontSize: 13,
            color: AppColors.textSecondary,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _buildStats(bool isWide) {
    final stats = [
      _StatItem('Riskli', result.summary.malicious, AppColors.danger),
      _StatItem('Temiz', result.summary.clean, AppColors.safe),
      _StatItem('Belirsiz', result.summary.unknown, AppColors.warning),
      _StatItem('Gecersiz', result.summary.invalid, AppColors.unknown),
      _StatItem('Toplam', result.summary.submitted, AppColors.electric),
    ];

    return Padding(
      padding: const EdgeInsets.all(18),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final columns = constraints.maxWidth >= 760 ? 5 : 2;
          final gap = 10.0;
          final width =
              (constraints.maxWidth - (gap * (columns - 1))) / columns;
          return Wrap(
            spacing: gap,
            runSpacing: gap,
            children: stats
                .map((item) => SizedBox(width: width, child: _statTile(item)))
                .toList(),
          );
        },
      ),
    );
  }

  Widget _statTile(_StatItem item) {
    return Container(
      height: 92,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: item.color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: item.color.withValues(alpha: 0.24)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            item.label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: GoogleFonts.inter(
              color: AppColors.textSecondary,
              fontSize: 12,
              fontWeight: FontWeight.w800,
            ),
          ),
          Text(
            item.value.toString(),
            style: GoogleFonts.firaCode(
              color: item.color,
              fontSize: 28,
              fontWeight: FontWeight.w900,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildResultList() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 18),
      child: Column(
        children: [
          Row(
            children: [
              Icon(
                Icons.format_list_bulleted_rounded,
                color: AppColors.accent,
                size: 18,
              ),
              const SizedBox(width: 10),
              Text(
                'URL sonuclari',
                style: GoogleFonts.inter(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w900,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          ...result.results.map(_resultRow),
        ],
      ),
    );
  }

  Widget _resultRow(BatchAnalysisItem item) {
    final color = _verdictColor(item.finalVerdict);
    final label = _verdictLabel(item.finalVerdict);
    final subtitle = item.error ?? item.summary ?? item.normalizedUrl ?? '';

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.04),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.20)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 34,
            height: 34,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.10),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              item.index.toString(),
              style: GoogleFonts.firaCode(
                color: color,
                fontSize: 12,
                fontWeight: FontWeight.w900,
              ),
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
                        item.input,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.firaCode(
                          color: AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                    const SizedBox(width: 10),
                    Text(
                      label,
                      style: GoogleFonts.firaCode(
                        color: color,
                        fontSize: 11,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                  ],
                ),
                if (subtitle.isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Text(
                    subtitle,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
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
          if (!item.isInvalid) ...[
            const SizedBox(width: 12),
            SizedBox(
              width: 56,
              child: Text(
                '${item.riskPercent.toStringAsFixed(0)}%',
                textAlign: TextAlign.right,
                style: GoogleFonts.firaCode(
                  color: color,
                  fontSize: 13,
                  fontWeight: FontWeight.w900,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _divider() {
    return Container(height: 1, color: Colors.white.withValues(alpha: 0.10));
  }

  Color _verdictColor(String verdict) {
    switch (verdict) {
      case 'malicious':
        return AppColors.danger;
      case 'clean':
        return AppColors.safe;
      case 'invalid':
        return AppColors.unknown;
      default:
        return AppColors.warning;
    }
  }

  String _verdictLabel(String verdict) {
    switch (verdict) {
      case 'malicious':
        return 'RISKLI';
      case 'clean':
        return 'TEMIZ';
      case 'invalid':
        return 'HATALI';
      default:
        return 'BELIRSIZ';
    }
  }
}

class _StatItem {
  final String label;
  final int value;
  final Color color;

  const _StatItem(this.label, this.value, this.color);
}
