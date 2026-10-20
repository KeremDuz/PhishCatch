import 'package:flutter/material.dart';

import '../theme/app_theme.dart';

class AppBrand extends StatelessWidget {
  final bool compact;
  const AppBrand({super.key, this.compact = false});
  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Container(
        width: compact ? 36 : 42,
        height: compact ? 36 : 42,
        decoration: BoxDecoration(
          color: AppColors.primary,
          borderRadius: BorderRadius.circular(12),
        ),
        child: const Icon(Icons.link_rounded, color: Colors.white, size: 27),
      ),
      SizedBox(width: compact ? 10 : 12),
      Flexible(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'PhishCatch',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: compact ? 16 : 19,
                fontWeight: FontWeight.w700,
                letterSpacing: -0.5,
              ),
            ),
          ],
        ),
      ),
    ],
  );
}

class StatusBadge extends StatelessWidget {
  final String label;
  final Color color;
  const StatusBadge({
    super.key,
    required this.label,
    this.color = AppColors.primary,
  });
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 7),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.08),
      borderRadius: BorderRadius.circular(8),
      border: Border.all(color: color.withValues(alpha: 0.16)),
    ),
    child: Text(
      label,
      style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600),
    ),
  );
}

class NoticeCard extends StatelessWidget {
  final String message;
  final Color color;
  final IconData icon;
  const NoticeCard({
    super.key,
    required this.message,
    this.color = AppColors.warning,
    this.icon = Icons.info_outline,
  });
  @override
  Widget build(BuildContext context) => Semantics(
    liveRegion: true,
    child: Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 20, color: color),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: TextStyle(color: color, height: 1.5, fontSize: 13),
            ),
          ),
        ],
      ),
    ),
  );
}

/// Compatibility wrappers for existing administration and batch screens.
class CyberBackdrop extends StatelessWidget {
  final Widget child;
  final bool dense;
  const CyberBackdrop({super.key, required this.child, this.dense = false});
  @override
  Widget build(BuildContext context) =>
      ColoredBox(color: AppColors.bgDark, child: child);
}

class GlassCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final double borderRadius;
  final Color? borderColor;
  final double? width;
  final double? height;
  const GlassCard({
    super.key,
    required this.child,
    this.padding,
    this.margin,
    this.borderRadius = 16,
    this.borderColor,
    this.width,
    this.height,
  });
  @override
  Widget build(BuildContext context) => Container(
    width: width,
    height: height,
    margin: margin,
    child: Material(
      color: AppColors.bgCard,
      clipBehavior: Clip.antiAlias,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
        side: BorderSide(color: borderColor ?? AppColors.glassBorder),
      ),
      child: Padding(
        padding: padding ?? const EdgeInsets.all(24),
        child: child,
      ),
    ),
  );
}

class GradientText extends StatelessWidget {
  final String text;
  final TextStyle? style;
  final Gradient gradient;
  const GradientText({
    super.key,
    required this.text,
    this.style,
    this.gradient = AppColors.primaryGradient,
  });
  @override
  Widget build(BuildContext context) =>
      Text(text, style: style?.copyWith(color: AppColors.primary));
}

class GlowContainer extends StatelessWidget {
  final Widget child;
  final Color glowColor;
  final double blurRadius;
  final double borderRadius;
  const GlowContainer({
    super.key,
    required this.child,
    this.glowColor = AppColors.primary,
    this.blurRadius = 20,
    this.borderRadius = 20,
  });
  @override
  Widget build(BuildContext context) => child;
}

class PulsatingDot extends StatelessWidget {
  final Color color;
  final double size;
  const PulsatingDot({super.key, this.color = AppColors.safe, this.size = 10});
  @override
  Widget build(BuildContext context) => Container(
    width: size,
    height: size,
    decoration: BoxDecoration(shape: BoxShape.circle, color: color),
  );
}

class VerdictShield extends StatelessWidget {
  final String verdict;
  final double size;
  const VerdictShield({super.key, required this.verdict, this.size = 80});
  @override
  Widget build(BuildContext context) => Icon(
    verdict == 'malicious'
        ? Icons.gpp_bad_outlined
        : verdict == 'clean'
        ? Icons.verified_user_outlined
        : Icons.shield_outlined,
    size: size,
    color: verdict == 'malicious'
        ? AppColors.danger
        : verdict == 'clean'
        ? AppColors.safe
        : AppColors.warning,
  );
}
