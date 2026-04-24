import 'dart:ui';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

/// Glassmorphism container widget
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
    this.borderRadius = 20,
    this.borderColor,
    this.width,
    this.height,
  });

  @override
  Widget build(BuildContext context) {
    // Web'de BackdropFilter aşırı FPS düşüşüne neden olur.
    // Görüntüyü aynı tutmak için Web tarafında blur yerine yarı saydam bir arka plan kullanıyoruz.
    final decoration = BoxDecoration(
      color: kIsWeb ? AppColors.bgCard.withValues(alpha: 0.95) : AppColors.glassWhite,
      borderRadius: BorderRadius.circular(borderRadius),
      border: Border.all(
        color: borderColor ?? AppColors.glassBorder,
        width: 1,
      ),
    );

    final content = Container(
      padding: padding ?? const EdgeInsets.all(20),
      decoration: decoration,
      child: child,
    );

    return Container(
      width: width,
      height: height,
      margin: margin,
      child: kIsWeb
          ? ClipRRect(
              borderRadius: BorderRadius.circular(borderRadius),
              child: content,
            )
          : ClipRRect(
              borderRadius: BorderRadius.circular(borderRadius),
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                child: content,
              ),
            ),
    );
  }
}

/// Gradient text widget
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
  Widget build(BuildContext context) {
    return ShaderMask(
      blendMode: BlendMode.srcIn,
      shaderCallback: (bounds) => gradient.createShader(
        Rect.fromLTWH(0, 0, bounds.width, bounds.height),
      ),
      child: Text(text, style: style),
    );
  }
}

/// Animated glow container
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
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(borderRadius),
        boxShadow: [
          BoxShadow(
            color: glowColor.withValues(alpha: 0.3),
            blurRadius: blurRadius,
            spreadRadius: 0,
          ),
        ],
      ),
      child: child,
    );
  }
}

/// Pulsating dot indicator
class PulsatingDot extends StatefulWidget {
  final Color color;
  final double size;

  const PulsatingDot({
    super.key,
    this.color = AppColors.safe,
    this.size = 10,
  });

  @override
  State<PulsatingDot> createState() => _PulsatingDotState();
}

class _PulsatingDotState extends State<PulsatingDot>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    )..repeat(reverse: true);
    _animation = Tween<double>(begin: 0.4, end: 1.0).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animation,
      builder: (context, child) {
        return Container(
          width: widget.size,
          height: widget.size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: widget.color,
            boxShadow: [
              BoxShadow(
                color: widget.color.withValues(alpha: _animation.value * 0.6),
                blurRadius: widget.size * _animation.value,
                spreadRadius: widget.size * 0.2 * _animation.value,
              ),
            ],
          ),
        );
      },
    );
  }
}

/// Shield icon with verdict coloring
class VerdictShield extends StatelessWidget {
  final String verdict;
  final double size;

  const VerdictShield({
    super.key,
    required this.verdict,
    this.size = 80,
  });

  Color get _color {
    switch (verdict) {
      case 'malicious':
        return AppColors.danger;
      case 'clean':
        return AppColors.safe;
      default:
        return AppColors.warning;
    }
  }

  IconData get _icon {
    switch (verdict) {
      case 'malicious':
        return Icons.gpp_bad_rounded;
      case 'clean':
        return Icons.verified_user_rounded;
      default:
        return Icons.shield_rounded;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        boxShadow: [
          BoxShadow(
            color: _color.withValues(alpha: 0.4),
            blurRadius: 30,
            spreadRadius: 5,
          ),
        ],
      ),
      child: Icon(
        _icon,
        size: size,
        color: _color,
      ),
    );
  }
}
