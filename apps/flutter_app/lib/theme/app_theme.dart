import 'package:flutter/material.dart';

/// Shared tokens keep mobile and administration screens aligned.
class AppColors {
  static const primary = Color(0xFF166D55);
  static const primaryLight = Color(0xFF278469);
  static const primaryDark = Color(0xFF104C3C);
  static const accent = primary;
  static const accentGlow = Color(0x19166D55);
  static const electric = primary;
  static const magenta = Color(0xFF7C537D);
  static const bgDark = Color(0xFFF4F6F5);
  static const bgCard = Colors.white;
  static const bgCardLight = Color(0xFFF0F4F2);
  static const bgSurface = Colors.white;
  static const safe = Color(0xFF166D55);
  static const safeGlow = Color(0x19166D55);
  static const danger = Color(0xFFB23D39);
  static const dangerGlow = Color(0x19B23D39);
  static const warning = Color(0xFF8C6118);
  static const warningGlow = Color(0x198C6118);
  static const unknown = Color(0xFF626E69);
  static const textPrimary = Color(0xFF1C2C25);
  static const textSecondary = Color(0xFF53655B);
  static const textMuted = Color(0xFF5D6D64);
  static const glassWhite = Colors.white;
  static const glassBorder = Color(0xFFDCE4DF);
  static const primaryGradient = LinearGradient(colors: [primary, primaryDark]);
  static const bgGradient = LinearGradient(colors: [bgDark, bgDark]);
  static const dangerGradient = LinearGradient(colors: [danger, danger]);
  static const safeGradient = LinearGradient(colors: [safe, safe]);
}

class AppTheme {
  static ThemeData get lightTheme => ThemeData(
    useMaterial3: true,
    brightness: Brightness.light,
    colorScheme: ColorScheme.fromSeed(
      seedColor: AppColors.primary,
      brightness: Brightness.light,
      surface: AppColors.bgCard,
      error: AppColors.danger,
    ),
    scaffoldBackgroundColor: AppColors.bgDark,
    pageTransitionsTheme: const PageTransitionsTheme(
      builders: {
        TargetPlatform.android: _SubtlePageTransition(),
        TargetPlatform.iOS: _SubtlePageTransition(),
        TargetPlatform.macOS: _SubtlePageTransition(),
        TargetPlatform.windows: _SubtlePageTransition(),
        TargetPlatform.linux: _SubtlePageTransition(),
      },
    ),
    fontFamily: 'Arial',
    textTheme: ThemeData.light().textTheme.apply(
      bodyColor: AppColors.textPrimary,
      displayColor: AppColors.textPrimary,
      fontFamily: 'Arial',
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.bgDark,
      foregroundColor: AppColors.textPrimary,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        color: AppColors.textPrimary,
        fontSize: 18,
        fontWeight: FontWeight.w600,
      ),
    ),
    dividerTheme: const DividerThemeData(color: AppColors.glassBorder),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AppColors.bgCard,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 18),
      border: _border(),
      enabledBorder: _border(),
      focusedBorder: _border(AppColors.primary, 1.6),
      errorBorder: _border(AppColors.danger),
      hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 15),
      labelStyle: const TextStyle(color: AppColors.textSecondary),
    ),
    filledButtonTheme: FilledButtonThemeData(style: _buttonStyle()),
    elevatedButtonTheme: ElevatedButtonThemeData(style: _buttonStyle()),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.primary,
        minimumSize: const Size(48, 52),
        side: const BorderSide(color: AppColors.glassBorder),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: AppColors.primary,
        minimumSize: const Size(48, 48),
      ),
    ),
    iconButtonTheme: IconButtonThemeData(
      style: IconButton.styleFrom(minimumSize: const Size(48, 48)),
    ),
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
  );

  // Compatibility with the existing app entry point.
  static ThemeData get darkTheme => lightTheme;

  static OutlineInputBorder _border([
    Color color = AppColors.glassBorder,
    double width = 1,
  ]) => OutlineInputBorder(
    borderRadius: BorderRadius.circular(12),
    borderSide: BorderSide(color: color, width: width),
  );
  static ButtonStyle _buttonStyle() => FilledButton.styleFrom(
    backgroundColor: AppColors.primary,
    foregroundColor: Colors.white,
    disabledBackgroundColor: AppColors.bgCardLight,
    disabledForegroundColor: AppColors.textMuted,
    minimumSize: const Size(48, 54),
    elevation: 0,
    textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
    padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 18),
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
  );
}

class _SubtlePageTransition extends PageTransitionsBuilder {
  const _SubtlePageTransition();
  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    if (MediaQuery.disableAnimationsOf(context)) return child;
    return FadeTransition(
      opacity: animation.drive(CurveTween(curve: Curves.easeOut)),
      child: child,
    );
  }
}
