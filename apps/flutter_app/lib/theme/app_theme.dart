import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppColors {
  // Primary gradient colors
  static const Color primary = Color(0xFF6C63FF);
  static const Color primaryLight = Color(0xFF8F7CFF);
  static const Color primaryDark = Color(0xFF302B9B);

  // Accent/secondary
  static const Color accent = Color(0xFF25D6A2);
  static const Color accentGlow = Color(0x4025D6A2);
  static const Color electric = Color(0xFF19D4F2);
  static const Color magenta = Color(0xFFFF4FD8);

  // Background palette
  static const Color bgDark = Color(0xFF050817);
  static const Color bgCard = Color(0xFF111525);
  static const Color bgCardLight = Color(0xFF24283A);
  static const Color bgSurface = Color(0xFF090D1D);

  // Status colors
  static const Color safe = Color(0xFF2DE38B);
  static const Color safeGlow = Color(0x402DE38B);
  static const Color danger = Color(0xFFFF4D6D);
  static const Color dangerGlow = Color(0x40FF4D6D);
  static const Color warning = Color(0xFFFFC857);
  static const Color warningGlow = Color(0x40FFC857);
  static const Color unknown = Color(0xFF8F94AB);

  // Text
  static const Color textPrimary = Color(0xFFF0F1F5);
  static const Color textSecondary = Color(0xFF8F94AB);
  static const Color textMuted = Color(0xFF5A5F7A);

  // Glass
  static const Color glassWhite = Color(0x14FFFFFF);
  static const Color glassBorder = Color(0x26FFFFFF);

  // Gradients
  static const LinearGradient primaryGradient = LinearGradient(
    colors: [primary, Color(0xFF328BFF), electric],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient bgGradient = LinearGradient(
    colors: [Color(0xFF060919), Color(0xFF080D20), bgDark],
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
  );

  static const LinearGradient dangerGradient = LinearGradient(
    colors: [danger, Color(0xFFFF6B9D)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient safeGradient = LinearGradient(
    colors: [safe, Color(0xFF69F0AE)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );
}

class AppTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: AppColors.bgDark,
      colorScheme: const ColorScheme.dark(
        primary: AppColors.primary,
        secondary: AppColors.accent,
        surface: AppColors.bgCard,
        error: AppColors.danger,
      ),
      textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme).apply(
        bodyColor: AppColors.textPrimary,
        displayColor: AppColors.textPrimary,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        titleTextStyle: GoogleFonts.inter(
          fontSize: 20,
          fontWeight: FontWeight.w700,
          color: AppColors.textPrimary,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.bgCardLight,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 20,
          vertical: 18,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: AppColors.glassBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: AppColors.glassBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: AppColors.primary, width: 2),
        ),
        hintStyle: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 15),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle: GoogleFonts.inter(
            fontSize: 16,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }
}
