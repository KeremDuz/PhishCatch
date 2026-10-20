import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_web_plugins/url_strategy.dart';

import 'screens/admin_screen.dart';
import 'screens/home_screen.dart';
import 'theme/app_theme.dart';
import 'services/allsafe_api_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  usePathUrlStrategy();

  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
      systemNavigationBarColor: AppColors.bgDark,
      systemNavigationBarIconBrightness: Brightness.dark,
    ),
  );

  runApp(const PhishCatchApp());
  unawaited(ApiService.shared.restoreWebSession());
}

class PhishCatchApp extends StatelessWidget {
  const PhishCatchApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ALLSAFE · PhishCatch',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      initialRoute: _initialRoute(),
      routes: {
        '/': (_) => const HomeScreen(),
        '/admin': (_) => const AdminScreen(),
      },
      onUnknownRoute: (_) =>
          MaterialPageRoute(builder: (_) => const HomeScreen()),
    );
  }

  String _initialRoute() {
    final uri = Uri.base;
    final path = uri.path.toLowerCase();
    final fragment = uri.fragment.toLowerCase();
    if (path == '/admin' || fragment == '/admin' || fragment == 'admin') {
      return '/admin';
    }
    return '/';
  }
}
