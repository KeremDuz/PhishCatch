import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_web_plugins/url_strategy.dart';

import 'screens/admin_screen.dart';
import 'screens/home_screen.dart';
import 'screens/standalone_tools_screen.dart';
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
  if (!ApiService.shared.consumerMode) {
    unawaited(ApiService.shared.restoreWebSession());
  }
}

class PhishCatchApp extends StatelessWidget {
  const PhishCatchApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: ApiService.shared.consumerMode
          ? 'PhishCatch'
          : 'ALLSAFE · PhishCatch',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      initialRoute: _initialRoute(),
      routes: {
        '/': (_) => const HomeScreen(),
        if (!ApiService.shared.consumerMode)
          '/admin': (_) => const AdminScreen(),
        if (!ApiService.shared.consumerMode)
          '/tools': (_) => const StandaloneToolsScreen(),
      },
      onUnknownRoute: (_) =>
          MaterialPageRoute(builder: (_) => const HomeScreen()),
    );
  }

  String _initialRoute() {
    if (ApiService.shared.consumerMode) return '/';
    final uri = Uri.base;
    final path = uri.path.toLowerCase();
    final fragment = uri.fragment.toLowerCase();
    if (path == '/admin' || fragment == '/admin' || fragment == 'admin') {
      return '/admin';
    }
    return '/';
  }
}
