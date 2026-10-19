import 'package:flutter/foundation.dart';

Uri validateServerOrigin(String value, {bool allowDevelopmentHttp = false}) {
  final uri = Uri.tryParse(value.trim());
  if (uri == null ||
      !uri.isAbsolute ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      uri.hasFragment ||
      (uri.path.isNotEmpty && uri.path != '/') ||
      value.contains('@') ||
      value.contains('?') ||
      value.contains('#')) {
    throw ArgumentError('Sunucu adresi yalnizca HTTPS sunucu kokunu icermeli.');
  }
  final local = {
    'localhost',
    '127.0.0.1',
    '::1',
    '[::1]',
    '10.0.2.2',
  }.contains(uri.host.toLowerCase());
  if (uri.scheme != 'https' &&
      !(uri.scheme == 'http' && kDebugMode && allowDevelopmentHttp && local)) {
    throw ArgumentError(
      'HTTPS gerekli. Yerel HTTP yalnizca acik gelistirme izniyle kullanilabilir.',
    );
  }
  return uri.replace(path: '/', query: null, fragment: null);
}
