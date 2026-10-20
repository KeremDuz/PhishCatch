import 'dart:js_interop';

import 'package:http/browser_client.dart';
import 'package:http/http.dart' as http;

@JS('document.cookie')
external String get _documentCookie;

http.Client createSessionClient() => BrowserClient()..withCredentials = true;
String? browserOrigin() => Uri.base.origin;
String? readCsrfToken() {
  for (final cookie in _documentCookie.split(';')) {
    final parts = cookie.trim().split('=');
    if (parts.length == 2 && parts.first == 'allsafe_csrf') {
      return Uri.decodeComponent(parts.last);
    }
  }
  return null;
}
