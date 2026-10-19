import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'api_service.dart';
import 'server_origin.dart';

class ApiException implements Exception {
  final String message;
  final int? statusCode;

  const ApiException(this.message, {this.statusCode});

  @override
  String toString() => message;
}

class _MobileSession {
  final String token;
  final DateTime expiresAt;
  final Map<String, dynamic> user;

  _MobileSession(this.token, this.expiresAt, this.user);
}

/// ALLSAFE authentication is deliberately held only in this process's memory.
class ApiService extends ChangeNotifier {
  static const allowDebugHttp = bool.fromEnvironment(
    'PHISHCATCH_ALLOW_DEV_HTTP',
  );
  static const _configuredStandalone = String.fromEnvironment(
    'PHISHCATCH_API_BASE_URL',
  );
  static const _renderServer = 'https://phishcatch-p4jc.onrender.com';
  static final ApiService shared = ApiService();

  final http.Client _client;
  final bool _ownsClient;
  final bool _allowDevelopmentHttp;
  final Uri _standaloneServer;
  Uri? _allsafeServer;
  _MobileSession? _session;
  int _connectionGeneration = 0;

  ApiService({
    http.Client? client,
    String? standaloneBaseUrl,
    bool allowDevelopmentHttp = allowDebugHttp,
  }) : _client = client ?? http.Client(),
       _ownsClient = client == null,
       _allowDevelopmentHttp = allowDevelopmentHttp,
       _standaloneServer = parseServerOrigin(
         standaloneBaseUrl ?? defaultStandaloneBaseUrl,
         allowDevelopmentHttp: allowDevelopmentHttp,
       );

  static String get defaultStandaloneBaseUrl {
    if (_configuredStandalone.isNotEmpty) return _configuredStandalone;
    if (kDebugMode && allowDebugHttp) {
      return !kIsWeb && defaultTargetPlatform == TargetPlatform.android
          ? 'http://10.0.2.2:8001'
          : 'http://localhost:8001';
    }
    return _renderServer;
  }

  static Uri parseServerOrigin(
    String value, {
    bool allowDevelopmentHttp = false,
  }) {
    try {
      return validateServerOrigin(
        value,
        allowDevelopmentHttp: allowDevelopmentHttp,
      );
    } on ArgumentError {
      throw const ApiException(
        'HTTPS sunucu kok adresi gerekli; yerel HTTP icin gelistirme izni gerekir.',
      );
    } on FormatException {
      throw const ApiException('Sunucu adresi gecersiz.');
    }
  }

  bool get isAllsafe => _allsafeServer != null;
  Uri? get allsafeServer => _allsafeServer;
  bool get isSignedIn =>
      _session != null && _session!.expiresAt.isAfter(DateTime.now());
  Map<String, dynamic>? get currentUser =>
      isSignedIn ? Map.unmodifiable(_session!.user) : null;

  void useAllsafe(String server) {
    final validated = parseServerOrigin(
      server,
      allowDevelopmentHttp: _allowDevelopmentHttp,
    );
    _connectionGeneration++;
    _session = null;
    _allsafeServer = validated;
    notifyListeners();
  }

  void useStandalone() {
    _connectionGeneration++;
    _session = null;
    _allsafeServer = null;
    notifyListeners();
  }

  Future<void> login({required String email, required String password}) async {
    final server = _allsafeServer;
    if (server == null) {
      throw const ApiException('Once ALLSAFE baglantisini secin.');
    }
    _session = null;
    notifyListeners();
    final generation = ++_connectionGeneration;
    final response = await _request(
      server,
      'POST',
      'api/v1/auth/mobile/login',
      body: {'email': email.trim(), 'password': password},
    );
    if (response.statusCode == 409) {
      throw const ApiException(
        'Bu kurum icin mobil OIDC girisi henuz desteklenmiyor.',
        statusCode: 409,
      );
    }
    _checkSuccess(response);
    final data = _object(response.body);
    final token = data['access_token'];
    final expires = data['expires_in'];
    final user = data['user'];
    if (token is! String ||
        token.isEmpty ||
        token.contains(RegExp(r'\s')) ||
        data['token_type'] != 'bearer' ||
        expires is! int ||
        expires <= 0 ||
        user is! Map) {
      throw const ApiException('Sunucunun oturum yaniti gecersiz.');
    }
    if (generation != _connectionGeneration || server != _allsafeServer) {
      throw const ApiException('Baglanti degisti. Yeniden giris yapin.');
    }
    _session = _MobileSession(
      token,
      DateTime.now().add(Duration(seconds: expires)),
      Map<String, dynamic>.from(user),
    );
    notifyListeners();
  }

  Future<Map<String, dynamic>> me() async {
    final response = await _authenticatedRequest('GET', 'api/v1/auth/me');
    return _object(response.body);
  }

  Future<void> logout() async {
    final server = _allsafeServer;
    final session = _session;
    _connectionGeneration++;
    _session = null;
    notifyListeners();
    if (server == null || session == null) return;
    final response = await _request(
      server,
      'POST',
      'api/v1/auth/mobile/logout',
      token: session.token,
    );
    if (response.statusCode != 401) _checkSuccess(response);
  }

  static String newClientRequestId() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    final hex = bytes
        .map((value) => value.toRadixString(16).padLeft(2, '0'))
        .join();
    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
  }

  Future<AnalysisResult> analyzeUrl(
    String url, {
    String source = 'url',
    String? clientRequestId,
  }) async {
    if (source != 'url' && source != 'qr') {
      throw const ApiException('Tarama kaynagi gecersiz.');
    }
    if (!isAllsafe) {
      final response = await _request(
        _standaloneServer,
        'POST',
        'api/v1/analyze',
        body: {'url': url},
      );
      _checkSuccess(response);
      return AnalysisResult.fromJson(_object(response.body));
    }
    final response = await _authenticatedRequest(
      'POST',
      'api/v1/phishcatch/scans',
      body: {
        'url': url,
        'source': source,
        'client_request_id': clientRequestId ?? newClientRequestId(),
      },
    );
    final record = _object(response.body);
    final analysis = record['analysis'];
    if (analysis is! Map) {
      return AnalysisResult.unavailable(
        url,
        centralScanId: record['id'] as String?,
      );
    }
    return AnalysisResult.fromJson(
      Map<String, dynamic>.from(analysis),
      scanStatusOverride: record['scan_status'] as String?,
      centralScanId: record['id'] as String?,
    );
  }

  Future<http.Response> _authenticatedRequest(
    String method,
    String path, {
    Map<String, dynamic>? body,
  }) async {
    final server = _allsafeServer;
    final session = _session;
    if (server == null || session == null || !isSignedIn) {
      _session = null;
      notifyListeners();
      throw const ApiException('ALLSAFE girisi gerekli.');
    }
    final response = await _request(
      server,
      method,
      path,
      body: body,
      token: session.token,
    );
    if (response.statusCode == 401 && identical(_session, session)) {
      _session = null;
      notifyListeners();
    }
    _checkSuccess(response);
    return response;
  }

  Future<http.Response> _request(
    Uri server,
    String method,
    String path, {
    Map<String, dynamic>? body,
    String? token,
  }) async {
    final request = http.Request(method, server.resolve(path))
      ..followRedirects = false;
    request.headers['Accept'] = 'application/json';
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    if (token != null) request.headers['Authorization'] = 'Bearer $token';
    try {
      final streamed = await _client
          .send(request)
          .timeout(const Duration(seconds: 120));
      return await http.Response.fromStream(
        streamed,
      ).timeout(const Duration(seconds: 120));
    } on TimeoutException {
      throw const ApiException(
        'Istek zamaninda tamamlanamadi. Ayni baglantiyi yeniden deneyebilirsiniz.',
      );
    } on http.ClientException {
      throw const ApiException('Sunucu baglantisi kurulamadi.');
    }
  }

  static void _checkSuccess(http.Response response) {
    if (response.statusCode >= 200 && response.statusCode < 300) return;
    if (response.statusCode == 401) {
      throw const ApiException(
        'Oturum gecersiz veya suresi doldu. Yeniden giris yapin.',
        statusCode: 401,
      );
    }
    throw ApiException(
      'Sunucu istegi kabul etmedi (${response.statusCode}).',
      statusCode: response.statusCode,
    );
  }

  static Map<String, dynamic> _object(String body) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map<String, dynamic>) return decoded;
    } on FormatException {
      // Server diagnostics are deliberately not included in user-visible errors.
    }
    throw const ApiException('Sunucu yaniti okunamadi.');
  }

  @override
  void dispose() {
    _session = null;
    if (_ownsClient) _client.close();
    super.dispose();
  }
}
