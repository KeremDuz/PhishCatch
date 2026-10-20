import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'api_service.dart';
import 'server_origin.dart';
import 'session_transport.dart' as transport;

class ApiException implements Exception {
  final String message;
  final int? statusCode;

  const ApiException(this.message, {this.statusCode});

  @override
  String toString() => message;
}

class _MobileSession {
  final String? token;
  final DateTime? expiresAt;
  final Map<String, dynamic> user;

  _MobileSession(this.token, this.expiresAt, this.user);
}

/// Native tokens stay in memory; web sessions use same-origin HttpOnly cookies.
class ApiService extends ChangeNotifier {
  static const allowDebugHttp = bool.fromEnvironment(
    'PHISHCATCH_ALLOW_DEV_HTTP',
  );
  static const _configuredStandalone = String.fromEnvironment(
    'PHISHCATCH_API_BASE_URL',
  );
  static const _configuredAllsafe = String.fromEnvironment(
    'ALLSAFE_API_BASE_URL',
  );
  static const _managedBuild = bool.fromEnvironment('ALLSAFE_MANAGED_MODE');
  static const _consumerBuild = bool.fromEnvironment(
    'PHISHCATCH_CONSUMER_MODE',
  );
  static const _renderServer = 'https://phishcatch-p4jc.onrender.com';
  static final ApiService shared = ApiService();

  final http.Client _client;
  final bool _ownsClient;
  final bool _allowDevelopmentHttp;
  final bool managedOnly;
  final bool consumerMode;
  final String? _browserOrigin;
  final String? Function() _csrfToken;
  final Uri _standaloneServer;
  Uri? _allsafeServer;
  _MobileSession? _session;
  int _connectionGeneration = 0;

  ApiService({
    http.Client? client,
    String? standaloneBaseUrl,
    bool allowDevelopmentHttp = allowDebugHttp,
    this.managedOnly = _managedBuild,
    this.consumerMode = _consumerBuild,
    String? allsafeBaseUrl,
    String? browserOrigin,
    String? Function()? csrfToken,
  }) : _client =
           client ??
           (consumerMode ? http.Client() : transport.createSessionClient()),
       _ownsClient = client == null,
       _browserOrigin = browserOrigin ?? transport.browserOrigin(),
       _csrfToken = csrfToken ?? transport.readCsrfToken,
       _allowDevelopmentHttp = allowDevelopmentHttp,
       _standaloneServer = parseServerOrigin(
         (consumerMode ? (browserOrigin ?? transport.browserOrigin()) : null) ??
             standaloneBaseUrl ??
             (managedOnly
                 ? 'https://standalone.invalid'
                 : defaultStandaloneBaseUrl),
         allowDevelopmentHttp: allowDevelopmentHttp,
       ) {
    final configured = allsafeBaseUrl ?? _configuredAllsafe;
    if (consumerMode && managedOnly) {
      throw const ApiException('Uygulama yapılandırması geçersiz.');
    }
    if (!consumerMode && (managedOnly || configured.isNotEmpty)) {
      final origin = _browserOrigin ?? configured;
      _allsafeServer = parseServerOrigin(
        origin,
        allowDevelopmentHttp: allowDevelopmentHttp,
      );
    }
  }

  static String get defaultStandaloneBaseUrl {
    if (_managedBuild) return 'https://standalone.invalid';
    if (_configuredStandalone.isNotEmpty) return _configuredStandalone;
    if (_consumerBuild) return 'https://unconfigured.invalid';
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
  bool get isBrowserSession => _browserOrigin != null;
  Uri? get allsafeServer => _allsafeServer;
  bool get isSignedIn =>
      _session != null &&
      (_session!.expiresAt == null ||
          _session!.expiresAt!.isAfter(DateTime.now()));
  Map<String, dynamic>? get currentUser =>
      isSignedIn ? Map.unmodifiable(_session!.user) : null;

  void useAllsafe(String server) {
    if (consumerMode) {
      throw const ApiException(
        'Bu uygulama PhishCatch analiz hizmetini kullanır.',
      );
    }
    final validated = parseServerOrigin(
      server,
      allowDevelopmentHttp: _allowDevelopmentHttp,
    );
    if (_browserOrigin != null &&
        validated.origin != Uri.parse(_browserOrigin).origin) {
      throw const ApiException(
        'Web uygulaması kendi ALLSAFE sunucusunu kullanır. Diğer sunucunun web adresini açın.',
      );
    }
    _connectionGeneration++;
    _session = null;
    _allsafeServer = validated;
    notifyListeners();
  }

  void useStandalone() {
    if (managedOnly) {
      throw const ApiException(
        'Bu sürüm ALLSAFE kurum bağlantısı için hazırlanmıştır.',
      );
    }
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
      isBrowserSession ? 'api/v1/auth/login' : 'api/v1/auth/mobile/login',
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
    if (isBrowserSession) {
      if (generation != _connectionGeneration || server != _allsafeServer) {
        throw const ApiException('Bağlantı değişti. Yeniden giriş yapın.');
      }
      _session = _MobileSession(null, null, data);
      notifyListeners();
      return;
    }
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

  Future<void> restoreWebSession() async {
    final server = _allsafeServer;
    if (!isBrowserSession || server == null) return;
    final generation = _connectionGeneration;
    try {
      final response = await _request(server, 'GET', 'api/v1/auth/me');
      if (generation != _connectionGeneration || server != _allsafeServer) {
        return;
      }
      if (response.statusCode == 401) return;
      _checkSuccess(response);
      _session = _MobileSession(null, null, _object(response.body));
      notifyListeners();
    } on ApiException {
      // A failed restore remains signed out; it never selects another service.
    }
  }

  Future<List<Map<String, dynamic>>> scanHistory() async {
    final response = await _authenticatedRequest(
      'GET',
      'api/v1/phishcatch/scans?limit=50',
    );
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is List &&
          decoded.every((item) => item is Map<String, dynamic>)) {
        return decoded
            .map((item) => Map<String, dynamic>.from(item as Map))
            .toList();
      }
    } on FormatException {
      throw const ApiException('Geçmiş yanıtı okunamadı.');
    }
    throw const ApiException('Geçmiş yanıtı geçersiz.');
  }

  Future<void> logout() async {
    final server = _allsafeServer;
    final session = _session;
    final generation = ++_connectionGeneration;
    if (!isBrowserSession) {
      _session = null;
      notifyListeners();
    }
    if (server == null || session == null) return;
    final response = await _request(
      server,
      'POST',
      isBrowserSession ? 'api/v1/auth/logout' : 'api/v1/auth/mobile/logout',
      token: session.token,
    );
    if (response.statusCode != 401) _checkSuccess(response);
    if (isBrowserSession &&
        generation == _connectionGeneration &&
        identical(_session, session)) {
      _session = null;
      notifyListeners();
    }
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
    if (consumerMode) {
      final response = await _request(
        _standaloneServer,
        'POST',
        'api/v1/public/analyze',
        body: {
          'url': url,
          'source': source,
          'client_request_id': clientRequestId ?? newClientRequestId(),
        },
      );
      _checkSuccess(response);
      return AnalysisResult.fromConsumerJson(_object(response.body));
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
    if (isBrowserSession &&
        server == _allsafeServer &&
        token == null &&
        !{'GET', 'HEAD', 'OPTIONS'}.contains(method)) {
      final csrf = _csrfToken();
      if (csrf != null) request.headers['X-CSRF-Token'] = csrf;
    }
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
    if (response.statusCode == 429) {
      throw const ApiException(
        'Şu anda yoğunluk var. Biraz sonra yeniden deneyin.',
        statusCode: 429,
      );
    }
    if (response.statusCode == 503 || response.statusCode == 504) {
      throw const ApiException(
        'Analiz tamamlanamadı. Biraz sonra yeniden deneyin.',
        statusCode: 503,
      );
    }
    if (response.statusCode == 401) {
      throw const ApiException(
        'Oturum gecersiz veya suresi doldu. Yeniden giris yapin.',
        statusCode: 401,
      );
    }
    throw ApiException(
      'Bağlantı analiz edilemedi. Adresi kontrol edip yeniden deneyin.',
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
