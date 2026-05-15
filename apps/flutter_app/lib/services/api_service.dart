import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

class AnalysisResult {
  final String url;
  final String? originalInput;
  final String normalizedUrl;
  final String finalVerdict;
  final double? confidence;
  final double? maliciousProbability;
  final double? cleanProbability;
  final String decidedBy;
  final List<StageResult> stages;

  AnalysisResult({
    required this.url,
    this.originalInput,
    required this.normalizedUrl,
    required this.finalVerdict,
    this.confidence,
    this.maliciousProbability,
    this.cleanProbability,
    required this.decidedBy,
    required this.stages,
  });

  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    return AnalysisResult(
      url: json['url'] ?? '',
      originalInput: json['original_input'],
      normalizedUrl: json['normalized_url'] ?? '',
      finalVerdict: json['final_verdict'] ?? 'unknown',
      confidence: (json['confidence'] as num?)?.toDouble(),
      maliciousProbability: (json['malicious_probability'] as num?)?.toDouble(),
      cleanProbability: (json['clean_probability'] as num?)?.toDouble(),
      decidedBy: json['decided_by'] ?? '',
      stages:
          (json['stages'] as List<dynamic>?)
              ?.map((s) => StageResult.fromJson(s))
              .toList() ??
          [],
    );
  }

  bool get isMalicious => finalVerdict == 'malicious';
  bool get isClean => finalVerdict == 'clean';
  bool get isUnknown => finalVerdict == 'unknown';

  double get confidencePercent => (confidence ?? 0.0) * 100;
  double get maliciousPercent => (maliciousProbability ?? 0.0) * 100;
  double get cleanPercent => (cleanProbability ?? 0.0) * 100;
}

class StageResult {
  final String scanner;
  final String verdict;
  final double? confidence;
  final double? maliciousProbability;
  final double? cleanProbability;
  final String? reason;
  final Map<String, dynamic> details;

  StageResult({
    required this.scanner,
    required this.verdict,
    this.confidence,
    this.maliciousProbability,
    this.cleanProbability,
    this.reason,
    required this.details,
  });

  factory StageResult.fromJson(Map<String, dynamic> json) {
    return StageResult(
      scanner: json['scanner'] ?? '',
      verdict: json['verdict'] ?? 'unknown',
      confidence: (json['confidence'] as num?)?.toDouble(),
      maliciousProbability: (json['malicious_probability'] as num?)?.toDouble(),
      cleanProbability: (json['clean_probability'] as num?)?.toDouble(),
      reason: json['reason'],
      details: Map<String, dynamic>.from(json['details'] ?? {}),
    );
  }
}

class BatchAnalysisSummary {
  final int submitted;
  final int analyzed;
  final int malicious;
  final int clean;
  final int unknown;
  final int invalid;

  BatchAnalysisSummary({
    required this.submitted,
    required this.analyzed,
    required this.malicious,
    required this.clean,
    required this.unknown,
    required this.invalid,
  });

  factory BatchAnalysisSummary.fromJson(Map<String, dynamic> json) {
    return BatchAnalysisSummary(
      submitted: json['submitted'] ?? 0,
      analyzed: json['analyzed'] ?? 0,
      malicious: json['malicious'] ?? 0,
      clean: json['clean'] ?? 0,
      unknown: json['unknown'] ?? 0,
      invalid: json['invalid'] ?? 0,
    );
  }
}

class BatchAnalysisItem {
  final int index;
  final String input;
  final String? normalizedUrl;
  final String finalVerdict;
  final double? confidence;
  final double? riskScore;
  final double? maliciousProbability;
  final double? cleanProbability;
  final String? summary;
  final String? error;

  BatchAnalysisItem({
    required this.index,
    required this.input,
    this.normalizedUrl,
    required this.finalVerdict,
    this.confidence,
    this.riskScore,
    this.maliciousProbability,
    this.cleanProbability,
    this.summary,
    this.error,
  });

  factory BatchAnalysisItem.fromJson(Map<String, dynamic> json) {
    return BatchAnalysisItem(
      index: json['index'] ?? 0,
      input: json['input'] ?? '',
      normalizedUrl: json['normalized_url'],
      finalVerdict: json['final_verdict'] ?? 'unknown',
      confidence: (json['confidence'] as num?)?.toDouble(),
      riskScore: (json['risk_score'] as num?)?.toDouble(),
      maliciousProbability: (json['malicious_probability'] as num?)?.toDouble(),
      cleanProbability: (json['clean_probability'] as num?)?.toDouble(),
      summary: json['summary'],
      error: json['error'],
    );
  }

  bool get isMalicious => finalVerdict == 'malicious';
  bool get isClean => finalVerdict == 'clean';
  bool get isUnknown => finalVerdict == 'unknown';
  bool get isInvalid => finalVerdict == 'invalid';

  double get riskPercent => ((riskScore ?? maliciousProbability ?? 0.0) * 100)
      .clamp(0.0, 100.0)
      .toDouble();
}

class BatchAnalysisResult {
  final String filename;
  final BatchAnalysisSummary summary;
  final List<BatchAnalysisItem> results;

  BatchAnalysisResult({
    required this.filename,
    required this.summary,
    required this.results,
  });

  factory BatchAnalysisResult.fromJson(Map<String, dynamic> json) {
    return BatchAnalysisResult(
      filename: json['filename'] ?? 'uploaded_urls.txt',
      summary: BatchAnalysisSummary.fromJson(
        Map<String, dynamic>.from(json['summary'] ?? {}),
      ),
      results:
          (json['results'] as List<dynamic>?)
              ?.map((item) => BatchAnalysisItem.fromJson(item))
              .toList() ??
          [],
    );
  }
}

class AdminObservationItem {
  final int id;
  final String url;
  final String? normalizedUrl;
  final String? finalUrl;
  final String? domain;
  final String source;
  final String scannedAt;
  final String finalVerdict;
  final double? riskScore;
  final double? confidence;
  final double? maliciousProbability;
  final double? cleanProbability;
  final bool hasUrlFeatures;
  final bool hasHtmlFeatures;
  final int stageCount;

  AdminObservationItem({
    required this.id,
    required this.url,
    this.normalizedUrl,
    this.finalUrl,
    this.domain,
    required this.source,
    required this.scannedAt,
    required this.finalVerdict,
    this.riskScore,
    this.confidence,
    this.maliciousProbability,
    this.cleanProbability,
    required this.hasUrlFeatures,
    required this.hasHtmlFeatures,
    required this.stageCount,
  });

  factory AdminObservationItem.fromJson(Map<String, dynamic> json) {
    return AdminObservationItem(
      id: json['id'] ?? 0,
      url: json['url'] ?? '',
      normalizedUrl: json['normalized_url'],
      finalUrl: json['final_url'],
      domain: json['domain'],
      source: json['source'] ?? 'unknown',
      scannedAt: json['scanned_at'] ?? '',
      finalVerdict: json['final_verdict'] ?? 'unknown',
      riskScore: (json['risk_score'] as num?)?.toDouble(),
      confidence: (json['confidence'] as num?)?.toDouble(),
      maliciousProbability: (json['malicious_probability'] as num?)?.toDouble(),
      cleanProbability: (json['clean_probability'] as num?)?.toDouble(),
      hasUrlFeatures: json['has_url_features'] == true,
      hasHtmlFeatures: json['has_html_features'] == true,
      stageCount: json['stage_count'] ?? 0,
    );
  }

  double get riskPercent => ((riskScore ?? maliciousProbability ?? 0.0) * 100)
      .clamp(0.0, 100.0)
      .toDouble();
}

class AdminObservationDetail extends AdminObservationItem {
  final Map<String, dynamic>? urlFeatures;
  final Map<String, dynamic>? htmlFeatures;
  final List<Map<String, dynamic>> scannerResults;

  AdminObservationDetail({
    required super.id,
    required super.url,
    super.normalizedUrl,
    super.finalUrl,
    super.domain,
    required super.source,
    required super.scannedAt,
    required super.finalVerdict,
    super.riskScore,
    super.confidence,
    super.maliciousProbability,
    super.cleanProbability,
    required super.hasUrlFeatures,
    required super.hasHtmlFeatures,
    required super.stageCount,
    this.urlFeatures,
    this.htmlFeatures,
    required this.scannerResults,
  });

  factory AdminObservationDetail.fromJson(Map<String, dynamic> json) {
    final base = AdminObservationItem.fromJson(json);
    return AdminObservationDetail(
      id: base.id,
      url: base.url,
      normalizedUrl: base.normalizedUrl,
      finalUrl: base.finalUrl,
      domain: base.domain,
      source: base.source,
      scannedAt: base.scannedAt,
      finalVerdict: base.finalVerdict,
      riskScore: base.riskScore,
      confidence: base.confidence,
      maliciousProbability: base.maliciousProbability,
      cleanProbability: base.cleanProbability,
      hasUrlFeatures: base.hasUrlFeatures,
      hasHtmlFeatures: base.hasHtmlFeatures,
      stageCount: base.stageCount,
      urlFeatures: json['url_features'] is Map
          ? Map<String, dynamic>.from(json['url_features'])
          : null,
      htmlFeatures: json['html_features'] is Map
          ? Map<String, dynamic>.from(json['html_features'])
          : null,
      scannerResults:
          (json['scanner_results'] as List<dynamic>?)
              ?.whereType<Map>()
              .map((item) => Map<String, dynamic>.from(item))
              .toList() ??
          [],
    );
  }
}

class AdminObservationPage {
  final int total;
  final int limit;
  final int offset;
  final List<AdminObservationItem> results;

  AdminObservationPage({
    required this.total,
    required this.limit,
    required this.offset,
    required this.results,
  });

  factory AdminObservationPage.fromJson(Map<String, dynamic> json) {
    return AdminObservationPage(
      total: json['total'] ?? 0,
      limit: json['limit'] ?? 50,
      offset: json['offset'] ?? 0,
      results:
          (json['results'] as List<dynamic>?)
              ?.map((item) => AdminObservationItem.fromJson(item))
              .toList() ??
          [],
    );
  }
}

class AdminTrainingSampleItem {
  final int id;
  final int? observationId;
  final String url;
  final String? finalUrl;
  final String? domain;
  final int label;
  final String labelSource;
  final double labelConfidence;
  final bool approvedForTraining;
  final String createdAt;
  final bool hasUrlFeatures;
  final bool hasHtmlFeatures;
  final String? notes;

  AdminTrainingSampleItem({
    required this.id,
    this.observationId,
    required this.url,
    this.finalUrl,
    this.domain,
    required this.label,
    required this.labelSource,
    required this.labelConfidence,
    required this.approvedForTraining,
    required this.createdAt,
    required this.hasUrlFeatures,
    required this.hasHtmlFeatures,
    this.notes,
  });

  factory AdminTrainingSampleItem.fromJson(Map<String, dynamic> json) {
    return AdminTrainingSampleItem(
      id: json['id'] ?? 0,
      observationId: json['observation_id'],
      url: json['url'] ?? '',
      finalUrl: json['final_url'],
      domain: json['domain'],
      label: json['label'] ?? 0,
      labelSource: json['label_source'] ?? 'unknown',
      labelConfidence: (json['label_confidence'] as num?)?.toDouble() ?? 0,
      approvedForTraining: json['approved_for_training'] == true,
      createdAt: json['created_at'] ?? '',
      hasUrlFeatures: json['has_url_features'] == true,
      hasHtmlFeatures: json['has_html_features'] == true,
      notes: json['notes'],
    );
  }
}

class AdminTrainingSamplePage {
  final int total;
  final int limit;
  final int offset;
  final List<AdminTrainingSampleItem> results;

  AdminTrainingSamplePage({
    required this.total,
    required this.limit,
    required this.offset,
    required this.results,
  });

  factory AdminTrainingSamplePage.fromJson(Map<String, dynamic> json) {
    return AdminTrainingSamplePage(
      total: json['total'] ?? 0,
      limit: json['limit'] ?? 50,
      offset: json['offset'] ?? 0,
      results:
          (json['results'] as List<dynamic>?)
              ?.map((item) => AdminTrainingSampleItem.fromJson(item))
              .toList() ??
          [],
    );
  }
}

class AdminTrainingSampleActionResult {
  final int id;
  final String normalizedUrl;
  final int label;
  final String labelSource;
  final bool htmlFeaturesAvailable;

  AdminTrainingSampleActionResult({
    required this.id,
    required this.normalizedUrl,
    required this.label,
    required this.labelSource,
    required this.htmlFeaturesAvailable,
  });

  factory AdminTrainingSampleActionResult.fromJson(Map<String, dynamic> json) {
    return AdminTrainingSampleActionResult(
      id: json['id'] ?? 0,
      normalizedUrl: json['normalized_url'] ?? json['url'] ?? '',
      label: json['label'] ?? 0,
      labelSource: json['label_source'] ?? 'unknown',
      htmlFeaturesAvailable: json['html_features_available'] == true,
    );
  }
}

class AdminBulkTrainingResult {
  final int submitted;
  final int created;
  final int invalid;

  AdminBulkTrainingResult({
    required this.submitted,
    required this.created,
    required this.invalid,
  });

  factory AdminBulkTrainingResult.fromJson(Map<String, dynamic> json) {
    return AdminBulkTrainingResult(
      submitted: json['submitted'] ?? 0,
      created: json['created'] ?? 0,
      invalid: json['invalid'] ?? 0,
    );
  }
}

class AdminLoginSession {
  final String accessToken;
  final int expiresIn;

  AdminLoginSession({required this.accessToken, required this.expiresIn});

  factory AdminLoginSession.fromJson(Map<String, dynamic> json) {
    return AdminLoginSession(
      accessToken: json['access_token'] ?? '',
      expiresIn: json['expires_in'] ?? 0,
    );
  }
}

class PhishCatchApiService {
  static const String _configuredBaseUrl = String.fromEnvironment(
    'PHISHCATCH_API_BASE_URL',
  );
  static const String _productionBaseUrl =
      'https://phishcatch-p4jc.onrender.com';

  static String get _baseUrl {
    if (_configuredBaseUrl.isNotEmpty) {
      return _configuredBaseUrl;
    }

    if (kReleaseMode) {
      return _productionBaseUrl;
    }

    if (kIsWeb) {
      return 'http://localhost:8001';
    }

    if (defaultTargetPlatform == TargetPlatform.android) {
      return 'http://10.0.2.2:8001';
    }

    return 'http://localhost:8001';
  }

  static Future<AnalysisResult> analyzeUrl(String url) async {
    final uri = Uri.parse('$_baseUrl/api/v1/analyze');

    try {
      final response = await http
          .post(
            uri,
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'url': url}),
          )
          .timeout(const Duration(seconds: 120));

      if (response.statusCode == 200) {
        return AnalysisResult.fromJson(jsonDecode(response.body));
      } else if (response.statusCode == 422) {
        final detail = jsonDecode(response.body);
        final msg = detail['detail']?[0]?['msg'] ?? 'Invalid URL';
        throw Exception(msg);
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } on TimeoutException {
      throw Exception('Analiz zaman asimina ugradi. Backend yogun olabilir.');
    } on http.ClientException {
      throw Exception('Backend baglantisi kurulamadi. Backend acik mi?');
    }
  }

  static Future<BatchAnalysisResult> analyzeUrlFile({
    required Uint8List bytes,
    required String filename,
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/analyze-file');
    final request = http.MultipartRequest('POST', uri)
      ..files.add(
        http.MultipartFile.fromBytes('file', bytes, filename: filename),
      );

    try {
      final streamedResponse = await request.send().timeout(
        const Duration(seconds: 180),
      );
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        return BatchAnalysisResult.fromJson(jsonDecode(response.body));
      }

      final decoded = _tryDecodeJson(response.body);
      final detail = decoded?['detail'];
      if (detail is String) {
        throw Exception(detail);
      }
      throw Exception('Server error: ${response.statusCode}');
    } on TimeoutException {
      throw Exception('Toplu analiz zamaninda tamamlanamadi.');
    } on http.ClientException {
      throw Exception('Backend baglantisi kurulamadi. Backend acik mi?');
    }
  }

  static Future<AdminLoginSession> loginAdmin({
    required String username,
    required String password,
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/admin/login');
    final response = await http
        .post(
          uri,
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'username': username, 'password': password}),
        )
        .timeout(const Duration(seconds: 30));
    _throwIfAdminError(response);
    return AdminLoginSession.fromJson(jsonDecode(response.body));
  }

  static Future<AdminObservationPage> listAdminObservations({
    required String token,
    int limit = 50,
    int offset = 0,
    String? finalVerdict,
    String? query,
  }) async {
    final params = <String, String>{
      'limit': '$limit',
      'offset': '$offset',
      if (finalVerdict != null && finalVerdict.isNotEmpty)
        'final_verdict': finalVerdict,
      if (query != null && query.trim().isNotEmpty) 'q': query.trim(),
    };
    final uri = Uri.parse(
      '$_baseUrl/api/v1/admin/observations',
    ).replace(queryParameters: params);
    final response = await _adminGet(uri, token);
    return AdminObservationPage.fromJson(jsonDecode(response.body));
  }

  static Future<AdminObservationDetail> getAdminObservation({
    required String token,
    required int id,
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/admin/observations/$id');
    final response = await _adminGet(uri, token);
    return AdminObservationDetail.fromJson(jsonDecode(response.body));
  }

  static Future<AdminTrainingSamplePage> listAdminTrainingSamples({
    required String token,
    int limit = 50,
    int offset = 0,
    bool approvedOnly = false,
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/admin/training-samples').replace(
      queryParameters: {
        'limit': '$limit',
        'offset': '$offset',
        'approved_only': '$approvedOnly',
      },
    );
    final response = await _adminGet(uri, token);
    return AdminTrainingSamplePage.fromJson(jsonDecode(response.body));
  }

  static Future<AdminTrainingSampleActionResult> addAdminTrainingSample({
    required String token,
    required String url,
    required int label,
    String source = 'admin_manual',
    String? notes,
  }) async {
    final uri = Uri.parse('$_baseUrl/api/v1/admin/training-samples');
    final response = await _adminPost(uri, token, {
      'url': url,
      'label': label,
      'source': source,
      'label_confidence': 1.0,
      'approved_for_training': true,
      if (notes != null && notes.trim().isNotEmpty) 'notes': notes.trim(),
    });
    return AdminTrainingSampleActionResult.fromJson(jsonDecode(response.body));
  }

  static Future<AdminTrainingSampleActionResult> addObservationToTraining({
    required String token,
    required int observationId,
    required int label,
    String source = 'admin_observation',
    String? notes,
  }) async {
    final uri = Uri.parse(
      '$_baseUrl/api/v1/admin/observations/$observationId/training-sample',
    );
    final response = await _adminPost(uri, token, {
      'label': label,
      'source': source,
      'label_confidence': 1.0,
      'approved_for_training': true,
      if (notes != null && notes.trim().isNotEmpty) 'notes': notes.trim(),
    });
    return AdminTrainingSampleActionResult.fromJson(jsonDecode(response.body));
  }

  static Future<AdminBulkTrainingResult> bulkAddObservationsToTraining({
    required String token,
    required List<int> observationIds,
    required int label,
    String source = 'admin_observation',
    String? notes,
  }) async {
    final uri = Uri.parse(
      '$_baseUrl/api/v1/admin/observations/bulk-training-samples',
    );
    final response = await _adminPost(uri, token, {
      'observation_ids': observationIds,
      'label': label,
      'source': source,
      'label_confidence': 1.0,
      'approved_for_training': true,
      if (notes != null && notes.trim().isNotEmpty) 'notes': notes.trim(),
    });
    return AdminBulkTrainingResult.fromJson(jsonDecode(response.body));
  }

  static Future<http.Response> _adminGet(Uri uri, String token) async {
    final response = await http
        .get(uri, headers: _adminHeaders(token))
        .timeout(const Duration(seconds: 60));
    _throwIfAdminError(response);
    return response;
  }

  static Future<http.Response> _adminPost(
    Uri uri,
    String token,
    Map<String, dynamic> body,
  ) async {
    final response = await http
        .post(uri, headers: _adminHeaders(token), body: jsonEncode(body))
        .timeout(const Duration(seconds: 60));
    _throwIfAdminError(response);
    return response;
  }

  static Map<String, String> _adminHeaders(String token) {
    return {'Content-Type': 'application/json', 'X-Admin-Token': token};
  }

  static void _throwIfAdminError(http.Response response) {
    if (response.statusCode >= 200 && response.statusCode < 300) return;
    final decoded = _tryDecodeJson(response.body);
    final detail = decoded?['detail'];
    throw Exception(
      detail is String ? detail : 'Admin API error: ${response.statusCode}',
    );
  }

  static Map<String, dynamic>? _tryDecodeJson(String body) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }
    } catch (_) {
      return null;
    }
    return null;
  }
}
