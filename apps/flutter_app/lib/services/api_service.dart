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
