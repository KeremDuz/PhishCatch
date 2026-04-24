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
      stages: (json['stages'] as List<dynamic>?)
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

class PhishCatchApiService {
  static const String _configuredBaseUrl =
      String.fromEnvironment('PHISHCATCH_API_BASE_URL');

  static String get _baseUrl {
    if (_configuredBaseUrl.isNotEmpty) {
      return _configuredBaseUrl;
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

    final response = await http.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'url': url}),
    );

    if (response.statusCode == 200) {
      return AnalysisResult.fromJson(jsonDecode(response.body));
    } else if (response.statusCode == 422) {
      final detail = jsonDecode(response.body);
      final msg = detail['detail']?[0]?['msg'] ?? 'Invalid URL';
      throw Exception(msg);
    } else {
      throw Exception('Server error: ${response.statusCode}');
    }
  }
}
