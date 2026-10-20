import 'package:flutter/material.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';

class ResultScreen extends StatelessWidget {
  final AnalysisResult result;
  const ResultScreen({super.key, required this.result});

  Color get _color => result.isMalicious
      ? AppColors.danger
      : result.isClean
      ? AppColors.safe
      : AppColors.warning;
  String get _title => result.isMalicious
      ? 'Riskli bağlantı'
      : result.isClean
      ? 'Risk belirtisi bulunamadı'
      : result.scanStatus == 'failed'
      ? 'Analiz tamamlanamadı'
      : 'Sonuç belirsiz';
  String get _description => result.isMalicious
      ? 'Bu bağlantıyı açmayın ve kişisel bilgilerinizi paylaşmayın.'
      : result.isClean
      ? 'Belirgin bir risk görülmedi. Bu sonuç tam güvence değildir.'
      : result.scanStatus != 'complete'
      ? 'Bağlantı tam olarak incelenemedi. Güvenli olduğunu söyleyemiyoruz.'
      : 'Kesin bir sonuç alınamadı. Bağlantıyı açarken dikkatli olun.';

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Sonuç')),
    body: SafeArea(
      child: Align(
        alignment: Alignment.topCenter,
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(24, 40, 24, 36),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Align(
                  alignment: Alignment.centerLeft,
                  child: Container(
                    width: 64,
                    height: 64,
                    decoration: BoxDecoration(
                      color: _color.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(18),
                    ),
                    child: Icon(
                      result.isMalicious
                          ? Icons.warning_amber_rounded
                          : result.isClean
                          ? Icons.check_rounded
                          : Icons.question_mark_rounded,
                      color: _color,
                      size: 32,
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                Semantics(
                  liveRegion: true,
                  child: Text(
                    _title,
                    style: TextStyle(
                      fontSize: 28,
                      height: 1.2,
                      fontWeight: FontWeight.w700,
                      color: _color,
                      letterSpacing: -0.7,
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  _description,
                  style: const TextStyle(
                    fontSize: 15,
                    color: AppColors.textSecondary,
                    height: 1.6,
                  ),
                ),
                const SizedBox(height: 28),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: AppColors.bgCard,
                    border: Border.all(color: AppColors.glassBorder),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SelectableText(
                    result.originalInput ?? result.url,
                    style: const TextStyle(fontSize: 14, height: 1.6),
                  ),
                ),
                const SizedBox(height: 32),
                FilledButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Yeni analiz'),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}
