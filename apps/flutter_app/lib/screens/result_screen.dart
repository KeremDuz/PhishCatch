import 'package:flutter/material.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class ResultScreen extends StatelessWidget {
  final AnalysisResult result;
  const ResultScreen({super.key, required this.result});

  bool get _incomplete => result.scanStatus != 'complete';
  Color get _color => result.isMalicious
      ? AppColors.danger
      : result.isClean
      ? AppColors.safe
      : AppColors.warning;
  String get _title => result.isMalicious
      ? 'Riskli bağlantı'
      : result.isClean
      ? 'Risk sinyali bulunmadı'
      : result.scanStatus == 'partial'
      ? 'Analiz kısmen tamamlandı'
      : _incomplete
      ? 'Analiz tamamlanamadı'
      : 'Belirsiz sonuç';
  String get _description => result.isMalicious
      ? 'Oltalama veya zararlı içerik işaretleri bulundu. Bu bağlantıda kişisel bilgi paylaşmayın.'
      : result.isClean
      ? 'Tamamlanan kontroller belirgin bir risk göstermedi. Bu sonuç bir güvenlik garantisi değildir.'
      : _incomplete
      ? 'Bazı kontroller tamamlanamadı. Bu sonuç, bağlantının temiz olduğunu kanıtlamaz.'
      : 'Kontroller kesin bir değerlendirme üretmedi. Bağlantıyı açmadan önce dikkatli olun.';

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Analiz sonucu')),
    body: SafeArea(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 16, 20, 36),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 820),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                GlassCard(
                  padding: const EdgeInsets.all(28),
                  borderRadius: 20,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Wrap(
                        spacing: 16,
                        runSpacing: 16,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          Container(
                            width: 56,
                            height: 56,
                            decoration: BoxDecoration(
                              color: _color.withValues(alpha: 0.08),
                              borderRadius: BorderRadius.circular(16),
                            ),
                            child: Icon(
                              result.isMalicious
                                  ? Icons.gpp_bad_outlined
                                  : result.isClean
                                  ? Icons.verified_user_outlined
                                  : Icons.shield_outlined,
                              color: _color,
                              size: 30,
                            ),
                          ),
                          StatusBadge(
                            label: result.scanStatus == 'complete'
                                ? 'Analiz tamamlandı'
                                : result.scanStatus == 'partial'
                                ? 'Kısmi sonuç'
                                : 'Tamamlanamadı',
                            color: _color,
                          ),
                        ],
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
                            letterSpacing: -0.6,
                          ),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Text(
                        _description,
                        style: const TextStyle(
                          fontSize: 15,
                          color: AppColors.textSecondary,
                          height: 1.7,
                        ),
                      ),
                      if (result.isMalicious && _incomplete) ...[
                        const SizedBox(height: 16),
                        const NoticeCard(
                          message:
                              'Risk sinyali bulundu; diğer kontrollerin bir bölümü tamamlanamadı. Olasılık değerleri gösterilmiyor.',
                        ),
                      ],
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 24),
                        child: Divider(height: 1),
                      ),
                      const Text(
                        'İncelenen bağlantı',
                        style: TextStyle(
                          fontSize: 12,
                          color: AppColors.textMuted,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 10),
                      SelectableText(
                        result.originalInput ?? result.url,
                        style: const TextStyle(fontSize: 14, height: 1.6),
                      ),
                      if (result.normalizedUrl.isNotEmpty &&
                          result.normalizedUrl !=
                              (result.originalInput ?? result.url)) ...[
                        const SizedBox(height: 12),
                        const Text(
                          'Normalize edilmiş adres',
                          style: TextStyle(
                            fontSize: 12,
                            color: AppColors.textMuted,
                          ),
                        ),
                        const SizedBox(height: 6),
                        SelectableText(
                          result.normalizedUrl,
                          style: const TextStyle(
                            fontSize: 12,
                            color: AppColors.textSecondary,
                            height: 1.5,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                const SizedBox(height: 20),
                GlassCard(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const Text(
                        'Model olasılıkları',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 18),
                      LayoutBuilder(
                        builder: (context, constraints) {
                          final cards = [
                            _probability(
                              'Riskli',
                              _incomplete ? null : result.maliciousPercent,
                              AppColors.danger,
                            ),
                            _probability(
                              'Temiz',
                              _incomplete ? null : result.cleanPercent,
                              AppColors.safe,
                            ),
                          ];
                          return constraints.maxWidth >= 360
                              ? Row(
                                  children: [
                                    Expanded(child: cards[0]),
                                    const SizedBox(width: 16),
                                    Expanded(child: cards[1]),
                                  ],
                                )
                              : Column(
                                  children: [
                                    cards[0],
                                    const SizedBox(height: 16),
                                    cards[1],
                                  ],
                                );
                        },
                      ),
                      const SizedBox(height: 16),
                      Text(
                        _incomplete
                            ? 'Analiz eksik olduğu için olasılıklar kullanılamıyor.'
                            : 'Değerler modelin tahminidir; ölçülmüş doğruluk oranı değildir.',
                        style: const TextStyle(
                          fontSize: 12,
                          color: AppColors.textMuted,
                          height: 1.5,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 20),
                GlassCard(
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: ExpansionTile(
                    title: const Text(
                      'Analiz adımları',
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    subtitle: Text(
                      '${result.stages.where((stage) => stage.status == 'completed').length} / ${result.stages.length} kontrol tamamlandı',
                      style: const TextStyle(
                        fontSize: 12,
                        color: AppColors.textSecondary,
                      ),
                    ),
                    childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 20),
                    children: result.stages.isEmpty
                        ? [
                            const Padding(
                              padding: EdgeInsets.symmetric(vertical: 12),
                              child: Text(
                                'Sunucudan tamamlanmış kontrol bilgisi alınamadı.',
                                style: TextStyle(
                                  fontSize: 13,
                                  color: AppColors.textSecondary,
                                ),
                              ),
                            ),
                          ]
                        : result.stages.map(_stage).toList(),
                  ),
                ),
                if (result.centralScanId != null) ...[
                  const SizedBox(height: 20),
                  GlassCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Row(
                          children: [
                            Icon(
                              Icons.receipt_long_outlined,
                              size: 18,
                              color: AppColors.primary,
                            ),
                            SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                'ALLSAFE tarama kaydı',
                                style: TextStyle(
                                  fontSize: 14,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 10),
                        SelectableText(
                          result.centralScanId!,
                          style: const TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 12,
                            height: 1.6,
                          ),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Bu kayıt kurum hesabınızla ilişkilendirildi. Model eğitimi için ayrıca inceleme ve onay gerekir.',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 12,
                            height: 1.5,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.add, size: 20),
                  label: const Text('Yeni analiz'),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );

  Widget _probability(String label, double? value, Color color) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(18),
    decoration: BoxDecoration(
      color: AppColors.bgCardLight,
      borderRadius: BorderRadius.circular(12),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(fontSize: 13, color: AppColors.textSecondary),
        ),
        const SizedBox(height: 8),
        Text(
          value == null ? '—' : '${value.toStringAsFixed(1)}%',
          style: TextStyle(
            fontSize: 26,
            fontWeight: FontWeight.w600,
            color: value == null ? AppColors.textMuted : color,
          ),
        ),
        if (value != null) ...[
          const SizedBox(height: 14),
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: LinearProgressIndicator(
              value: (value / 100).clamp(0, 1),
              minHeight: 5,
              backgroundColor: AppColors.glassBorder,
              color: color,
            ),
          ),
        ],
      ],
    ),
  );

  Widget _stage(StageResult stage) {
    final complete = stage.status == 'completed';
    final color = !complete
        ? AppColors.warning
        : stage.verdict == 'malicious'
        ? AppColors.danger
        : stage.verdict == 'clean'
        ? AppColors.safe
        : AppColors.unknown;
    final status = !complete
        ? stage.status == 'skipped'
              ? 'Atlandı'
              : 'Tamamlanamadı'
        : stage.verdict == 'malicious'
        ? 'Riskli'
        : stage.verdict == 'clean'
        ? 'Risk bulunmadı'
        : 'Belirsiz';
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 12,
            runSpacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text(
                _scannerName(stage.scanner),
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              StatusBadge(label: status, color: color),
            ],
          ),
          if (stage.reason != null) ...[
            const SizedBox(height: 8),
            Text(
              stage.reason!,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                height: 1.6,
              ),
            ),
          ],
        ],
      ),
    );
  }

  String _scannerName(String name) => switch (name) {
    'url_model' => 'URL modeli',
    'html_model' => 'Sayfa içeriği modeli',
    'virustotal' => 'VirusTotal',
    'google_safe_browsing' => 'Google Safe Browsing',
    _ => name,
  };
}
