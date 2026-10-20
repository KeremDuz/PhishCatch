import 'package:flutter/material.dart';

import '../services/allsafe_api_service.dart';
import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';
import 'connection_screen.dart';
import 'result_screen.dart';

class HistoryScreen extends StatefulWidget {
  final ApiService api;
  const HistoryScreen({super.key, required this.api});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<Map<String, dynamic>>? _records;
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final records = await widget.api.scanHistory();
      if (mounted) setState(() => _records = records);
    } catch (error) {
      if (mounted) {
        setState(
          () => _error = error is ApiException
              ? error.message
              : 'Tarama geçmişi alınamadı. Yeniden deneyin.',
        );
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('Tarama geçmişi'),
      actions: [
        IconButton(
          onPressed: _loading ? null : _load,
          tooltip: 'Geçmişi yenile',
          icon: const Icon(Icons.refresh),
        ),
      ],
    ),
    body: SafeArea(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 16, 20, 36),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 820),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'ALLSAFE kayıtları',
                  style: TextStyle(
                    fontSize: 25,
                    fontWeight: FontWeight.w700,
                    letterSpacing: -0.5,
                  ),
                ),
                const SizedBox(height: 10),
                const Text(
                  'Hesabınızın erişebildiği son 50 tarama. Bir kaydı seçerek ayrıntılı sonucu görüntüleyin.',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 14,
                    height: 1.6,
                  ),
                ),
                const SizedBox(height: 24),
                if (_loading)
                  const Padding(
                    padding: EdgeInsets.all(36),
                    child: Center(child: CircularProgressIndicator()),
                  )
                else if (_error != null) ...[
                  NoticeCard(
                    message: _error!,
                    color: AppColors.danger,
                    icon: Icons.error_outline,
                  ),
                  const SizedBox(height: 16),
                  OutlinedButton(
                    onPressed: _load,
                    child: const Text('Yeniden dene'),
                  ),
                  if (!widget.api.isSignedIn)
                    TextButton(
                      onPressed: () async {
                        await Navigator.of(context).push(
                          MaterialPageRoute<void>(
                            builder: (_) => ConnectionScreen(api: widget.api),
                          ),
                        );
                        if (mounted) await _load();
                      },
                      child: const Text('Hesaba giriş yap'),
                    ),
                ] else if (_records?.isEmpty ?? true)
                  const GlassCard(
                    child: Column(
                      children: [
                        Icon(
                          Icons.history,
                          size: 32,
                          color: AppColors.textMuted,
                        ),
                        SizedBox(height: 16),
                        Text(
                          'Henüz tarama kaydı yok',
                          style: TextStyle(fontWeight: FontWeight.w600),
                        ),
                        SizedBox(height: 8),
                        Text(
                          'Yeni bir URL veya QR analizi yaptıktan sonra kaydı burada görebilirsiniz.',
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 13,
                            height: 1.6,
                          ),
                        ),
                      ],
                    ),
                  )
                else
                  ..._records!.map(_record),
              ],
            ),
          ),
        ),
      ),
    ),
  );

  Widget _record(Map<String, dynamic> record) {
    final analysis = record['analysis'];
    final status = record['scan_status'] as String? ?? 'failed';
    final url = record['url'] as String? ?? '';
    final result = analysis is Map
        ? AnalysisResult.fromJson(
            Map<String, dynamic>.from(analysis),
            scanStatusOverride: status,
            centralScanId: record['id'] as String?,
          )
        : AnalysisResult.unavailable(
            url,
            centralScanId: record['id'] as String?,
          );
    final color = result.isMalicious
        ? AppColors.danger
        : result.isClean
        ? AppColors.safe
        : AppColors.warning;
    final label = status == 'pending'
        ? 'Bekliyor'
        : status == 'failed'
        ? 'Başarısız'
        : status == 'partial'
        ? 'Kısmi'
        : result.isMalicious
        ? 'Riskli'
        : result.isClean
        ? 'Risk bulunmadı'
        : 'Belirsiz';
    final created = DateTime.tryParse(
      record['created_at'] as String? ?? '',
    )?.toLocal();
    final date = created == null
        ? 'Tarih bilinmiyor'
        : '${created.day.toString().padLeft(2, '0')}.${created.month.toString().padLeft(2, '0')}.${created.year} · ${created.hour.toString().padLeft(2, '0')}:${created.minute.toString().padLeft(2, '0')}';
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Material(
        color: AppColors.bgCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: const BorderSide(color: AppColors.glassBorder),
        ),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: status == 'pending'
              ? null
              : () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => ResultScreen(result: result),
                  ),
                ),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    StatusBadge(label: label, color: color),
                    Text(
                      '${record['source'] == 'qr' ? 'QR kod' : 'URL'} · $date',
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        url,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 14, height: 1.5),
                      ),
                    ),
                    if (status != 'pending')
                      const Padding(
                        padding: EdgeInsets.only(left: 12),
                        child: Icon(
                          Icons.chevron_right,
                          size: 20,
                          color: AppColors.textMuted,
                        ),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
