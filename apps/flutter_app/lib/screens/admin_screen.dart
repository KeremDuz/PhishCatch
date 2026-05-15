import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../services/api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class AdminScreen extends StatefulWidget {
  const AdminScreen({super.key});

  @override
  State<AdminScreen> createState() => _AdminScreenState();
}

class _AdminScreenState extends State<AdminScreen> {
  final TextEditingController _tokenController = TextEditingController();
  final TextEditingController _searchController = TextEditingController();
  final TextEditingController _manualUrlController = TextEditingController();
  final TextEditingController _manualNotesController = TextEditingController();
  String? _token;
  String? _error;
  bool _loading = false;
  bool _actionBusy = false;
  bool _manualBusy = false;
  String? _verdictFilter;
  int _manualLabel = 1;
  AdminObservationPage? _observations;
  AdminObservationDetail? _selectedDetail;
  AdminTrainingSamplePage? _trainingSamples;
  final Set<int> _selectedIds = <int>{};
  int _tabIndex = 0;

  @override
  void dispose() {
    _tokenController.dispose();
    _searchController.dispose();
    _manualUrlController.dispose();
    _manualNotesController.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    final token = _tokenController.text.trim();
    if (token.isEmpty) {
      setState(() => _error = 'Admin token gerekli.');
      return;
    }
    setState(() {
      _token = token;
      _error = null;
    });
    await _loadAll();
  }

  Future<void> _loadAll() async {
    await Future.wait([_loadObservations(), _loadTrainingSamples()]);
  }

  Future<void> _loadObservations() async {
    final token = _token;
    if (token == null) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final page = await PhishCatchApiService.listAdminObservations(
        token: token,
        finalVerdict: _verdictFilter,
        query: _searchController.text,
      );
      if (!mounted) return;
      setState(() {
        _observations = page;
        _selectedIds.removeWhere(
          (id) => !page.results.any((item) => item.id == id),
        );
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = error.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  Future<void> _loadTrainingSamples() async {
    final token = _token;
    if (token == null) return;
    try {
      final page = await PhishCatchApiService.listAdminTrainingSamples(
        token: token,
      );
      if (!mounted) return;
      setState(() => _trainingSamples = page);
    } catch (_) {
      // Observation ekranının kullanılabilir kalması daha önemli.
    }
  }

  Future<void> _loadDetail(AdminObservationItem item) async {
    final token = _token;
    if (token == null) return;
    setState(() => _selectedDetail = null);
    try {
      final detail = await PhishCatchApiService.getAdminObservation(
        token: token,
        id: item.id,
      );
      if (!mounted) return;
      setState(() => _selectedDetail = detail);
    } catch (error) {
      if (!mounted) return;
      setState(() => _error = error.toString().replaceFirst('Exception: ', ''));
    }
  }

  Future<void> _addSelectedToTraining(int label) async {
    final token = _token;
    final ids = _selectedIds.toList();
    if (token == null || ids.isEmpty || _actionBusy) return;
    setState(() {
      _actionBusy = true;
      _error = null;
    });
    try {
      await PhishCatchApiService.bulkAddObservationsToTraining(
        token: token,
        observationIds: ids,
        label: label,
        notes: 'Admin panel approval',
      );
      await _loadTrainingSamples();
      if (!mounted) return;
      setState(() {
        _selectedIds.clear();
        _actionBusy = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _actionBusy = false;
        _error = error.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  Future<void> _addDetailToTraining(int label) async {
    final token = _token;
    final detail = _selectedDetail;
    if (token == null || detail == null || _actionBusy) return;
    setState(() {
      _actionBusy = true;
      _error = null;
    });
    try {
      await PhishCatchApiService.addObservationToTraining(
        token: token,
        observationId: detail.id,
        label: label,
        notes: 'Admin panel approval',
      );
      await _loadTrainingSamples();
      if (!mounted) return;
      setState(() => _actionBusy = false);
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _actionBusy = false;
        _error = error.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  Future<void> _addManualTrainingSample() async {
    final token = _token;
    final url = _manualUrlController.text.trim();
    if (token == null || url.isEmpty || _manualBusy) return;
    setState(() {
      _manualBusy = true;
      _error = null;
    });
    try {
      await PhishCatchApiService.addAdminTrainingSample(
        token: token,
        url: url,
        label: _manualLabel,
        notes: _manualNotesController.text,
      );
      await _loadTrainingSamples();
      if (!mounted) return;
      setState(() {
        _manualBusy = false;
        _manualUrlController.clear();
        _manualNotesController.clear();
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _manualBusy = false;
        _error = error.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bgDark,
      body: CyberBackdrop(
        dense: MediaQuery.of(context).size.width < 900,
        child: SafeArea(
          child: SelectionArea(
            child: Padding(
              padding: const EdgeInsets.all(18),
              child: _token == null ? _buildLogin() : _buildDashboard(),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLogin() {
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480),
        child: _panel(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  const Icon(
                    Icons.admin_panel_settings,
                    color: AppColors.accent,
                  ),
                  const SizedBox(width: 12),
                  Text(
                    'Admin',
                    style: GoogleFonts.inter(
                      fontSize: 28,
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              TextField(
                controller: _tokenController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'X-Admin-Token',
                  prefixIcon: Icon(Icons.key_rounded),
                ),
                onSubmitted: (_) => _connect(),
              ),
              const SizedBox(height: 14),
              ElevatedButton.icon(
                onPressed: _connect,
                icon: const Icon(Icons.login_rounded),
                label: const Text('Giris'),
              ),
              if (_error != null) _errorLine(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDashboard() {
    final isWide = MediaQuery.of(context).size.width >= 1080;
    return Column(
      children: [
        _buildTopBar(),
        const SizedBox(height: 12),
        Expanded(
          child: IndexedStack(
            index: _tabIndex,
            children: [
              isWide
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Expanded(flex: 6, child: _buildObservationPanel()),
                        const SizedBox(width: 12),
                        Expanded(flex: 4, child: _buildDetailPanel()),
                      ],
                    )
                  : Column(
                      children: [
                        Expanded(child: _buildObservationPanel()),
                        const SizedBox(height: 12),
                        SizedBox(height: 360, child: _buildDetailPanel()),
                      ],
                    ),
              _buildTrainingSamplesPanel(),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildTopBar() {
    return _panel(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      child: Row(
        children: [
          IconButton(
            tooltip: 'Ana sayfa',
            onPressed: () => Navigator.of(context).pushReplacementNamed('/'),
            icon: const Icon(Icons.home_rounded),
          ),
          const SizedBox(width: 8),
          Text(
            'PhishCatch Admin',
            style: GoogleFonts.inter(fontSize: 20, fontWeight: FontWeight.w900),
          ),
          const Spacer(),
          SegmentedButton<int>(
            segments: const [
              ButtonSegment(
                value: 0,
                icon: Icon(Icons.list_alt_rounded),
                label: Text('Gozlemler'),
              ),
              ButtonSegment(
                value: 1,
                icon: Icon(Icons.school_rounded),
                label: Text('Egitim'),
              ),
            ],
            selected: {_tabIndex},
            onSelectionChanged: (value) =>
                setState(() => _tabIndex = value.first),
          ),
          const SizedBox(width: 8),
          IconButton(
            tooltip: 'Yenile',
            onPressed: _loadAll,
            icon: const Icon(Icons.refresh_rounded),
          ),
        ],
      ),
    );
  }

  Widget _buildObservationPanel() {
    final observations = _observations?.results ?? [];
    return _panel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            spacing: 10,
            runSpacing: 10,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              SizedBox(
                width: 280,
                child: TextField(
                  controller: _searchController,
                  decoration: const InputDecoration(
                    isDense: true,
                    prefixIcon: Icon(Icons.search_rounded),
                    hintText: 'URL veya domain ara',
                  ),
                  onSubmitted: (_) => _loadObservations(),
                ),
              ),
              SizedBox(
                width: 170,
                child: DropdownButtonFormField<String?>(
                  initialValue: _verdictFilter,
                  decoration: const InputDecoration(isDense: true),
                  items: const [
                    DropdownMenuItem(value: null, child: Text('Tum kararlar')),
                    DropdownMenuItem(value: 'malicious', child: Text('Riskli')),
                    DropdownMenuItem(value: 'clean', child: Text('Temiz')),
                    DropdownMenuItem(
                      value: 'unknown',
                      child: Text('Bilinmiyor'),
                    ),
                  ],
                  onChanged: (value) {
                    setState(() => _verdictFilter = value);
                    _loadObservations();
                  },
                ),
              ),
              IconButton(
                tooltip: 'Ara',
                onPressed: _loadObservations,
                icon: const Icon(Icons.manage_search_rounded),
              ),
              _actionButton(
                icon: Icons.verified_rounded,
                label: 'Temiz',
                color: AppColors.safe,
                onPressed: _selectedIds.isEmpty
                    ? null
                    : () => _addSelectedToTraining(0),
              ),
              _actionButton(
                icon: Icons.gpp_bad_rounded,
                label: 'Phishing',
                color: AppColors.danger,
                onPressed: _selectedIds.isEmpty
                    ? null
                    : () => _addSelectedToTraining(1),
              ),
            ],
          ),
          if (_error != null) _errorLine(),
          const SizedBox(height: 12),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : observations.isEmpty
                ? _emptyState('Kayitli gozlem yok')
                : Scrollbar(
                    child: SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: SingleChildScrollView(
                        child: DataTable(
                          showCheckboxColumn: false,
                          columns: const [
                            DataColumn(label: Text('Sec')),
                            DataColumn(label: Text('URL')),
                            DataColumn(label: Text('Karar')),
                            DataColumn(label: Text('Risk')),
                            DataColumn(label: Text('Katman')),
                            DataColumn(label: Text('Feature')),
                            DataColumn(label: Text('Zaman')),
                          ],
                          rows: observations.map(_observationRow).toList(),
                        ),
                      ),
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  DataRow _observationRow(AdminObservationItem item) {
    final selected = _selectedIds.contains(item.id);
    return DataRow(
      selected: selected,
      onSelectChanged: (_) {
        setState(() {
          selected ? _selectedIds.remove(item.id) : _selectedIds.add(item.id);
        });
        _loadDetail(item);
      },
      cells: [
        DataCell(
          Checkbox(
            value: selected,
            onChanged: (_) {
              setState(() {
                selected
                    ? _selectedIds.remove(item.id)
                    : _selectedIds.add(item.id);
              });
            },
          ),
        ),
        DataCell(
          SizedBox(
            width: 320,
            child: Text(
              item.url,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.firaCode(fontSize: 12),
            ),
          ),
          onTap: () => _loadDetail(item),
        ),
        DataCell(_verdictPill(item.finalVerdict)),
        DataCell(Text('${item.riskPercent.toStringAsFixed(1)}%')),
        DataCell(Text('${item.stageCount}')),
        DataCell(
          Text(
            '${item.hasUrlFeatures ? 'URL' : '-'} / ${item.hasHtmlFeatures ? 'HTML' : '-'}',
          ),
        ),
        DataCell(Text(_shortDate(item.scannedAt))),
      ],
    );
  }

  Widget _buildDetailPanel() {
    final detail = _selectedDetail;
    return _panel(
      child: detail == null
          ? _emptyState('Bir URL sec')
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        detail.url,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.firaCode(
                          fontWeight: FontWeight.w700,
                          fontSize: 13,
                        ),
                      ),
                    ),
                    _verdictPill(detail.finalVerdict),
                  ],
                ),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    _actionButton(
                      icon: Icons.verified_rounded,
                      label: 'Temiz olarak egit',
                      color: AppColors.safe,
                      onPressed: () => _addDetailToTraining(0),
                    ),
                    _actionButton(
                      icon: Icons.gpp_bad_rounded,
                      label: 'Phishing olarak egit',
                      color: AppColors.danger,
                      onPressed: () => _addDetailToTraining(1),
                    ),
                  ],
                ),
                const Divider(height: 24),
                _metricLine(
                  'Final URL',
                  detail.finalUrl ?? detail.normalizedUrl ?? '-',
                ),
                _metricLine('Domain', detail.domain ?? '-'),
                _metricLine(
                  'Risk',
                  '${detail.riskPercent.toStringAsFixed(2)}%',
                ),
                _metricLine(
                  'URL feature',
                  '${detail.urlFeatures?.length ?? 0}',
                ),
                _metricLine(
                  'HTML feature',
                  '${detail.htmlFeatures?.length ?? 0}',
                ),
                const Divider(height: 24),
                Text(
                  'Katman Sonuclari',
                  style: GoogleFonts.inter(fontWeight: FontWeight.w900),
                ),
                const SizedBox(height: 8),
                Expanded(
                  child: ListView.separated(
                    itemCount: detail.scannerResults.length,
                    separatorBuilder: (context, index) =>
                        const SizedBox(height: 8),
                    itemBuilder: (context, index) {
                      final stage = detail.scannerResults[index];
                      return _stageTile(stage);
                    },
                  ),
                ),
              ],
            ),
    );
  }

  Widget _buildTrainingSamplesPanel() {
    final samples = _trainingSamples?.results ?? [];
    return _panel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Text(
                'Egitim Havuzu',
                style: GoogleFonts.inter(
                  fontSize: 18,
                  fontWeight: FontWeight.w900,
                ),
              ),
              const Spacer(),
              IconButton(
                tooltip: 'Yenile',
                onPressed: _loadTrainingSamples,
                icon: const Icon(Icons.refresh_rounded),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              SizedBox(
                width: 360,
                child: TextField(
                  controller: _manualUrlController,
                  decoration: const InputDecoration(
                    isDense: true,
                    prefixIcon: Icon(Icons.link_rounded),
                    hintText: 'Manuel URL ekle',
                  ),
                  onSubmitted: (_) => _addManualTrainingSample(),
                ),
              ),
              SizedBox(
                width: 260,
                child: TextField(
                  controller: _manualNotesController,
                  decoration: const InputDecoration(
                    isDense: true,
                    prefixIcon: Icon(Icons.note_alt_rounded),
                    hintText: 'Not',
                  ),
                ),
              ),
              SegmentedButton<int>(
                segments: const [
                  ButtonSegment(
                    value: 0,
                    icon: Icon(Icons.verified_rounded),
                    label: Text('Temiz'),
                  ),
                  ButtonSegment(
                    value: 1,
                    icon: Icon(Icons.gpp_bad_rounded),
                    label: Text('Phishing'),
                  ),
                ],
                selected: {_manualLabel},
                onSelectionChanged: (value) {
                  setState(() => _manualLabel = value.first);
                },
              ),
              FilledButton.icon(
                onPressed: _manualBusy ? null : _addManualTrainingSample,
                icon: _manualBusy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.add_rounded),
                label: const Text('Ekle'),
              ),
            ],
          ),
          if (_error != null) _errorLine(),
          const SizedBox(height: 12),
          Expanded(
            child: samples.isEmpty
                ? _emptyState('Training sample yok')
                : ListView.separated(
                    itemCount: samples.length,
                    separatorBuilder: (context, index) =>
                        const SizedBox(height: 8),
                    itemBuilder: (context, index) {
                      final sample = samples[index];
                      final verdict = sample.label == 1 ? 'malicious' : 'clean';
                      return Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppColors.bgSurface.withValues(alpha: 0.78),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppColors.glassBorder),
                        ),
                        child: Row(
                          children: [
                            _verdictPill(verdict),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    sample.url,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: GoogleFonts.firaCode(fontSize: 12),
                                  ),
                                  const SizedBox(height: 5),
                                  Text(
                                    '${sample.labelSource}  •  URL:${sample.hasUrlFeatures ? 'var' : 'yok'}  HTML:${sample.hasHtmlFeatures ? 'var' : 'yok'}',
                                    style: const TextStyle(
                                      color: AppColors.textSecondary,
                                      fontSize: 12,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _stageTile(Map<String, dynamic> stage) {
    final details = const JsonEncoder.withIndent(
      '  ',
    ).convert(stage['details'] ?? {});
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.bgSurface.withValues(alpha: 0.72),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.glassBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  '${stage['scanner'] ?? 'Scanner'}',
                  style: GoogleFonts.inter(fontWeight: FontWeight.w800),
                ),
              ),
              _verdictPill('${stage['verdict'] ?? 'unknown'}'),
            ],
          ),
          if (stage['reason'] != null) ...[
            const SizedBox(height: 8),
            Text(
              '${stage['reason']}',
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
              ),
            ),
          ],
          if (details != '{}') ...[
            const SizedBox(height: 8),
            Text(
              details.length > 900
                  ? '${details.substring(0, 900)}...'
                  : details,
              style: GoogleFonts.firaCode(
                color: AppColors.textMuted,
                fontSize: 11,
                height: 1.35,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _panel({required Widget child, EdgeInsetsGeometry? padding}) {
    return Container(
      padding: padding ?? const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.bgCard.withValues(alpha: 0.92),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.glassBorder),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.28),
            blurRadius: 28,
            offset: const Offset(0, 16),
          ),
        ],
      ),
      child: child,
    );
  }

  Widget _actionButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback? onPressed,
  }) {
    return FilledButton.icon(
      onPressed: _actionBusy ? null : onPressed,
      icon: Icon(icon, size: 18),
      label: Text(label),
      style: FilledButton.styleFrom(
        backgroundColor: color.withValues(alpha: 0.92),
        foregroundColor: Colors.white,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
    );
  }

  Widget _verdictPill(String verdict) {
    final color = switch (verdict) {
      'malicious' => AppColors.danger,
      'clean' => AppColors.safe,
      _ => AppColors.warning,
    };
    final text = switch (verdict) {
      'malicious' => 'Riskli',
      'clean' => 'Temiz',
      _ => 'Bilinmiyor',
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.13),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.36)),
      ),
      child: Text(
        text,
        style: TextStyle(
          color: color,
          fontWeight: FontWeight.w800,
          fontSize: 12,
        ),
      ),
    );
  }

  Widget _metricLine(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 96,
            child: Text(
              label,
              style: const TextStyle(color: AppColors.textMuted),
            ),
          ),
          Expanded(
            child: Text(value, style: GoogleFonts.firaCode(fontSize: 12)),
          ),
        ],
      ),
    );
  }

  Widget _emptyState(String text) {
    return Center(
      child: Text(text, style: const TextStyle(color: AppColors.textSecondary)),
    );
  }

  Widget _errorLine() {
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Text(
        _error!,
        style: const TextStyle(
          color: AppColors.danger,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }

  String _shortDate(String value) {
    if (value.length >= 16) {
      return value.substring(0, 16).replaceFirst('T', ' ');
    }
    return value;
  }
}
