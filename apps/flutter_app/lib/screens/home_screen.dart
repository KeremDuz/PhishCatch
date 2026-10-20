import 'package:flutter/material.dart';

import '../services/allsafe_api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';
import 'connection_screen.dart';
import 'history_screen.dart';
import 'qr_scanner_screen.dart';
import 'result_screen.dart';

class HomeScreen extends StatefulWidget {
  final ApiService? api;
  const HomeScreen({super.key, this.api});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _urlController = TextEditingController();
  final _urlFocusNode = FocusNode();
  bool _isLoading = false;
  String? _errorMessage;
  String? _pendingRequestId;
  String? _pendingRequestUrl;
  String? _pendingRequestSource;
  String _inputSource = 'url';
  ApiService get _api => widget.api ?? ApiService.shared;

  @override
  void dispose() {
    _urlController.dispose();
    _urlFocusNode.dispose();
    super.dispose();
  }

  Future<void> _openConnection() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => ConnectionScreen(api: _api)),
    );
  }

  Future<void> _analyzeUrl(String input, {String? source}) async {
    final url = input.trim();
    final scanSource = source ?? _inputSource;
    if (url.isEmpty) {
      setState(
        () => _errorMessage = 'Kontrol etmek istediğiniz bağlantıyı girin.',
      );
      _urlFocusNode.requestFocus();
      return;
    }
    if (_api.isAllsafe && !_api.isSignedIn) {
      await _openConnection();
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      if (_pendingRequestUrl != url || _pendingRequestSource != scanSource) {
        _pendingRequestId = ApiService.newClientRequestId();
        _pendingRequestUrl = url;
        _pendingRequestSource = scanSource;
      }
      final result = await _api.analyzeUrl(
        url,
        source: scanSource,
        clientRequestId: _pendingRequestId ??= ApiService.newClientRequestId(),
      );
      _pendingRequestId = _pendingRequestUrl = _pendingRequestSource = null;
      if (!mounted) return;
      setState(() => _isLoading = false);
      await Navigator.of(context).push(
        MaterialPageRoute<void>(builder: (_) => ResultScreen(result: result)),
      );
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _errorMessage = error is ApiException
            ? error.message
            : 'Analiz tamamlanamadı. Bağlantınızı kontrol edip yeniden deneyin.';
      });
    }
  }

  Future<void> _openQrScanner() async {
    if (_isLoading) return;
    if (_api.isAllsafe && !_api.isSignedIn) {
      await _openConnection();
      return;
    }
    final value = await Navigator.of(
      context,
    ).push<String>(MaterialPageRoute(builder: (_) => const QrScannerScreen()));
    if (!mounted || value == null) return;
    _urlController.text = value;
    _inputSource = 'qr';
    await _analyzeUrl(value, source: 'qr');
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: SafeArea(
      child: AnimatedBuilder(
        animation: _api,
        builder: (context, _) => LayoutBuilder(
          builder: (context, constraints) {
            final wide = constraints.maxWidth >= 900;
            return Align(
              alignment: Alignment.topCenter,
              child: SingleChildScrollView(
                padding: EdgeInsets.symmetric(
                  horizontal: wide ? 48 : 20,
                  vertical: wide ? 32 : 20,
                ),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 1120),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _header(wide),
                      SizedBox(height: wide ? 72 : 40),
                      if (wide)
                        Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(flex: 5, child: _introduction(wide)),
                            const SizedBox(width: 64),
                            Expanded(flex: 6, child: _workspace(wide)),
                          ],
                        )
                      else ...[
                        _introduction(wide),
                        const SizedBox(height: 28),
                        _workspace(wide),
                      ],
                      SizedBox(height: wide ? 64 : 36),
                      const Divider(height: 1),
                      const Padding(
                        padding: EdgeInsets.only(top: 20),
                        child: Text(
                          'Analiz sonucu bir tahmindir. Eksik kontroller, bağlantının temiz olduğu anlamına gelmez.',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 12,
                            height: 1.6,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
    ),
  );

  Widget _header(bool wide) => Row(
    children: [
      Expanded(
        child: AppBrand(compact: MediaQuery.sizeOf(context).width < 380),
      ),
      if (wide) ...[
        StatusBadge(label: _api.isAllsafe ? 'Kurum modu' : 'Bağımsız mod'),
        const SizedBox(width: 16),
      ],
      if (_api.isAllsafe)
        IconButton(
          onPressed: _isLoading
              ? null
              : () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => HistoryScreen(api: _api),
                  ),
                ),
          tooltip: 'Tarama geçmişi',
          icon: const Icon(
            Icons.history_outlined,
            color: AppColors.textSecondary,
          ),
        ),
      IconButton(
        onPressed: _isLoading ? null : _openConnection,
        tooltip: 'Bağlantı ve hesap',
        icon: const Icon(
          Icons.settings_outlined,
          color: AppColors.textSecondary,
        ),
      ),
    ],
  );

  Widget _introduction(bool wide) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text(
        'BAĞLANTI GÜVENLİĞİ',
        style: TextStyle(
          color: AppColors.primary,
          fontSize: 11,
          fontWeight: FontWeight.w700,
          letterSpacing: 1.6,
        ),
      ),
      const SizedBox(height: 16),
      Text(
        'Açmadan önce\nkontrol edin.',
        style: TextStyle(
          fontSize: wide ? 46 : 34,
          height: 1.15,
          fontWeight: FontWeight.w700,
          letterSpacing: -1.4,
        ),
      ),
      const SizedBox(height: 20),
      const Text(
        'Bir bağlantı yapıştırın veya QR kod okutun. PhishCatch, olası oltalama işaretlerini sunucuda analiz eder.',
        style: TextStyle(
          color: AppColors.textSecondary,
          fontSize: 16,
          height: 1.7,
        ),
      ),
      if (wide) ...[
        const SizedBox(height: 36),
        _step('01', 'Bağlantıyı paylaşın', 'URL ya da QR kod ile başlayın.'),
        const SizedBox(height: 20),
        _step(
          '02',
          'Sonucu inceleyin',
          'Tahmini ve tamamlanan kontrolleri görün.',
        ),
      ],
    ],
  );

  Widget _step(String number, String title, String description) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Container(
        width: 30,
        height: 30,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: AppColors.primary.withValues(alpha: 0.07),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(
          number,
          style: const TextStyle(
            color: AppColors.primary,
            fontSize: 11,
            fontWeight: FontWeight.w700,
          ),
        ),
      ),
      const SizedBox(width: 14),
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 4),
            Text(
              description,
              style: const TextStyle(
                fontSize: 13,
                height: 1.5,
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      ),
    ],
  );

  Widget _workspace(bool wide) => GlassCard(
    padding: EdgeInsets.all(wide ? 32 : 22),
    borderRadius: 20,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Yeni analiz',
          style: TextStyle(
            fontSize: 21,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.4,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Kontrol etmek istediğiniz adresi girin.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 14,
            height: 1.5,
          ),
        ),
        const SizedBox(height: 26),
        const Text(
          'Bağlantı adresi',
          style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 10),
        TextField(
          key: const ValueKey('url-input'),
          controller: _urlController,
          focusNode: _urlFocusNode,
          enabled: !_isLoading,
          keyboardType: TextInputType.url,
          autocorrect: false,
          enableSuggestions: false,
          textInputAction: TextInputAction.search,
          decoration: const InputDecoration(
            hintText: 'https://example.com',
            prefixIcon: Icon(Icons.link_outlined, size: 20),
            helperText: 'Bağlantı cihazınızda açılmaz; sunucuda incelenir.',
            helperMaxLines: 2,
          ),
          onChanged: (_) => _inputSource = 'url',
          onSubmitted: _isLoading ? null : (value) => _analyzeUrl(value),
        ),
        const SizedBox(height: 22),
        FilledButton.icon(
          onPressed: _isLoading ? null : () => _analyzeUrl(_urlController.text),
          icon: _isLoading
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: AppColors.primary,
                  ),
                )
              : const Icon(Icons.search_outlined, size: 20),
          label: Text(_isLoading ? 'Analiz ediliyor…' : 'Bağlantıyı analiz et'),
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: _isLoading ? null : _openQrScanner,
          icon: const Icon(Icons.qr_code_scanner, size: 20),
          label: const Text('QR kod tara'),
        ),
        if (_isLoading) ...[
          const SizedBox(height: 16),
          Semantics(
            liveRegion: true,
            child: const Text(
              'Sunucudan sonuç bekleniyor. Bu işlem bağlantıya göre zaman alabilir.',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.5,
              ),
            ),
          ),
        ],
        if (_errorMessage != null) ...[
          const SizedBox(height: 16),
          NoticeCard(
            message: _errorMessage!,
            color: AppColors.danger,
            icon: Icons.error_outline,
          ),
        ],
        const Padding(
          padding: EdgeInsets.symmetric(vertical: 24),
          child: Divider(height: 1),
        ),
        _connectionSummary(),
      ],
    ),
  );

  Widget _connectionSummary() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Wrap(
        spacing: 8,
        runSpacing: 8,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          const Icon(Icons.dns_outlined, size: 18, color: AppColors.textMuted),
          Text(
            _api.isAllsafe ? 'ALLSAFE' : 'Bağımsız PhishCatch',
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
          ),
          StatusBadge(
            label: _api.isAllsafe
                ? _api.isSignedIn
                      ? 'Oturum açık'
                      : 'Giriş gerekli'
                : 'Kurum kaydı kapalı',
            color: _api.isAllsafe && !_api.isSignedIn
                ? AppColors.warning
                : AppColors.textSecondary,
          ),
        ],
      ),
      const SizedBox(height: 10),
      Text(
        _api.isAllsafe
            ? _api.allsafeServer!.host
            : 'Taramalar ALLSAFE kurum geçmişine kaydedilmez.',
        style: const TextStyle(
          color: AppColors.textMuted,
          fontSize: 12,
          height: 1.5,
        ),
      ),
      if (_api.isAllsafe) ...[
        const SizedBox(height: 8),
        Text(
          _api.isSignedIn
              ? 'Taramalar kurum hesabınızla ilişkilendirilir.'
              : 'Analiz yapmak için kurum hesabınızla giriş yapın.',
          style: const TextStyle(
            color: AppColors.textSecondary,
            fontSize: 12,
            height: 1.5,
          ),
        ),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton(
            onPressed: _isLoading ? null : _openConnection,
            child: Text(_api.isSignedIn ? 'Hesabı yönet' : 'Hesaba giriş yap'),
          ),
        ),
      ],
    ],
  );
}
