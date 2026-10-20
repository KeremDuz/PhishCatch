import 'package:flutter/material.dart';

import '../services/allsafe_api_service.dart';
import '../theme/app_theme.dart';
import '../widgets/common_widgets.dart';

class ConnectionScreen extends StatefulWidget {
  final ApiService api;
  const ConnectionScreen({super.key, required this.api});
  @override
  State<ConnectionScreen> createState() => _ConnectionScreenState();
}

class _ConnectionScreenState extends State<ConnectionScreen> {
  late final TextEditingController _server;
  final _email = TextEditingController();
  final _password = TextEditingController();
  bool _busy = false;
  bool _obscurePassword = true;
  String? _message;

  @override
  void initState() {
    super.initState();
    _server = TextEditingController(
      text:
          widget.api.allsafeServer?.toString() ??
          const String.fromEnvironment('ALLSAFE_API_BASE_URL'),
    );
    widget.api.addListener(_changed);
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    widget.api.removeListener(_changed);
    _server.dispose();
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _perform(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await action();
    } catch (error) {
      if (mounted) {
        setState(
          () => _message = error is ApiException
              ? error.message
              : 'İşlem tamamlanamadı. Yeniden deneyin.',
        );
      }
    } finally {
      if (mounted) {
        _password.clear();
        setState(() => _busy = false);
      }
    }
  }

  Future<void> _selectServer() => _perform(() async {
    final validated = ApiService.parseServerOrigin(
      _server.text,
      allowDevelopmentHttp: ApiService.allowDebugHttp,
    );
    await widget.api.logout();
    widget.api.useAllsafe(validated.toString());
  });
  Future<void> _login() => _perform(
    () => widget.api.login(email: _email.text, password: _password.text),
  );

  @override
  Widget build(BuildContext context) {
    final api = widget.api;
    return Scaffold(
      appBar: AppBar(title: const Text('Bağlantı ve hesap')),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 36),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 600),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const AppBrand(),
                  const SizedBox(height: 28),
                  GlassCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        const Text(
                          'Kurum bağlantısı',
                          style: TextStyle(
                            fontSize: 22,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: 10),
                        const Text(
                          'ALLSAFE üzerinden yapılan taramalar, giriş yaptığınız kurum hesabına kaydedilir.',
                          style: TextStyle(
                            color: AppColors.textSecondary,
                            height: 1.6,
                          ),
                        ),
                        const SizedBox(height: 24),
                        TextField(
                          controller: _server,
                          enabled: !_busy,
                          keyboardType: TextInputType.url,
                          autocorrect: false,
                          enableSuggestions: false,
                          decoration: const InputDecoration(
                            labelText: 'ALLSAFE sunucusu',
                            hintText: 'https://allsafe.example',
                            helperText:
                                'Özel sunucuya erişmek için Tailscale bağlantınız açık olmalı.',
                            helperMaxLines: 2,
                          ),
                        ),
                        const SizedBox(height: 16),
                        OutlinedButton.icon(
                          onPressed: _busy ? null : _selectServer,
                          icon: const Icon(Icons.dns_outlined, size: 18),
                          label: const Text('Sunucu adresini uygula'),
                        ),
                        if (api.isAllsafe) ...[
                          const Padding(
                            padding: EdgeInsets.symmetric(vertical: 24),
                            child: Divider(height: 1),
                          ),
                          if (api.isSignedIn) ...[
                            const Align(
                              alignment: Alignment.centerLeft,
                              child: StatusBadge(label: 'Oturum açık'),
                            ),
                            const SizedBox(height: 16),
                            Text(
                              'Giriş yapıldı: ${api.currentUser?['email'] ?? ''}',
                              style: const TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w600,
                                height: 1.5,
                              ),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              api.isBrowserSession
                                  ? 'Taramalar bu hesapla ilişkilendirilir. Güvenli tarayıcı oturumu kullanılır.'
                                  : 'Taramalar bu hesapla ilişkilendirilir. Oturum yalnızca uygulama belleğinde tutulur.',
                              style: const TextStyle(
                                color: AppColors.textSecondary,
                                fontSize: 13,
                                height: 1.5,
                              ),
                            ),
                            const SizedBox(height: 20),
                            FilledButton.icon(
                              onPressed: _busy
                                  ? null
                                  : () => Navigator.of(context).pop(),
                              icon: const Icon(Icons.arrow_forward, size: 18),
                              label: const Text('Analize dön'),
                            ),
                            const SizedBox(height: 10),
                            TextButton(
                              onPressed: _busy
                                  ? null
                                  : () => _perform(api.logout),
                              child: const Text('Çıkış yap'),
                            ),
                          ] else ...[
                            const Text(
                              'Kurum hesabıyla giriş yapın.',
                              style: TextStyle(
                                fontWeight: FontWeight.w600,
                                fontSize: 16,
                              ),
                            ),
                            const SizedBox(height: 18),
                            AutofillGroup(
                              child: Column(
                                children: [
                                  TextField(
                                    controller: _email,
                                    enabled: !_busy,
                                    keyboardType: TextInputType.emailAddress,
                                    autofillHints: const [
                                      AutofillHints.username,
                                    ],
                                    autocorrect: false,
                                    textInputAction: TextInputAction.next,
                                    decoration: const InputDecoration(
                                      labelText: 'E-posta',
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                  TextField(
                                    controller: _password,
                                    enabled: !_busy,
                                    obscureText: _obscurePassword,
                                    autofillHints: const [
                                      AutofillHints.password,
                                    ],
                                    enableSuggestions: false,
                                    autocorrect: false,
                                    textInputAction: TextInputAction.done,
                                    onSubmitted: _busy ? null : (_) => _login(),
                                    decoration: InputDecoration(
                                      labelText: 'Parola',
                                      suffixIcon: IconButton(
                                        tooltip: _obscurePassword
                                            ? 'Parolayı göster'
                                            : 'Parolayı gizle',
                                        onPressed: () => setState(
                                          () => _obscurePassword =
                                              !_obscurePassword,
                                        ),
                                        icon: Icon(
                                          _obscurePassword
                                              ? Icons.visibility_outlined
                                              : Icons.visibility_off_outlined,
                                        ),
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            const SizedBox(height: 20),
                            FilledButton(
                              onPressed: _busy ? null : _login,
                              child: const Text('Giriş yap'),
                            ),
                            const SizedBox(height: 16),
                            Text(
                              api.isBrowserSession
                                  ? 'Oturum süresi dolduğunda tekrar giriş gerekir. Tarayıcı oturumu analiz isteklerinde kullanılır.'
                                  : 'Uygulama yeniden açıldığında veya oturum süresi dolduğunda tekrar giriş gerekir.',
                              style: const TextStyle(
                                color: AppColors.textMuted,
                                fontSize: 12,
                                height: 1.5,
                              ),
                            ),
                          ],
                        ],
                        if (_busy) ...[
                          const SizedBox(height: 20),
                          const LinearProgressIndicator(),
                        ],
                        if (_message != null) ...[
                          const SizedBox(height: 20),
                          NoticeCard(
                            message: _message!,
                            color: AppColors.danger,
                            icon: Icons.error_outline,
                          ),
                        ],
                      ],
                    ),
                  ),
                  if (!api.managedOnly) ...[
                    const SizedBox(height: 24),
                    ExpansionTile(
                      tilePadding: const EdgeInsets.symmetric(horizontal: 4),
                      title: const Text(
                        'Gelişmiş bağlantı',
                        style: TextStyle(fontSize: 14),
                      ),
                      children: [
                        const Padding(
                          padding: EdgeInsets.symmetric(vertical: 12),
                          child: Text(
                            'Bağımsız mod, ALLSAFE kurum hesabını ve merkezi tarama kaydını kullanmaz. Ayrı analiz servisi yapılandırması gerektirir.',
                            style: TextStyle(
                              color: AppColors.textSecondary,
                              fontSize: 13,
                              height: 1.6,
                            ),
                          ),
                        ),
                        OutlinedButton(
                          onPressed: _busy
                              ? null
                              : () => _perform(() async {
                                  await api.logout();
                                  api.useStandalone();
                                }),
                          child: Text(
                            api.isAllsafe
                                ? 'Bağımsız moda geç'
                                : 'Bağımsız mod etkin',
                          ),
                        ),
                        const SizedBox(height: 16),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
