import 'package:flutter/material.dart';

import '../services/allsafe_api_service.dart';

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
              : 'Islem tamamlanamadi.',
        );
      }
    } finally {
      if (mounted) {
        _password.clear();
        setState(() => _busy = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final api = widget.api;
    return Scaffold(
      appBar: AppBar(title: const Text('Baglanti ve giris')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 520),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    'PhishCatch tek basina kullanilabilir. ALLSAFE modu taramalari kurum hesabina kaydeder.',
                  ),
                  const SizedBox(height: 20),
                  OutlinedButton(
                    onPressed: _busy
                        ? null
                        : () => _perform(() async {
                            try {
                              await api.logout();
                            } finally {
                              api.useStandalone();
                            }
                          }),
                    child: Text(
                      api.isAllsafe
                          ? 'Bagimsiz moda gec'
                          : 'Bagimsiz mod etkin',
                    ),
                  ),
                  const SizedBox(height: 20),
                  TextField(
                    controller: _server,
                    enabled: !_busy,
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    decoration: const InputDecoration(
                      labelText: 'ALLSAFE sunucusu',
                      hintText: 'https://allsafe.example',
                    ),
                  ),
                  const SizedBox(height: 12),
                  FilledButton(
                    onPressed: _busy
                        ? null
                        : () => _perform(() async {
                            final validated = ApiService.parseServerOrigin(
                              _server.text,
                              allowDevelopmentHttp: ApiService.allowDebugHttp,
                            );
                            try {
                              await api.logout();
                            } finally {
                              api.useAllsafe(validated.toString());
                            }
                          }),
                    child: const Text('ALLSAFE baglantisini sec'),
                  ),
                  if (api.isAllsafe) ...[
                    const SizedBox(height: 24),
                    Text(
                      api.isSignedIn
                          ? 'Giris yapildi: ${api.currentUser?['email'] ?? ''}'
                          : 'Kurum hesabiyla giris yapin.',
                    ),
                    if (!api.isSignedIn) ...[
                      const SizedBox(height: 12),
                      TextField(
                        controller: _email,
                        enabled: !_busy,
                        keyboardType: TextInputType.emailAddress,
                        autocorrect: false,
                        decoration: const InputDecoration(labelText: 'E-posta'),
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _password,
                        enabled: !_busy,
                        obscureText: true,
                        enableSuggestions: false,
                        autocorrect: false,
                        decoration: const InputDecoration(labelText: 'Parola'),
                      ),
                      const SizedBox(height: 12),
                      FilledButton(
                        onPressed: _busy
                            ? null
                            : () => _perform(
                                () => api.login(
                                  email: _email.text,
                                  password: _password.text,
                                ),
                              ),
                        child: const Text('Giris yap'),
                      ),
                    ] else ...[
                      const SizedBox(height: 12),
                      OutlinedButton(
                        onPressed: _busy ? null : () => _perform(api.logout),
                        child: const Text('Cikis yap'),
                      ),
                    ],
                    const SizedBox(height: 16),
                    const Text(
                      'Oturum yalnizca uygulama belleginde tutulur. Uygulama yeniden acildiginda tekrar giris gerekir.',
                    ),
                  ],
                  if (_busy) ...[
                    const SizedBox(height: 16),
                    const LinearProgressIndicator(),
                  ],
                  if (_message != null) ...[
                    const SizedBox(height: 16),
                    Text(
                      _message!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
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
