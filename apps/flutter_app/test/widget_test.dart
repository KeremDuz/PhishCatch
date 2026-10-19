import 'package:flutter_test/flutter_test.dart';

import 'package:phishcatch/main.dart';

void main() {
  testWidgets('PhishCatch app renders', (WidgetTester tester) async {
    await tester.pumpWidget(const PhishCatchApp());
    await tester.pumpAndSettle();

    expect(find.text('PhishCatch'), findsOneWidget);
  });
}
