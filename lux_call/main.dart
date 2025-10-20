import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

// Корневой виджет приложения
class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Мое первое приложение',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const MyHomePage(), // Первый экран
    );
  }
}

// Экран с состоянием (здесь будет меняться счетчик)
class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      // Вызов setState заставляет виджет перерисоваться
      _counter++;
    });
  }

  @override
  Widget build(BuildContext context) {
    // Scaffold - это базовый "каркас" экрана (AppBar, тело и т.д.)
    return Scaffold(
      appBar: AppBar(
        title: const Text('Пример Flutter'),
      ),
      body: Center(
        // Center - виджет, который центрирует своего ребенка
        child: Column(
          // Column - располагает виджеты вертикально
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'Счетчик:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Увеличить',
        child: const Icon(Icons.add),
      ),
    );
  }
}