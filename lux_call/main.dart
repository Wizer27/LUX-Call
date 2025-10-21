import 'package:flutter/material.dart';
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const Main());
}
class Main extends StatelessWidget {
  const Main({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Lux-Call',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const AuthScreen(), 
    );
  }
}
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => AuthScreenState();
}

class AuthScreenState extends State<AuthScreen> {
  final TextEditingController username_cont = TextEditingController();
  final TextEditingController password_cont = TextEditingController();
  bool is_login = true;
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(is_login ? 'Login' : 'Register')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Поле email
            TextField(
              controller: username_cont,
              decoration: const InputDecoration(
                labelText: 'Email',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            
            // Поле пароля
            TextField(
              controller: password_cont,
              obscureText: true, // Скрываем пароль
              decoration: const InputDecoration(
                labelText: 'Password',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 20),
            
            // Кнопка входа/регистрации
            ElevatedButton(
              onPressed: _auth,
              child: Text(is_login ? 'Login' : 'Register'),
            ),
            const SizedBox(height: 10),
            
            // Переключение между входом и регистрацией
            TextButton(
              onPressed: () => setState(() => is_login = !is_login),
              child: Text(is_login
                ? 'Register' 
                : 'Login'
              ),
            ),
          ],
        ),
      ),
    );
  }
  void _auth(){
    final username = username_cont.text;
    final psw = password_cont.text;
    if(username.isEmpty || psw.isEmpty){
      _showMessage("Fill all the blanks");
    }

  }
  void _showMessage(String text) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(text)),
    );
  }


}
