import 'package:flutter/material.dart';
import 'dart:io';
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;


// ------- INIT FILE -------
final secrets = '/Users/ivan/LUX-Call/data/secrets.json';

Future<Map<String,dynamic>> read_json() async{
  try{
    final file  = File(secrets);
    final data = await file.readAsString();
    return jsonDecode(data) as Map<String, dynamic>;
  }catch(e){
    print('Exception $e');
    return {};
  }
}

class GenerateSignature {
  final String BaseUrl;
  final String api_key;
  final String secret_key;

  GenerateSignature({
    required this.BaseUrl,
    required this.api_key,
    required this.secret_key,
  });
  String TimeStamp(){
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return now.toString();
  }
  String generate_siganture(String data,String timestamp){
    final message = data + timestamp + secret_key;
    final key = utf8.encode(secret_key);
    final bytes = utf8.encode(message);
    final hmac = Hmac(sha256, key);
    final digest = hmac.convert(bytes);
    return digest.toString();
  }
  Future<http.Response> test_post({required String endpoint,required Map<String,dynamic> data}) async{
    final timestamp = TimeStamp();
    final url = Uri.parse('$BaseUrl$endpoint');
    final json_data = json.encode(data);
    final signature = generate_siganture(json_data,timestamp);
    return await http.post(
      url,
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': timestamp,
        'X-API-Key': api_key,
      },
      body: json_data,
    );

  }
}
late GenerateSignature siganture_middleware;
void init() async {
  final secrets_data = await read_json();
  String api_key = secrets_data["api"];
  String secret_key = secrets_data["key"];
  siganture_middleware = GenerateSignature(BaseUrl: "http://0.0.0.0:80", api_key: api_key, secret_key: secret_key);

  
}


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
