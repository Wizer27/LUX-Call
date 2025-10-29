import 'package:flutter/material.dart';
import 'dart:io';
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';


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
late GenerateSignature signature_middleware;
void init() async {
  final secrets_data = await read_json();
  String api_key = secrets_data["api"];
  String secret_key = secrets_data["key"];
  signature_middleware = GenerateSignature(BaseUrl: "http://0.0.0.0:8080", api_key: api_key, secret_key: secret_key);

  
}
Future<bool> register(String username,String password) async {
  final time = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  final now = time.toString();
  final url = Uri.parse('http://0.0.0.0:8080/api/register');
  dynamic data = {
    'username':username,
    'password' : password
  };
  final json_data = json.encode(data);
  final signature = signature_middleware.generate_siganture(json_data, now);
  final resp = await http.post(url,headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': now,
        'X-API-Key': signature_middleware.api_key,
      },body: json_data);
  return resp.statusCode == 200;    
}
Future<bool> login(String username,String psw)async {
  final time = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  final now = time.toString();
  final url = Uri.parse('http://0.0.0.0:8080/api/login');
  dynamic data = {
    'username':username,
    'psw':psw
  };
  final json_data = json.encode(data);
  final signature = signature_middleware.generate_siganture(json_data, now);
  final resp = await http.post(url,headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': now,
        'X-API-Key': signature_middleware.api_key,
      },body: json_data);
  return resp.statusCode == 200;
}
/*
void _showMessage(String text) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(text)),
    );
  }
*/

void main() {
  runApp(const Main());
}
class Main extends StatelessWidget {
  const Main({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Lux-Call',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      routes: {
        '/': (_) => const SplashScreen(),
        '/login': (_) => const LoginPage(),
        '/register': (_) => const RegisterPage(),
        '/home': (_) => const HomePage(),
      },
      initialRoute: '/',
    );
  }
}

class SplashScreen extends StatefulWidget{
  const SplashScreen({super.key});
  @override
  State<SplashScreen> createState() => _SplashScreenState();
}
class _SplashScreenState extends State<SplashScreen>{
  final storage = const FlutterSecureStorage();
  @override
  void initState() {
    super.initState();
    _check();
  }
  Future<void> _check() async {
    final token = await storage.read(key: 'auth_token');
    if (!mounted) return;
    Navigator.of(context).pushReplacementNamed(token == null ? '/login' : '/home');
  }
  @override
  Widget build(BuildContext context) => const Scaffold(
    body: Center(child: CircularProgressIndicator()),
  );
}

class LoginPage extends StatefulWidget{
  const LoginPage({super.key});
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage>{
  
}