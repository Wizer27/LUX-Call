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
class TokenStorage {
  static const _s = FlutterSecureStorage();
  static Future<void> save(String access, String refresh) async {
    await _s.write(key: 'access', value: access);
    await _s.write(key: 'refresh', value: refresh);
  }
  static Future<String?> get access async => _s.read(key: 'access');
  static Future<String?> get refresh async => _s.read(key: 'refresh');
  static Future<void> clear() async {
    await _s.delete(key: 'access');
    await _s.delete(key: 'refresh');
  }
}

class HmacAuthClient extends http.BaseClient {
  HmacAuthClient({
    required this.baseUrl,
    required this.apiKey,
    required this.secretKey,
  });

  final String baseUrl;
  final String apiKey;
  final String secretKey;
  final http.Client _inner = http.Client();

  String _ts() => (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();

  String _sign(String jsonData, String ts) {
    final message = jsonData + ts + secretKey;
    final hmacSha256 = Hmac(sha256, utf8.encode(secretKey));
    return hmacSha256.convert(utf8.encode(message)).toString();
  }

  Future<http.StreamedResponse> _sendOnce(http.BaseRequest req, {String bodyForSign = ''}) async {
    // baseUrl для относительных путей
    if (!req.url.isAbsolute) {
      req.url = Uri.parse('$baseUrl${req.url.path}');
    }

    final access = await TokenStorage.access;
    final ts = _ts();
    final sig = _sign(bodyForSign, ts);

    req.headers.addAll({
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
      'X-Timestamp': ts,
      'X-Signature': sig,
      if (access != null) 'Authorization': 'Bearer $access',
    });

    return _inner.send(req);
  }

  Future<http.StreamedResponse> _sendWithRefresh(http.BaseRequest req, {String bodyForSign = ''}) async {
    var res = await _sendOnce(req, bodyForSign: bodyForSign);
    if (res.statusCode != 401) return res;

    // пробуем refresh
    final refresh = await TokenStorage.refresh;
    if (refresh == null) return res;

    final r = http.Request('POST', Uri.parse('$baseUrl/refresh'));
    final body = jsonEncode({'token': refresh});
    // ручная подпись для refresh
    final ts = _ts();
    final sig = _sign(body, ts);
    r.headers.addAll({
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
      'X-Timestamp': ts,
      'X-Signature': sig,
    });
    r.body = body;

    final rResp = await _inner.send(r);
    final rFull = await http.Response.fromStream(rResp);

    if (rFull.statusCode >= 200 && rFull.statusCode < 300) {
      final map = jsonDecode(rFull.body) as Map<String, dynamic>;
      final newAccess = map['access_token'] as String?;
      final newRefresh = map['refresh_token'] as String?;
      if (newAccess != null && newRefresh != null) {
        await TokenStorage.save(newAccess, newRefresh);
        // пересобрать исходный запрос
        final rebuilt = http.Request(req.method, req.url);
        rebuilt.headers.addAll(req.headers);
        if (req is http.Request) {
          rebuilt.body = (req.body);
        }
        return _sendOnce(rebuilt, bodyForSign: bodyForSign);
      }
    }

    return res; // refresh не удался
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final bodyForSign = request is http.Request ? request.body : '';
    return _sendWithRefresh(request, bodyForSign: bodyForSign);
  }

  // Удобные хелперы:
  Future<http.Response> getJson(String path) async {
    final req = http.Request('GET', Uri.parse(path));
    final s = await send(req);
    return http.Response.fromStream(s);
    }
  Future<http.Response> postJson(String path, Map<String, dynamic> data) async {
    final req = http.Request('POST', Uri.parse(path));
    req.body = jsonEncode(data);
    final s = await send(req);
    return http.Response.fromStream(s);
  }
}
