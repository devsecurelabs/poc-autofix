import 'package:sqflite/sqflite.dart';

// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// VULNERABLE: Dart string interpolation passed directly to rawQuery
// An attacker can supply id=1 OR 1=1 to dump the entire users table

class DbHelper {
  Database? db;

  Future<List<Map>> getUser(String id) async {
    return await db!.rawQuery('SELECT * FROM users WHERE id = ?', [id]);
  }
}
