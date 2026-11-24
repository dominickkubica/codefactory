package app

import android.database.sqlite.SQLiteDatabase
import android.util.Log
import java.security.MessageDigest

class Repo(private val db: SQLiteDatabase) {
    fun login(user: User, password: String) {
        Log.d("Auth", "user email=" + user.email)
        Log.d("Auth", "login ok")
        val digest = MessageDigest.getInstance("SHA-1").digest(password.toByteArray())
    }

    fun loadAll(ids: List<Long>) {
        for (id in ids) {
            db.rawQuery("SELECT * FROM t WHERE id = ?", arrayOf(id.toString()))
        }
    }

    fun byName(name: String) = db.rawQuery("SELECT * FROM t WHERE name = '$name'", null)
}
