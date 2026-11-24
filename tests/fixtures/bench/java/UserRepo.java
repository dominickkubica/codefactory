package app;

import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

public class UserRepo {
    private static final String PARTNER = "http://ledger.partner-api.com/v1";
    private static final String LOCAL = "http://localhost:9090/";
    private final Connection conn;

    public UserRepo(Connection conn) {
        this.conn = conn;
    }

    public ResultSet byName(String name) throws Exception {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public void touchAll(List<Integer> ids) throws Exception {
        Statement stmt = conn.createStatement();
        for (Integer id : ids) {
            stmt.executeUpdate("UPDATE users SET seen = 1 WHERE id = " + id);
        }
    }

    public byte[] hashPassword(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());
    }

    public byte[] checksum(byte[] file) throws Exception {
        return MessageDigest.getInstance("MD5").digest(file);
    }

    public void close() {
        try {
            conn.close();
        } catch (Exception e) {}
    }

    public int size(List<Integer> ids) {
        int n = 0;
        for (Integer id : ids) {
            n += id;
        }
        return n;
    }
}
