package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/user")
    public List<Map<String, Object>> getUser(@RequestParam String username) {
        // VULNERABLE: Raw string concatenation in SQL query
        // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
        // An attacker can supply username=admin' OR '1'='1'-- to bypass authentication
        String sql = "SELECT id, username, email FROM users WHERE username = '" + username + "'";

        return jdbcTemplate.queryForList(sql);
    }
}
