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
        // SECURE: Using parameterized query to prevent SQL injection
        String sql = "SELECT id, username, email FROM users WHERE username = ?";

        return jdbcTemplate.queryForList(sql, username);
    }
}
