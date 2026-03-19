package com.devsecure.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/user")
    public List<Map<String, Object>> getUser(@RequestParam String id) {
        // VULNERABLE: Direct string concatenation in Spring JdbcTemplate
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        return jdbcTemplate.queryForList(sql);
    }
}