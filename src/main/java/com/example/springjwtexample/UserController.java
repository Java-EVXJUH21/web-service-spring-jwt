package com.example.springjwtexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/info")
    public String info() {
        return "Hello World!";
    }

    @PostMapping("/register")
    public boolean register(
            @RequestBody Map<String, Object> credentials
    ) {
        var username = credentials.get("username");
        var password = credentials.get("password");

        userService.register((String) username, (String) password);
        return true;
    }
}
