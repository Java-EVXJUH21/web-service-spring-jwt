package com.example.springjwtexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserService implements UserDetailsService {

    private final PasswordEncoder encoder;
    private final Map<String, User> users = new HashMap<>();

    @Autowired
    public UserService(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException
    {
        var user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException(username + " was not found.");
        }

        return user;
    }

    public User register(String username, String password) {
        var user = new User(username, encoder.encode(password));
        users.put(user.getUsername(), user);
        return user;
    }
}
