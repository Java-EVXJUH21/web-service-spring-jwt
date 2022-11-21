package com.example.springjwtexample;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager manager;

    public JWTLoginFilter(AuthenticationManager manager) {
        this.manager = manager;
    }
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        var username = request.getHeader("username");
        var password = request.getHeader("password");

        var auth = new UsernamePasswordAuthenticationToken(username, password);

        return manager.authenticate(auth);
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException, ServletException {
        try {
            var algorithm = Algorithm.HMAC256("secret-code");
            var token = JWT.create()
                    .withIssuer("auth0")
                    .withSubject(authResult.getName())
                    .withClaim("hej", 5)
                    .sign(algorithm);

            response.addHeader("token", token);
        } catch (JWTCreationException exception) {
            exception.printStackTrace();
        }
    }
}
