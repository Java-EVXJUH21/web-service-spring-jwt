package com.example.springjwtexample;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTVerifyFilter extends OncePerRequestFilter {

    private final UserService userService;

    public JWTVerifyFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        var authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Authorization: Bearer aciroiHJOIGYFrnXNUOÅEFIPUVBIG7680

        var jwtToken = authorizationHeader.substring("Bearer ".length());
        if (jwtToken.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            var algorithm = Algorithm.HMAC256("secret-code");
            var verifier = JWT.require(algorithm)
                    .withIssuer("auth0")
                    .build();

            var jwt = verifier.verify(jwtToken);

            var user = userService.loadUserByUsername(jwt.getSubject());

            var auth = new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(auth);

            filterChain.doFilter(request, response);
        } catch (JWTVerificationException exception) {
            throw new IllegalStateException("Failed to authenticate");
        }
    }
}
