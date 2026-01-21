
package com.example.resourceserver;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/public")
    public String publicApi() {
        return "public ok";
    }

    @GetMapping("/api/hello")
    public String hello(@AuthenticationPrincipal Jwt jwt) {
        return "hello, sub=" + jwt.getSubject();
    }
}
