package com.ssh.greenthumb.api.controller;

import com.ssh.greenthumb.api.dao.user.UserRepository;
import com.ssh.greenthumb.api.domain.user.User;
import com.ssh.greenthumb.api.dto.login.AuthRequest;
import com.ssh.greenthumb.api.dto.login.SignUpRequest;
import com.ssh.greenthumb.api.service.AuthService;
import com.ssh.greenthumb.auth.domain.CurrentUser;
import com.ssh.greenthumb.auth.domain.UserPrincipal;
import com.ssh.greenthumb.auth.token.AppProperties;
import io.jsonwebtoken.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.elasticsearch.ResourceNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

@Tag(name = "User", description = "사용자 API")
@RequestMapping("/auth")
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final AuthService authService;
    private final UserRepository userDao;
    private final AppProperties appProperties;

    @Operation(summary = "로그인", description = "이메일, 패스워드를 입력하여 로그인을 합니다.")
    @PostMapping("/login")
    public Object authenticateUser(@RequestBody AuthRequest.Login loginRequest) {
        return authService.authenticateUser(loginRequest);
    }

    @Operation(summary = "회원가입", description = "이메일, 패스워드, 닉네임을 입력하여 회원가입을 합니다.")
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignUpRequest signUpRequest) {
        return authService.registerUser(signUpRequest);
    }

    @Operation(summary = "로그아웃", description = "사용자 id로 로그아웃을 합니다.")
    @Transactional
    @DeleteMapping("/logout/{id}")
    public void logout(@PathVariable Long id) {
        authService.logout(id);
    }

    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userDao.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }

}