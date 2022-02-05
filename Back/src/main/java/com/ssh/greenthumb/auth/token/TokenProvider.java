package com.ssh.greenthumb.auth.token;

import com.ssh.greenthumb.api.common.exception.NotFoundException;
import com.ssh.greenthumb.api.dao.user.UserRepository;
import com.ssh.greenthumb.api.domain.user.User;
import com.ssh.greenthumb.auth.domain.RefreshToken;
import com.ssh.greenthumb.auth.domain.UserPrincipal;
import com.ssh.greenthumb.auth.repository.RefreshTokenRepository;
import com.ssh.greenthumb.auth.service.CustomUserDetailsService;
import io.jsonwebtoken.*;
import org.aspectj.weaver.bcel.AtAjAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenProvider {

    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);
    private final AppProperties appProperties;

    @Autowired
    private RefreshTokenRepository refreshTokenDao;
    @Autowired
    private UserRepository userDao;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @Transactional
    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Map<String, Object> header = new HashMap<>();
        header.put("type", "jwt");

        Map<String, Object> payload = new HashMap<>();
        payload.put("userId", userPrincipal.getId());

        return Jwts.builder()
                .setHeader(header)
                .setClaims(payload)
                .setSubject("User Checking")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + appProperties.getAuth().getAccessTokenExpiry()))
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
                .compact();
    }

    @Transactional
    public String createRefreshToken(Long userId) {
        Map<String, Object> header = new HashMap<>();
        header.put("type", "jwt");

        Map<String, Object> payload = new HashMap<>();
        payload.put("userId", userId);

        String refreshToken = Jwts.builder()
                .setHeader(header)
                .setClaims(payload)
                .setSubject("User Checking")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + appProperties.getAuth().getRefreshTokenExpiry()))
                .signWith(SignatureAlgorithm.HS256, appProperties.getAuth().getTokenSecret())
                .compact();

        User user = userDao.findById(userId).orElseThrow(NotFoundException::new);

        return refreshTokenDao.save(RefreshToken.builder()
                .refreshToken(refreshToken)
                .user(user)
                .build()).getRefreshToken();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = customUserDetailsService.loadUserById(this.getUserId(token));
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    public Long getUserId(String token) {
       return (Long) Jwts.parser()
                .setSigningKey(appProperties.getAuth().getTokenSecret())
                .parseClaimsJws(token)
                .getBody().get("userId");
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            log.error("유효하지 않은 JWT 서명");
        } catch (MalformedJwtException ex) {
            log.error("유효하지 않은 JWT 토큰");
        } catch (ExpiredJwtException ex) {
            log.error("만료된 JWT 토큰");
        } catch (UnsupportedJwtException ex) {
            log.error("지원하지 않는 JWT 토큰");
        } catch (IllegalArgumentException ex) {
            log.error("비어있는 JWT");
        }
        return false;
    }

}
