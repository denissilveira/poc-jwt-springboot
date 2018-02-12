package com.pocs.jwtboot.auth;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.pocs.jwtboot.model.entity.User;
import com.pocs.jwtboot.provider.TimeProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class TokenHelper {

    @Value("${app.name}")
    private String APP_NAME;
    @Value("${jwt.secret}")
    public String SECRET;
    @Value("${jwt.expires_in}")
    private int EXPIRES_IN;
    @Value("${jwt.mobile_expires_in}")
    private int MOBILE_EXPIRES_IN;
    @Value("${jwt.header}")
    private String AUTH_HEADER;

    public static final String AUDIENCE_UNKNOWN = "unknown";
    public static final String AUDIENCE_WEB = "web";
    public static final String AUDIENCE_MOBILE = "mobile";
    public static final String AUDIENCE_TABLET = "tablet";

    @Autowired
    private TimeProvider timeProvider;
    private SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;

    public String getUsernameFromToken(final String token) {

        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            return claims.getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    public Date getIssuedAtDateFromToken(final String token) {
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            return claims.getIssuedAt();
        } catch (Exception e) {
            return null;
        }
    }

    public String getAudienceFromToken(final String token) {
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            return claims.getAudience();
        } catch (Exception e) {
            return null;
        }
    }

    public String refreshToken(final String token, final Device device) {
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            claims.setIssuedAt(timeProvider.now());
            return Jwts.builder()
                    .setClaims(claims)
                    .setExpiration(generateExpirationDate(device))
                    .signWith(SIGNATURE_ALGORITHM, SECRET)
                    .compact();
        } catch (Exception e) {
            return null;
        }
    }

    public String generateToken(final String username, final Device device) {
        return Jwts.builder()
                .setIssuer(APP_NAME)
                .setSubject(username)
                .setAudience(generateAudience(device))
                .setIssuedAt(timeProvider.now())
                .setExpiration(generateExpirationDate(device))
                .signWith(SIGNATURE_ALGORITHM, SECRET)
                .compact();
    }

    private String generateAudience(final Device device) {
        if (device.isNormal()) {
            return AUDIENCE_WEB;
        } else if (device.isTablet()) {
            return AUDIENCE_TABLET;
        } else if (device.isMobile()) {
            return AUDIENCE_MOBILE;
        }
        return AUDIENCE_UNKNOWN;
    }

    private Claims getAllClaimsFromToken(final String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    private Date generateExpirationDate(final Device device) {
        long expiresIn = device.isTablet() || device.isMobile() ? MOBILE_EXPIRES_IN : EXPIRES_IN;
        return new Date(timeProvider.now().getTime() + expiresIn * 1000);
    }

    public int getExpiredIn(final Device device) {
        return device.isMobile() || device.isTablet() ? MOBILE_EXPIRES_IN : EXPIRES_IN;
    }

    public Boolean validateToken(final String token, final UserDetails userDetails) {
        final User user = (User) userDetails;
        final String username = getUsernameFromToken(token);
        final Date created = getIssuedAtDateFromToken(token);
        return (username != null && username.equals(userDetails.getUsername())
                && !isCreatedBeforeLastPasswordReset(created, user.getLastPasswordResetDate()));
    }

    private Boolean isCreatedBeforeLastPasswordReset(final Date created, final Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    public String getToken(final HttpServletRequest request) {

        final String authHeader = getAuthHeaderFromHeader(request);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    public String getAuthHeaderFromHeader(final HttpServletRequest request) {
        return request.getHeader(AUTH_HEADER);
    }

}