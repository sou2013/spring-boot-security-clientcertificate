package com.wstutorial.spingboot.security.clientcertificat;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenHelper {

    @Value("${jwt.expires_in}")
    private int EXPIRES_IN;

    @Value("${jwt.header}")
    private String AUTH_HEADER;

    static final String AUDIENCE_UNKNOWN = "unknown";
    static final String AUDIENCE_WEB = "web";
    static final String AUDIENCE_MOBILE = "mobile";
    static final String AUDIENCE_TABLET = "tablet";
    private static final String privateKey =
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDK7c0HtOvefMRM" +
                    "s1tkdiJm+A16Df85lQlmXjQvMHNgY4P/znvl4kRON9DdBdo3K81OG7pR/0H9XvdB" +
                    "TEojj/6vCVuMDeeIiBrgx0OJjhv0r8oUD4d52+1kXXITaniyZcbJ08s4sF7fUSCu" +
                    "IZOhvvwQTd/tIwXGU1qqfg+bsomQ6h2czPSKXAux54vUiRO2IWf/Y6twyk8cy1PH" +
                    "IOfelCVUJ4kzmP+CsOH7Rh3JMwZ0Mc4GAzndWpKwNXKjVM20/bKE9FgIiIjzmEQd" +
                    "VpSdUz2MbAKM1kskdaHXQyuaHoHfPwESYuEwBld4vh9AGMF3jYMu8ggnAzVRIoWG" +
                    "Mr5eCE2tAgMBAAECggEBAKBPXiKRdahMzlJ9elyRyrmnihX7Cr41k7hwAS+qSetC" +
                    "kpu6RjykFCvqgjCpF+tvyf/DfdybF0mPBStrlkIj1iH29YBd16QPSZR7NkprnoAd" +
                    "gzl3zyGgcRhRjfXyrajZKEJ281s0Ua5/i56kXdlwY/aJXrYabcxwOvbnIXNxhqWY" +
                    "NSejZn75fcacSyvaueRO6NqxmCTBG2IO4FDc/xGzsyFKIOVYS+B4o/ktUOlU3Kbf" +
                    "vwtz7U5GAh9mpFF+Dkr77Kv3i2aQUonja6is7X3JlA93dPu4JDWK8jrhgdZqY9p9" +
                    "Q8odbKYUaBV8Z8CnNgz2zaNQinshzwOeGfFlsd6H7SECgYEA7ScsDCL7omoXj4lV" +
                    "Mt9RkWp6wQ8WDu5M+OCDrcM1/lfyta2wf7+9hv7iDb+FwQnWO3W7eFngYUTwSw5x" +
                    "YP2uvOL5qbe7YntKI4Q9gHgUd4XdRJJSIdcoY9/d1pavkYwOGk7KsUrmSeoJJ2Jg" +
                    "54ypVzZlVRkcHjuwiiXKvHwj2+UCgYEA2w5YvWSujExREmue0BOXtypOPgxuolZY" +
                    "pS5LnuAr4rvrZakE8I4sdYjh0yLZ6qXJHzVlxW3DhTqhcrhTLhd54YDogy2IT2ff" +
                    "0GzAV0kX+nz+mRhw0/u+Yw6h0QuzH9Q04Wg3T/u/K9+rG335j/RU1Tnh7nxetfGb" +
                    "EwJ1oOqcXikCgYEAqBAWmxM/mL3urH36ru6r842uKJr0WuhuDAGvz7iDzxesnSvV" +
                    "5PKQ8dY3hN6xfzflZoXssUGgTc55K/e0SbP93UZNAAWA+i29QKY6n4x5lKp9QFch" +
                    "dXHw4baIk8Z97Xt/kw07f6FAyijdC9ggLHf2miOmdEQzNQm/9mcJ4cFn+DECgYEA" +
                    "gvOepQntNr3gsUxY0jcEOWE3COzRroZD0+tLFZ0ZXx/L5ygVZeD4PwMnTNrGvvmA" +
                    "tAFt54pomdqk7Tm3sBQkrmQrm0+67w0/xQ9eJE/z37CdWtQ7jt4twHXc0mVWHa70" +
                    "NdPhTRVIAWhil7rFWANOO3Gw2KrMy6O1erW7sAjQlZECgYBmjXWzgasT7JcHrP72" +
                    "fqrEx4cg/jQFNlqODNb515tfXSBBoAFiaxWJK3Uh/60/I6cFL/Qoner4trNDWSNo" +
                    "YENBqXLZnWGfIo0vAIgniJ6OD67+1hEQtbenhSfeE8Hou2BnFOTajUxmYgGm3+hx" +
                    "h8TPOvfHATdiwIm7Qu76gHhpzQ==" ;

    private static final String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyu3NB7Tr3nzETLNbZHYi" +
            "ZvgNeg3/OZUJZl40LzBzYGOD/8575eJETjfQ3QXaNyvNThu6Uf9B/V73QUxKI4/+" +
            "rwlbjA3niIga4MdDiY4b9K/KFA+HedvtZF1yE2p4smXGydPLOLBe31EgriGTob78" +
            "EE3f7SMFxlNaqn4Pm7KJkOodnMz0ilwLseeL1IkTtiFn/2OrcMpPHMtTxyDn3pQl" +
            "VCeJM5j/grDh+0YdyTMGdDHOBgM53VqSsDVyo1TNtP2yhPRYCIiI85hEHVaUnVM9" +
            "jGwCjNZLJHWh10Mrmh6B3z8BEmLhMAZXeL4fQBjBd42DLvIIJwM1USKFhjK+XghN" +
            "rQIDAQAB";

    private static final String privateKey2 =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0DB/uXu0kf3Rc" +
                    "p/Wa1lhapOt2wgtcGY86wBc541ChHKvNdPpusj757UZvo6ebExEX09T55ob1M3BS" +
                    "Dzh+G6OVtDFUde2Ws8i8XSp6uDyuyL6gSuq5EpA9GHtu0lWImWt+n0PwT+iYFk6E" +
                    "43pR98X0Cc/0YyQOLHbKNtxNwatLCx1qwB/HSM7WSxCA5hoWgi4zfdCze9I0h5Uf" +
                    "XHbv0qnyrDnjdF8TLUlo6pFowffq4yPf2s3yh9sEsIp024JSMbXAxnx5bfup2xJK" +
                    "9i3mixWu3L1sRbyL9NI1V2JhoLICumUdQ9U7iPHqhj6xVD88mlA/U209bUaWqXHz" +
                    "m1xaQyXXAgMBAAECggEAZf1ISTs0kiwwuhvaoK8ytYYea9NXpABGhj0x6vS9Q8Z9" +
                    "+5B8HCCUU/b4o1zNIKcYU6sHRdg0MsnEondExQrbC35bQ0DaKTgGSc1str+OgGPu" +
                    "t9Y4SEYftrwbj5dOJGbj4YJOdd6OHzjjmZtSOwRj+e1lA0b1saG2WK3i9ZjzczoR" +
                    "CkURHeCcZvGc9mZhh/WgR0rryxmh9Jn299ohjQ654y6vlvzDrs1i+ohVtbq4+cWX" +
                    "Uvq+eRQC9e9cS4/Is4RoDwUznuloohyCDISZte2V160vcbaD86DvYq8NgWcQpLNz" +
                    "OqLMNFQxq3rh/fncXDzuGjJxW8c0xuzr7Ak0a2MXAQKBgQDiUC3awwTWZV587PfJ" +
                    "rHBSxYBOYyrNaVNAr3kdO28y9qZnqfWPcCOmAwXnMCHXdkxIIHNhCfez6uOoF/iq" +
                    "xfHn7S0gyFq4BCwqE69PE0659zZnx+mi0egqJqOD8NFZwdRR5Nu/3oWTw3vM/dqq" +
                    "T571NPSLj5JcH9QhcMsCYtHioQKBgQDLqksGvbIYOFZGrPskC1rQK1rNRWI5L77w" +
                    "RRJCg0LJMmm1Y3l/JufdNomcalPXKdIur8ADRBEv1Mx0gZlNovFOF7GAvDY3ILJT" +
                    "iQPpGKPaJnVTP/iKhwOrz7aZLQ/D23l6+V1qry5NFKqjLfIMmErcqP+AdeKGZ7S4" +
                    "FFXS1QytdwKBgEOMXPNjrAj1/qrY6+iVAH2kF3TOIpNm8YNoHIU+HSWf+vEMCJBE" +
                    "j09YraVgd2lhFMmebfGz0OwxmrusU/tc06Q+5W5YfsNX83qnn3bBs4jMIb/+Klz/" +
                    "vAUAvWN/OG1K7j13SqPNHh+JhGUeC+szkqVrpeYV90Bp+53zlZRjvHOhAoGAXR4D" +
                    "J5Xbs48ugynbuWMnpj3sSiYK/rKBzkEGVDrHck4GXtSYXDZhlJa23DkRFDMe0hGw" +
                    "7M1WPlRBFpOakBCL23Shx4ZGE3ZzkhX3H8AQSlGDGwkIje2lFAzoI6iiqJ3UMRGK" +
                    "UJi/xqZITktXe8K1l6X9C7LaWzFXQ0Ko6rhWD4kCgYEA1mdn27O2OBRDaUZQoXCM" +
                    "6jvFMB03lYTiYLBph2gsIc/v6HQgZE3xQQZroXkXXYhc4wckM/s1qul2TIYaaVLo" +
                    "XBlJXchd5Envy/nckemdxUn0b1bmJtPaIzAEBRsZRaltjQci38aBtns4M51JIv8t" +
                    "md17Yn6pn96hLJ94LXTsD2I=";
    private static final String publicKey2 =
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoR4t+2eN5VUBLMWibuEu" +
            "dwleJA189G76fgVcKjjjd55RmyI+EkjyxGJ2RjUK4/bdN/QpeZga6RGyPT5MSiJl" +
            "63Hao0ow9Xsaz3TuEuPZHmz8uEmOAlwXetdzA/XUgaU/KNn5sol/YLvmMnuZJUO9" +
            "T6AI7cR4Uli7m8qdqidleePmOAnzcc131YZeDYs2vLR0lpLfM4m8cbUGVn944hUG" +
            "qGY4LzgcVr+Kc/AFfGoZ34hwVCSuRxB+WL8W5ok8wM1PsCOch/j9cQn/P1yTjJ5Q" +
            "TCOczL9mYLOFlqONfqL0V5njwTWFQYuwsTBBaeqnrnpyjmwDSn0TeUd4bdHkhg7H" +
            "tkcO/ALPKoU1kgGeLlg1TGrU6w935c7yUaEm8jDWJ1bmgD8LjifW8/d2wBikIZNs" +
            "MnjhRYFKl2z1Vwf6Xqtk0wLksbzZBM4038YTKN2tT+ySZSe4QAKIiJ4i8MP00YCi" +
            "jQitJj3M/wGAuhQ6ysmvqHuuNfdig2Olf4Sw5IBC2irIELnN8PDkUbEdDx4d3poK" +
            "2b2qZ6RUhD1ZejmlAqaSc2NeQqnqZEutYcU7VzGQTTnTLKdqqDDI8e7h/Lr2xR6X" +
            "xiuXJgQQnUg8oKzyqSZjGL73+2dRLADdGVcdhmoCT5k0gEr1Rs++8B4biEDeRHy3" +
            "tbC6/BX4TJKQjWUzjbS4l3kCAwEAAQ==";


    //@Autowired
    //TimeProvider timeProvider;

    private SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;

    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    public Date getIssuedAtDateFromToken(String token) {
        Date issueAt;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            issueAt = claims.getIssuedAt();
        } catch (Exception e) {
            issueAt = null;
        }
        return issueAt;
    }

    public String getAudienceFromToken(String token) {
        String audience;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            audience = claims.getAudience();
        } catch (Exception e) {
            audience = null;
        }
        return audience;
    }

    public String refreshToken(String token) {
        String refreshedToken;
        Date a =new Date();
        Date expiration = new Date(a.getTime() + 60* 60 * 1000);
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            claims.setIssuedAt(a);
            refreshedToken = Jwts.builder()
                    .setClaims(claims)
                    .setExpiration(expiration)
                    //.signWith( SIGNATURE_ALGORITHM, SECRET )
                    .signWith(SignatureAlgorithm.RS256, getPrivateKey())
                    .compact();
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }

    public String generateToken(String username,  Map<String, String> claims) {
        String audience = "web"; //generateAudience(device);
        Date expiration = new Date(new Date().getTime() + 60* 60 * 1000);
   //     Map<String, String> claims = new HashMap<>();
   //     claims.put("roles", "operator");
        String s =  Jwts.builder()
                .setClaims(claims)
                .setIssuer( "RBAC-Service" )
                .setSubject(username)
                .setAudience(audience)
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                //.signWith( SIGNATURE_ALGORITHM, SECRET )
                .signWith(getPrivateKey())
                .compact();
        // System.out.println("Using private key and generated AccessToken: " + s  + "\n");
        return s;
    }

    private static PublicKey getPublicKey() {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        PublicKey pubKey = null;
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            pubKey  = kf.generatePublic(keySpec);
        }catch(Exception e) {
            e.printStackTrace();
        }
        return pubKey;
    }

    private static PrivateKey getPrivateKey() {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory kf = null;
        PrivateKey pkey = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            pkey = kf.generatePrivate(keySpec);
        }catch (Exception e) {
            e.printStackTrace();
        }
        return pkey;
    }

    public Claims getAllClaimsFromToken(String token) {
        System.out.println("validating token signature with PublicKey: " + publicKey + "\n");
        Claims claims;
        try {
            claims = Jwts.parser()
                    // .setSigningKey(SECRET)
                    .setSigningKey(getPublicKey())
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            e.printStackTrace();
            claims = null;
        }

        System.out.println("Token contains these claims: " + claims.entrySet().toString() + "\n");
        return claims;
    }

    private Date generateExpirationDate() {
        // long expiresIn = device.isTablet() || device.isMobile() ? MOBILE_EXPIRES_IN : EXPIRES_IN;
        return new Date(new Date().getTime() + EXPIRES_IN * 1000);
    }
    /*
        public int getExpiredIn(Device device) {
            return device.isMobile() || device.isTablet() ? MOBILE_EXPIRES_IN : EXPIRES_IN;
        }
        /*
        public Boolean validateToken(String token, UserDetails userDetails) {
            User user = (User) userDetails;
            final String username = getUsernameFromToken(token);
            final Date created = getIssuedAtDateFromToken(token);
            return (
                    username != null &&
                            username.equals(userDetails.getUsername()) &&
                            !isCreatedBeforeLastPasswordReset(created, user.getLastPasswordResetDate())
            );
        }
    */
    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    public String getToken( HttpServletRequest request ) {
        /**
         *  Getting the token from Authentication header
         *  e.g Bearer your_token
         */
        String authHeader = getAuthHeaderFromHeader( request );
        if ( authHeader != null && authHeader.startsWith("Bearer ")) {
            String s = authHeader.substring(7);
            System.out.println("Received AccessToken in Bearer header: " + s + "\n");
            return  s ;
        }

        return null;
    }

    public String getAuthHeaderFromHeader( HttpServletRequest request ) {
        return request.getHeader(AUTH_HEADER);
    }

    public static void main(String[] ar) {
        System.out.println("public key=" + publicKey + "\n");
        System.out.println("private key=" + privateKey + "\n");

        TokenHelper h = new TokenHelper();
        String s = h.generateToken("testoperator" , null);
        h.getAllClaimsFromToken(s);
    }
}
