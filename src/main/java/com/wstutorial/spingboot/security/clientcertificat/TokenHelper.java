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
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChqlR7dQIkD2Sn" +
                    "Ub2IrK8SFUpFeH0rlEK1oxcPpwJklQWaeSYIop1SRDGTf3JutVZ1smp9QHTchjtP" +
                    "jfgjrkoUHJ1R7EJuo3z1iAwn2i2ufyd1qsrFyPbK4F6QT90DWFiYnJ8J0liuIqK7" +
                    "IsCxmU2o4ED2MqdhTESFb2qXgd2EorafFElDsNHym+0J0nVY22wiv/ynCVirkVv3" +
                    "VSxzIOAJ+dOPwSXsQAryfP3DQK4If+YXTGnZRIRuzDm0qi5KaAqDCq6S10Opqu11" +
                    "Zx1C6awwxycCFU1AXRAbx6lIKrIfpiOKyLw47DAs3KRhe3SvoHkWEizHc9CEBp68" +
                    "/AI6DuvfAgMBAAECggEAJb8ldqX9V/oYIFEflffr8Kbz7oCRiUlWwh5QViFCl8WL" +
                    "x2OeE8oUPY8anDvXti21AEomPxR7tLnKw2p8k6gwN73upaAqarbViGa5n9x7ahDa" +
                    "X8j/C2s+5GO68KsVCaDpHskDAUIR3qbLpDIbF9yZm2KxCEsPddJe9WDsXG/ADyWn" +
                    "sDV6W+ISQKPhlWK9/d92S7CCHRg1XBnW19C1JdxG5m4TUC0XDF3oRJEjTAJq0NU4" +
                    "EtIPo7ymzVwcaCAce5dGQdWTZw2LMCGbK0CkkoZHCUCd9mrTsFcb9okb3jIMwl6y" +
                    "9Rc7W6zLHIrU/6u689MpQtj7DVZNsuVN+K6S0oK+kQKBgQDVCebkt19iucqzZPll" +
                    "P8oW7kAV+JStDhj6YqJlDAa8qmnRbxl+GbnRnbSDcZJ/nzi8ph5LU/pzPO6xJT8D" +
                    "aqX1Dty+e3VajsNPDm1Q2n7Ay4Ga7IMwb37LnIAVQjUGBaD1DSiIitRQJxVlKnPt" +
                    "rLWKnpKnEN3o4hqBkfcVKp5GXQKBgQDCREknoPSdc4lqvdY6roqN7vT61LHcSzTP" +
                    "b0xGm2AwpRvfwqBf04MaAUcXbTBkfp/qTZOpYbeBN7SdvHrqtBBZOX50YWEjEAzw" +
                    "IT+7bJ6OHiz3rFw9nsyYhTetmR3f9QXcr3GvdzeDyQzIqK4DJ3y7CgOW32rKmlf5" +
                    "Mvk5MkdfawKBgQDUQi5j+XQ3OGgGv3dg8uKWYEFH4sm3dtFaP4YP6aCYv6349pnO" +
                    "szEZ8ehWAoV1VJ3CED0kzoI96RrlMvgKnmrFtE4qF3YAiTd9gCFYqqoZy2nRgw7e" +
                    "5mfN1JslEzcjTd5l6ftVuAT760T87ARfbXHfsEjr3flLvGOub1FgLHtQHQKBgDwW" +
                    "gQYn6+GTrgp9I3lNKYATTGUVStpXzMLoqxAf2RXSzBdfDNn3A1MU2Bdv54r9+5qu" +
                    "WiEHH4pxX4V2mhJklbXzaaC3yiLdQRM5RYxEYZqVzNTi1DkfGCuI8RraBHqUQDbt" +
                    "cV2To3E4y6J5QjGpkhQMWeXdvxthuBpVYO8HFTp3AoGBAIrXkWhDC3DZhZ6u4/b0" +
                    "ylPUxWtrVIcSMY8lTX8FNE8e3of9mcifNI+QS3Xs3+cVAwMk3oSRLPfjNrHH14FN" +
                    "oM2NOE+9+/h82L2qr4r5uv9pUURskW+ZBPdA+Cn0ySLsPeWqCb6+MbCVhv47LPnP" +
                    "17njPUeJ5AqrPotmj2QNfazT" ;

    private static final String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoapUe3UCJA9kp1G9iKyv" +
            "EhVKRXh9K5RCtaMXD6cCZJUFmnkmCKKdUkQxk39ybrVWdbJqfUB03IY7T434I65K" +
            "FBydUexCbqN89YgMJ9otrn8ndarKxcj2yuBekE/dA1hYmJyfCdJYriKiuyLAsZlN" +
            "qOBA9jKnYUxEhW9ql4HdhKK2nxRJQ7DR8pvtCdJ1WNtsIr/8pwlYq5Fb91UscyDg" +
            "CfnTj8El7EAK8nz9w0CuCH/mF0xp2USEbsw5tKouSmgKgwquktdDqartdWcdQums" +
            "MMcnAhVNQF0QG8epSCqyH6Yjisi8OOwwLNykYXt0r6B5FhIsx3PQhAaevPwCOg7r" +
            "3wIDAQAB";

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
   //     claims.put("roles", "operator")
        Map<String, Object> header = new HashMap<>();
        header = Jwts.jwsHeader();
        header.put("alg", "RS256");
        header.put("typ", "JWT");
        header.put("kid", "id1234");
        //Jwts.header(header);
        String s =  Jwts.builder()
                .setHeader(header)
                .setClaims(claims)
                //.setId("id1234")
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

        String role =  "p093operator"; // (name, null); // //
        Map<String, String> claims = new HashMap<>();
        claims.put("roles", role);
        TokenHelper h = new TokenHelper();
        String s = h.generateToken("testoperator" , claims);
        h.getAllClaimsFromToken(s);
    }
}
