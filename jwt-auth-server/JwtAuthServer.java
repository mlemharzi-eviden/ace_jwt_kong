import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.stream.Collectors;

public class JwtAuthServer {

    // Simuler une base de données
    private static final Map<String, String> userDb = Map.of(
        "alice", "password1",
        "bob", "password2"
    );

    
    private static final String SECRET = "ThisIsASecretKeyWithAtLeast32Char"; //// Clé secrète de 32+ caractères (256 bits) pour HS256
	private static final String JWT_SECRET_Base64 = "VGhpc0lzQVNlY3JldEtleVdpdGhBdExlYXN0MzJDaGFy"; // Secret encodé en base64
	private static final String JWT_ISSUER = "ace-client";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/auth/token", new TokenHandler());
        server.setExecutor(null);
        System.out.println("Auth server running on http://localhost:8080/auth/token");
        server.start();
    }

    static class TokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String body = new BufferedReader(new InputStreamReader(exchange.getRequestBody()))
                    .lines().collect(Collectors.joining());

            String username = extract(body, "username");
            String password = extract(body, "password");

            if (username == null || password == null || !password.equals(userDb.get(username))) {
                sendTextResponse(exchange, 401, "Invalid username or password");
                return;
            }
			
			byte[] decodedJWTSecret = Base64.getDecoder().decode(JWT_SECRET_Base64);
			
			
            try {
                JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .issuer(JWT_ISSUER)
                        .subject(username)
                        .expirationTime(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .issueTime(new Date())
                        .build();
				
                JWSSigner signer = new MACSigner(decodedJWTSecret);
                SignedJWT signedJWT = new SignedJWT(
                        new JWSHeader(JWSAlgorithm.HS256),
                        claims
                );
                signedJWT.sign(signer);

                String token = signedJWT.serialize();
                String jsonResponse = "{\"token\":\"" + token + "\"}";

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, jsonResponse.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(jsonResponse.getBytes());
                }

            } catch (KeyLengthException e) {
                sendTextResponse(exchange, 500, "JWT secret must be at least 256 bits (32 characters)");
            } catch (JOSEException e) {
                sendTextResponse(exchange, 500, "JWT signing error: " + e.getMessage());
            } catch (Exception e) {
                sendTextResponse(exchange, 500, "Unexpected error: " + e.getMessage());
            }
        }

        private String extract(String json, String key) {
            if (json.contains("\"" + key + "\"")) {
                return json.replaceAll(".*\"" + key + "\"\\s*:\\s*\"([^\"]+)\".*", "$1");
            }
            return null;
        }

        private void sendTextResponse(HttpExchange exchange, int status, String message) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(status, message.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(message.getBytes());
            }
        }
    }
}
