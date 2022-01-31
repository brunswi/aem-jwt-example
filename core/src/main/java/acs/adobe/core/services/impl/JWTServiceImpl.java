package acs.adobe.core.services.impl;

import static org.apache.sling.api.resource.ResourceResolverFactory.SUBSERVICE;

import acs.adobe.core.services.JWTService;
import com.adobe.granite.keystore.KeyStoreService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.auth0.jwt.interfaces.Verification;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;


@Component(service = JWTService.class)
@Designate(ocd = JWTServiceImpl.Config.class)
@Slf4j
public class JWTServiceImpl implements JWTService {

    private static final String SERVICE_USER = "keystore-reader";

    @Reference
    private ResourceResolverFactory resolverFactory;

    @Reference
    private KeyStoreService keyStoreService;

    private String userId;
    private String password;
    private int expirationTime;

    @ObjectClassDefinition(name = "JWT Service")
    public @interface Config {

        @AttributeDefinition(name = "UserId",
            description = "Id of the User holding the keystore")
        String userId() default "jwt-user";

        @AttributeDefinition(name = "Password",
            description = "Keystore password")
        String password() default "secret";

        @AttributeDefinition(name = "Expiration Time",
            description = "Valid Time of the Token in Seconds")
        int expirationTime() default 3600;
    }

    @Activate
    protected void activate(Config config) {
        userId = config.userId();
        password = config.password();
        expirationTime = config.expirationTime();
        log.info("Activated with userId {}", userId);
    }

    public String createToken(ACCESS_TYPE accessType, String userId) {
        String token = null;
        try (ResourceResolver resolver = resolverFactory.getServiceResourceResolver(
            Collections.singletonMap(SUBSERVICE, SERVICE_USER))) {
            KeyStore keyStore = keyStoreService.getKeyStore(resolver, this.userId);
            log.info("keyStore: {}", keyStore);
            Algorithm algorithm = Algorithm.RSA256(getKeyProvider(keyStore));
            token = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + (expirationTime * 1000L)))
                .withClaim(ACCESS, accessType.name())
                .withSubject(userId)
                .sign(algorithm);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return token;
    }

    public DecodedJWT verifyToken(String token) {
        DecodedJWT jwt = null;
        long startTime = System.currentTimeMillis();
        try (ResourceResolver resolver = resolverFactory.getServiceResourceResolver(
            Collections.singletonMap(SUBSERVICE, SERVICE_USER))) {
            KeyStore keyStore = keyStoreService.getKeyStore(resolver, userId);
            Algorithm algorithm = Algorithm.RSA256(getKeyProvider(keyStore));
            Verification verification = JWT.require(algorithm);
            JWTVerifier verifier = verification.build();
            jwt = verifier.verify(decode(token));
            if (jwt == null) {
                log.error("JWT is could not be verified and is invalid.");
            }
        } catch (Exception e) {
            log.error("Could not validate JWT: {}", e.getMessage(), e);
        }
        log.debug("JWT authentication took '{}' ms.", System.currentTimeMillis() - startTime);
        return jwt;
    }

    private DecodedJWT decode(final String token) {
        DecodedJWT result = null;
        try {
            log.info("Decoding token '{}'", StringUtils.abbreviate(token, 32));
            result = JWT.decode(token);
        } catch (Exception e) {
            log.error("Could not decode JWT: {}", e.getMessage());
        }
        return result;
    }

    private RSAKeyProvider getKeyProvider(final KeyStore keyStore) {
        return new RSAKeyProvider() {
            private final String alias = getAlias();

            @Override
            public RSAPublicKey getPublicKeyById(String alias) {
                RSAPublicKey publicKey = null;
                try {
                    publicKey = (RSAPublicKey) keyStore.getCertificate(alias).getPublicKey();
                } catch (KeyStoreException e) {
                    log.error(e.getMessage(), e);
                }
                return publicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                RSAPrivateKey rsaPrivateKey = null;
                try {
                    rsaPrivateKey = (RSAPrivateKey) keyStore.getKey(alias,
                        password.toCharArray());
                    log.info("rsaPrivateKey: {}", rsaPrivateKey);
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                    log.error(e.getMessage(), e);
                }
                return rsaPrivateKey;
            }

            @Override
            public String getPrivateKeyId() {
                log.info("getPrivateKeyId: {}", alias);
                return alias;
            }

            /**
             * Returns the alias of the most recent certificate.
             * This is evaluated by examining the NotBefore property.
             * @return most recent alias
             */
            private String getAlias() {
                String alias = null;
                try {
                    // get all certificates
                    Enumeration<String> aliases = keyStore.aliases();
                    List<X509Certificate> certificates = new ArrayList<>();
                    while (aliases.hasMoreElements()) {
                        String currentAlias = aliases.nextElement();
                        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(
                            currentAlias);
                        log.info("alias: {}, certificate: {}", currentAlias, certificate);
                        certificates.add(certificate);
                    }
                    // sort certificates based on the NotBefore property
                    certificates.sort(
                        (o1, o2) -> o2.getNotBefore().compareTo(o1.getNotBefore()));
                    // get alias of latest certificate
                    alias = keyStore.getCertificateAlias(certificates.get(0));
                    log.info("alias of latest certificate: {}", alias);
                } catch (KeyStoreException e) {
                    log.error(e.getMessage(), e);
                }
                return alias;
            }
        };
    }
}
