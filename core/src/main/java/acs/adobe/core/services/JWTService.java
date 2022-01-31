package acs.adobe.core.services;

import com.auth0.jwt.interfaces.DecodedJWT;

public interface JWTService {

    /**
     * Creates a token based on the given accessType and the given userId.
     * @param accessType access claim of the JWT
     * @param userId sub claim of the JWT
     * @return JWT token
     */
    String createToken(ACCESS_TYPE accessType, String userId);

    /**
     * Verifies the given token.
     * @param token token to be verified
     * @return DecodedJWT if the token can be verified. Otherwise, <code>null</code> is returned.
     */
    DecodedJWT verifyToken(String token);

    /**
     * Example for using an ACCESS_TYPE with the token.
     * Can be one of RESTRICTED or CONFIDENTIAL
     * See @createToken
     */
    enum ACCESS_TYPE {
        RESTRICTED,
        CONFIDENTIAL
    }

    /**
     * Name of the access/accessType claim
     */
    String ACCESS = "access";
}