package acs.adobe.core.servlets;

import acs.adobe.core.services.JWTService;
import acs.adobe.core.services.JWTService.ACCESS_TYPE;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.util.Arrays;
import javax.servlet.Servlet;
import javax.servlet.http.Cookie;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.servlets.annotations.SlingServletResourceTypes;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;

@Component(service = {Servlet.class})
@SlingServletResourceTypes(
    resourceTypes = "jwt/components/page",
    methods = HttpConstants.METHOD_GET,
    extensions = "txt")
@ServiceDescription("Login Servlet")
@Slf4j
public class TestServlet extends SlingSafeMethodsServlet {

    @Reference
    JWTService jwtService;

    @Override
    protected void doGet(@NonNull final SlingHttpServletRequest request, @NonNull final SlingHttpServletResponse response) throws IOException {
        String userId = request.getParameter("login");
        response.setContentType("text/plain;charset=UTF-8");
        if (userId != null) {
            // userId is set with the login parameter: create a new token and store it in a cookie
            String token = jwtService.createToken(ACCESS_TYPE.RESTRICTED, userId);
            response.getWriter().println(token);
            DecodedJWT jwt = jwtService.verifyToken(token);
            response.getWriter().println(jwt != null);
            if (jwt != null) {
                Cookie cookie = new Cookie("auth-token", token);
                cookie.setHttpOnly(true);
                response.addCookie(cookie);
            }
        } else {
            // validate a given token and print out some info about the user
            String token = Arrays.stream(request.getCookies())
                .filter(c -> "auth-token".equals(c.getName()))
                .map(Cookie::getValue)
                .findAny().orElse(StringUtils.EMPTY);
            DecodedJWT jwt = jwtService.verifyToken(token);
            response.getWriter().println("Validate token '" + token + "': " + (jwt != null));
            if (jwt != null) {
                response.getWriter().println("userId: " + jwt.getClaim("sub"));
                response.getWriter().println("access: " + jwt.getClaim(JWTService.ACCESS));
            }
        }
    }
}
