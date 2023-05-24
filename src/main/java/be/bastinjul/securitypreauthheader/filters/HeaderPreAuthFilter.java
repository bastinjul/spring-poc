package be.bastinjul.securitypreauthheader.filters;

import be.bastinjul.securitypreauthheader.users.CustomUserBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.StringUtils;

import static be.bastinjul.securitypreauthheader.filters.HeaderPresenceFilter.CUSTOM_HEADER;

public class HeaderPreAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

    public HeaderPreAuthFilter(AuthenticationManager preAuthManager) {
        this.setAuthenticationManager(preAuthManager);
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        if(StringUtils.hasText(request.getHeader(CUSTOM_HEADER))) {
            DecodedJWT decodedJWT = JWT.decode(request.getHeader(CUSTOM_HEADER));
            return new CustomUserBuilder()
                    .username(decodedJWT.getSubject())
                    .roles(decodedJWT.getClaim("roles").asList(String.class))
                    .additionalInfo(decodedJWT.getClaim("additionalInfo").asString())
                    .build();
        }
        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return null;
    }
}
