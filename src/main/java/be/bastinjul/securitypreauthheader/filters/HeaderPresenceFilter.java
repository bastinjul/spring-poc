package be.bastinjul.securitypreauthheader.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class HeaderPresenceFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(HeaderPresenceFilter.class);

    public static final String CUSTOM_HEADER = "X-Custom-Header";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(LOGGER.isDebugEnabled()) LOGGER.debug("Check presence for header {}", CUSTOM_HEADER);
        if(StringUtils.hasText(request.getHeader(CUSTOM_HEADER))) {
            filterChain.doFilter(request, response);
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getOutputStream().println(String.format("Header %s is not present", CUSTOM_HEADER));
        }
    }
}
