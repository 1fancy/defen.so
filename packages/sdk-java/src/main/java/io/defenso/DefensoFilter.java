package io.defenso;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Defenso Servlet filter — fail-open security middleware.
 *
 * Alpha scaffold. Full impl: policy fetch + local eval + background attack ingest.
 */
public class DefensoFilter implements Filter {

    private final String token;

    public DefensoFilter(String token) {
        this.token = token;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // TODO: policy check; short-circuit with 403 on match
        chain.doFilter(request, response);
    }
}
