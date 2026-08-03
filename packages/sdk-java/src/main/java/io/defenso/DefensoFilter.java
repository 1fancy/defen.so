package io.defenso;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

/**
 * Defenso Servlet filter — fail-open WAF middleware.
 *
 * Design (mirrors the Node / PHP / Python / Go / Ruby / .NET / Rust SDKs):
 * - Fails open. If Defenso is unreachable or slow, the request is allowed.
 * - Policy is cached. Rules are pulled on a background thread and evaluated
 *   locally; the request path never blocks on a network call.
 * - Logs are fire-and-forget.
 */
public class DefensoFilter implements Filter {

    private final String token;
    private final String apiUrl;
    private final HttpClient http;
    private volatile List<Rule> rules = Collections.emptyList();
    private final List<String> queue = new CopyOnWriteArrayList<>();

    public DefensoFilter(String token) {
        this(token, "https://app.defen.so/api");
    }

    public DefensoFilter(String token, String apiUrl) {
        String t = token;
        if (t == null || t.isEmpty()) {
            t = System.getenv("DEFENSO_TOKEN");
        }
        this.token = t;
        this.apiUrl = apiUrl.replaceAll("/+$", "");
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
        if (this.token != null && !this.token.isEmpty()) {
            Thread refresher = new Thread(() -> {
                while (true) {
                    refreshOnce();
                    try { Thread.sleep(300_000L); } catch (InterruptedException e) { return; }
                }
            });
            refresher.setDaemon(true);
            refresher.start();
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (token == null || token.isEmpty() || !(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }
        try {
            HttpServletRequest req = (HttpServletRequest) request;
            String query = req.getQueryString() == null ? "" : req.getQueryString();
            String path = req.getRequestURI() == null ? "" : req.getRequestURI();
            Rule match = evaluate(path, query);
            if (match != null && "block".equals(match.action)) {
                queueLog(match, req);
                HttpServletResponse res = (HttpServletResponse) response;
                res.setStatus(403);
                res.setContentType("application/json");
                res.getWriter().write("{\"error\":\"Request blocked by Defenso\",\"rule\":\"" + esc(match.id) + "\"}");
                return;
            }
        } catch (Exception ignored) {
            // Any error must fail open.
        }
        chain.doFilter(request, response);
    }

    private Rule evaluate(String path, String query) {
        for (Rule r : rules) {
            String hay = "url".equals(r.target) ? path : query; // headers target omitted for simplicity
            if (hay != null && !hay.isEmpty() && r.pattern.matcher(hay).find()) {
                return r;
            }
        }
        return null;
    }

    private void refreshOnce() {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(apiUrl + "/policy"))
                    .timeout(Duration.ofSeconds(1))
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .GET().build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) return;
            this.rules = Json.parseRules(res.body());
        } catch (Exception ignored) {
            // Fail open: keep last-known-good rules.
        }
    }

    private void queueLog(Rule m, HttpServletRequest req) {
        String ip = req.getHeader("CF-Connecting-IP");
        if (ip == null) ip = req.getRemoteAddr();
        String entry = "{\"at\":" + Instant.now().getEpochSecond()
                + ",\"verdict\":{\"action\":\"block\",\"rule\":{\"id\":\"" + esc(m.id) + "\"},\"reason\":\"" + esc(m.category) + "\"}"
                + ",\"request\":{\"method\":\"" + esc(req.getMethod()) + "\",\"url\":\"" + esc(req.getRequestURI()) + "\",\"ip\":\"" + esc(ip) + "\"}}";
        queue.add(entry);
        if (queue.size() >= 25) {
            List<String> batch = new ArrayList<>(queue);
            queue.clear();
            flush(batch);
        }
    }

    private void flush(List<String> batch) {
        Thread t = new Thread(() -> {
            try {
                String body = "{\"logs\":[" + String.join(",", batch) + "]}";
                HttpRequest req = HttpRequest.newBuilder(URI.create(apiUrl + "/attacks/ingest"))
                        .timeout(Duration.ofSeconds(1))
                        .header("Authorization", "Bearer " + token)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build();
                http.send(req, HttpResponse.BodyHandlers.discarding());
            } catch (Exception ignored) {
                // logs are best-effort
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static final class Rule {
        final String id, action, target, category;
        final Pattern pattern;
        Rule(String id, String action, String target, String category, Pattern pattern) {
            this.id = id; this.action = action; this.target = target; this.category = category; this.pattern = pattern;
        }
    }
}
