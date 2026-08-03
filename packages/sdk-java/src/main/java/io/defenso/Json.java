package io.defenso;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal, dependency-free reader for the Defenso policy response. We only need
 * the "rules" array's id/pattern/flags/target/action/category fields, so a full
 * JSON library is unnecessary. A malformed rule is skipped, never fatal — the
 * SDK fails open.
 */
final class Json {

    private Json() {}

    // Each rule object between the outer { ... } of the "rules" array.
    private static final Pattern OBJ = Pattern.compile("\\{[^}]*\\}");

    static List<DefensoFilter.Rule> parseRules(String body) {
        List<DefensoFilter.Rule> out = new ArrayList<>();
        if (body == null) return out;
        int idx = body.indexOf("\"rules\"");
        if (idx < 0) return out;
        int start = body.indexOf('[', idx);
        int end = body.indexOf(']', start);
        if (start < 0 || end < 0) return out;
        String arr = body.substring(start, end + 1);

        Matcher m = OBJ.matcher(arr);
        while (m.find()) {
            String o = m.group();
            String id = str(o, "id");
            String pat = str(o, "pattern");
            if (id == null || pat == null) continue;
            String flags = str(o, "flags");
            String target = str(o, "target");
            String action = str(o, "action");
            String category = str(o, "category");
            try {
                int f = (flags != null && flags.contains("i")) ? Pattern.CASE_INSENSITIVE : 0;
                Pattern p = Pattern.compile(unescape(pat), f);
                out.add(new DefensoFilter.Rule(
                        id,
                        action == null || action.isEmpty() ? "block" : action,
                        target == null || target.isEmpty() ? "query" : target,
                        category == null ? "" : category,
                        p));
            } catch (Exception ignored) {
                // skip a bad regex, never fatal
            }
        }
        return out;
    }

    // Extract a JSON string value for the given key from a flat object literal.
    private static String str(String obj, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(obj);
        return m.find() ? m.group(1) : null;
    }

    private static String unescape(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\/", "/");
    }
}
