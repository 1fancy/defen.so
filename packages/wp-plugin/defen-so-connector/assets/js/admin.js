/* global jQuery, DefensoAdmin */
jQuery(function ($) {
    'use strict';

    var popup = null;

    $('#defenso-connect').on('click', function (e) {
        e.preventDefault();
        var url = DefensoAdmin.oauth_url
            + '?wp_url=' + encodeURIComponent(DefensoAdmin.site_url)
            + '&nonce=' + encodeURIComponent(DefensoAdmin.oauth_nonce);
        var w = 640, h = 780;
        var y = window.outerHeight / 2 + window.screenY - h / 2;
        var x = window.outerWidth / 2 + window.screenX - w / 2;
        popup = window.open(url, 'defensoConnect',
            'width=' + w + ',height=' + h + ',left=' + x + ',top=' + y + ',resizable=1,scrollbars=1');
        if (! popup) {
            alert('Popup blocked. Allow popups for this site and try again.');
        }
    });

    // Origin-locked postMessage listener — accepts only messages from app.defen.so.
    window.addEventListener('message', function (event) {
        if (! event.data || event.data.type !== 'defenso:wp-connected') return;
        try {
            var expected = new URL(DefensoAdmin.app_url).origin;
            if (event.origin !== expected) return;
        } catch (_) { return; }
        var key = event.data.api_key || '';
        if (! /^df_(live|test)_[A-Za-z0-9]{20,80}$/.test(key)) return;
        $.post(DefensoAdmin.ajax_url, {
            action: 'defenso_save_key',
            api_key: key,
            plan_label: event.data.plan_label || '',
            _wpnonce: DefensoAdmin.oauth_nonce
        }).done(function (r) {
            if (r && r.success) {
                window.location = r.data.redirect;
            } else {
                alert((r && r.data && r.data.message) || 'Could not save the key. Try again.');
            }
        }).fail(function () {
            alert('Network error saving the key. Try again.');
        });
    }, false);

    $('#defenso-disconnect').on('click', function (e) {
        e.preventDefault();
        if (! confirm('Disconnect Defen.so from this site? Your dashboard data is kept — you can reconnect any time.')) return;
        $.post(DefensoAdmin.ajax_url, {
            action: 'defenso_disconnect',
            _wpnonce: DefensoAdmin.admin_nonce
        }).done(function () { window.location.reload(); });
    });

    /* ---------- Malware scan ---------- */
    var $mwBtn = $('#defenso-malware-scan');
    var $mwOut = $('#defenso-malware-findings');
    function renderFindings(list) {
        if (! list || ! list.length) {
            $mwOut.html('<p style="margin-top:14px;color:#166534;">No malware signatures matched. This is heuristic — a real cleanup should be done from your Defen.so dashboard.</p>');
            return;
        }
        var rows = list.map(function (f) {
            var sev = (f.severity || 'low').toLowerCase();
            var bg = sev === 'critical' ? '#FEE2E2' : (sev === 'high' ? '#FEF3C7' : '#F3F4F6');
            var col = sev === 'critical' ? '#991B1B' : (sev === 'high' ? '#92400E' : '#525252');
            return '<tr>' +
                '<td style="padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:11.5px;color:#0a0a0a;">' + escapeHtml(f.file) + '</td>' +
                '<td style="padding:8px 10px;font-size:11px;font-weight:700;background:' + bg + ';color:' + col + ';border-radius:4px;">' + escapeHtml(String(f.severity || '').toUpperCase()) + '</td>' +
                '<td style="padding:8px 10px;font-size:12px;color:#525252;">' + escapeHtml(f.reason || '') + '</td>' +
                '</tr>';
        }).join('');
        $mwOut.html('<table style="width:100%;margin-top:16px;border-collapse:separate;border-spacing:0 6px;">' +
            '<thead><tr><th style="text-align:left;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#737373;padding:0 10px;">File</th><th style="text-align:left;font-size:10px;padding:0 10px;">Sev</th><th style="text-align:left;font-size:10px;padding:0 10px;">Signature</th></tr></thead>' +
            '<tbody>' + rows + '</tbody></table>');
    }
    function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]; }); }
    $mwBtn.on('click', function () {
        $mwBtn.prop('disabled', true).text('Scanning…');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_malware_scan', _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    renderFindings(r.data.findings);
                    $mwBtn.text('Scan again');
                } else {
                    var msg = (r && r.data && r.data.message) || 'Scan failed.';
                    if (r && r.data && r.data.upgrade_url) {
                        msg += ' Upgrade for unlimited scans: ' + r.data.upgrade_url;
                    }
                    alert(msg);
                    $mwBtn.text('Scan now');
                }
            })
            .fail(function () { alert('Network error running the scan.'); $mwBtn.text('Scan now'); })
            .always(function () { $mwBtn.prop('disabled', false); });
    });

    /* ---------- File integrity ---------- */
    var $ibBtn = $('#defenso-integrity-baseline');
    var $idBtn = $('#defenso-integrity-diff');
    var $ibOut = $('#defenso-integrity-result');
    $ibBtn.on('click', function () {
        if (! confirm('Take a fresh integrity baseline of every PHP/JS/.htaccess file? Overwrites the current baseline.')) return;
        $ibBtn.prop('disabled', true).text('Hashing…');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_integrity_baseline', _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    $ibOut.html('<p style="margin-top:14px;color:#166534;">Baseline stored · ' + r.data.files + ' files hashed.</p>');
                    $idBtn.prop('disabled', false);
                } else {
                    alert((r && r.data && r.data.message) || 'Failed.');
                }
            })
            .fail(function () { alert('Network error taking baseline.'); })
            .always(function () { $ibBtn.prop('disabled', false).text('Take baseline'); });
    });
    $idBtn.on('click', function () {
        $idBtn.prop('disabled', true).text('Comparing…');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_integrity_diff', _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    var d = r.data;
                    var html = '<div style="margin-top:14px;display:grid;grid-template-columns:repeat(3,1fr);gap:10px;">' +
                        '<div class="defenso-card" style="padding:12px 14px;margin:0;"><div style="font-size:22px;font-weight:700;">' + d.counts.added + '</div><div style="font-size:11px;color:#737373;">Added</div></div>' +
                        '<div class="defenso-card" style="padding:12px 14px;margin:0;"><div style="font-size:22px;font-weight:700;">' + d.counts.changed + '</div><div style="font-size:11px;color:#737373;">Changed</div></div>' +
                        '<div class="defenso-card" style="padding:12px 14px;margin:0;"><div style="font-size:22px;font-weight:700;">' + d.counts.removed + '</div><div style="font-size:11px;color:#737373;">Removed</div></div>' +
                        '</div>';
                    var top = [].concat(d.added.slice(0, 8).map(function (p) { return { kind:'added', p:p }; }),
                                        d.changed.slice(0, 8).map(function (p) { return { kind:'changed', p:p }; }),
                                        d.removed.slice(0, 8).map(function (p) { return { kind:'removed', p:p }; }));
                    if (top.length) {
                        html += '<ul style="margin-top:12px;font-family:JetBrains Mono,monospace;font-size:11.5px;">' +
                            top.map(function (row) {
                                var col = row.kind === 'added' ? '#166534' : (row.kind === 'changed' ? '#92400E' : '#991B1B');
                                return '<li style="padding:2px 0;color:' + col + ';">[' + row.kind + '] ' + escapeHtml(row.p) + '</li>';
                            }).join('') + '</ul>';
                    }
                    $ibOut.html(html);
                } else {
                    alert((r && r.data && r.data.message) || 'Compare failed.');
                }
            })
            .fail(function () { alert('Network error running the diff.'); })
            .always(function () { $idBtn.prop('disabled', false).text('Check for changes'); });
    });

    /* ---------- Vulnerability scan ---------- */
    var $vsBtn = $('#defenso-vuln-scan');
    var $vsOut = $('#defenso-vuln-result');
    $vsBtn.on('click', function () {
        $vsBtn.prop('disabled', true).text('Scanning…');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_vuln_scan', _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    var findings = r.data.findings || [];
                    var html = '<p style="margin-top:14px;">Checked ' + r.data.checked + ' packages · <strong>' + r.data.vulnerable + '</strong> vulnerable.</p>';
                    var vuln = findings.filter(function (f) { return f.vulnerabilities && f.vulnerabilities.length; });
                    if (vuln.length) {
                        html += '<table style="width:100%;margin-top:8px;border-collapse:separate;border-spacing:0 6px;">' +
                            '<thead><tr><th style="text-align:left;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#737373;padding:0 10px;">Package</th><th style="text-align:left;font-size:10px;padding:0 10px;">Version</th><th style="text-align:left;font-size:10px;padding:0 10px;">Vulnerabilities</th></tr></thead><tbody>';
                        vuln.forEach(function (f) {
                            html += '<tr>' +
                                '<td style="padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:11.5px;">' + escapeHtml(f.name) + ' <em style="color:#a3a3a3;">(' + escapeHtml(f.kind) + ')</em></td>' +
                                '<td style="padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:11.5px;">' + escapeHtml(f.version) + '</td>' +
                                '<td style="padding:8px 10px;font-size:12px;">' + f.vulnerabilities.map(function (v) { return escapeHtml(v.id); }).join(', ') + '</td>' +
                            '</tr>';
                        });
                        html += '</tbody></table>';
                    }
                    $vsOut.html(html);
                } else {
                    var msg = (r && r.data && r.data.message) || 'Scan failed.';
                    if (r && r.data && r.data.upgrade_url) { msg += ' Upgrade: ' + r.data.upgrade_url; }
                    alert(msg);
                }
            })
            .fail(function () { alert('Network error running the vuln scan.'); })
            .always(function () { $vsBtn.prop('disabled', false).text('Scan now'); });
    });

    /* ---------- Geo-block ---------- */
    $('#defenso-geo-save').on('click', function () {
        var codes = $('#defenso-geo-input').val();
        $('#defenso-geo-status').text('Saving…').css('color', '#525252');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_geo_save', countries: codes, _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    $('#defenso-geo-status').text('Saved · ' + (r.data.blocklist.length ? r.data.blocklist.join(', ') : 'no blocks')).css('color', '#166534');
                } else {
                    var msg = (r && r.data && r.data.message) || 'Failed.';
                    $('#defenso-geo-status').text(msg).css('color', '#991B1B');
                }
            })
            .fail(function () { $('#defenso-geo-status').text('Network error.').css('color', '#991B1B'); });
    });

    // Live plan badge — poll the app every 30s so an upgrade from the
    // Defen.so dashboard reflects here without needing a page reload.
    var $planBadge = $('#defenso-plan-badge');
    if ($planBadge.length) {
        function refreshSiteInfo() {
            $.post(DefensoAdmin.ajax_url, {
                action: 'defenso_site_info',
                _wpnonce: DefensoAdmin.admin_nonce
            }).done(function (r) {
                if (! r || ! r.success || ! r.data) return;
                var d = r.data;
                if (d.plan_label) {
                    $planBadge.text(d.plan_label).removeClass('defenso-pill-warn defenso-pill-ok').addClass('defenso-pill-ok');
                }
                if (typeof d.verified !== 'undefined') {
                    var $v = $('#defenso-verified-chip');
                    if ($v.length) {
                        $v.text(d.verified ? '● Verified' : '◐ Not verified')
                          .toggleClass('defenso-pill-ok', d.verified)
                          .toggleClass('defenso-pill-warn', ! d.verified);
                    }
                }
                if (d.upgrade_url) {
                    $('#defenso-upgrade-link').attr('href', d.upgrade_url);
                }
            });
        }
        refreshSiteInfo();
        setInterval(refreshSiteInfo, 30000);
    }
});
