/* global jQuery, DefensoAdmin */
jQuery(function ($) {
    'use strict';

    /* ---- Nice modals instead of the browser's blocking alert()/confirm() ---- */
    function defToast(msg, isErr) {
        var $t = $('<div class="defenso-toast' + (isErr ? ' err' : '') + '"></div>').text(msg);
        $('body').append($t);
        // force reflow then animate in
        $t[0].offsetHeight;
        $t.addClass('show');
        setTimeout(function () { $t.removeClass('show'); setTimeout(function () { $t.remove(); }, 250); }, 3200);
    }
    // Promise-based confirm dialog (centered card, no blocking).
    function defConfirm(opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var $ov = $(
                '<div class="defenso-modal-ov">' +
                  '<div class="defenso-modal" role="dialog" aria-modal="true">' +
                    '<h3></h3><p></p>' +
                    '<div class="defenso-modal-actions">' +
                      '<button type="button" class="button defenso-modal-cancel"></button>' +
                      '<button type="button" class="button button-primary defenso-modal-ok' + (opts.danger ? ' defenso-danger' : '') + '"></button>' +
                    '</div>' +
                  '</div>' +
                '</div>'
            );
            $ov.find('h3').text(opts.title || 'Please confirm');
            $ov.find('p').text(opts.body || '');
            $ov.find('.defenso-modal-cancel').text(opts.cancel || 'Cancel');
            $ov.find('.defenso-modal-ok').text(opts.ok || 'Confirm');
            function close(v) { $ov.removeClass('show'); setTimeout(function () { $ov.remove(); }, 200); resolve(v); }
            $ov.find('.defenso-modal-cancel').on('click', function () { close(false); });
            $ov.find('.defenso-modal-ok').on('click', function () { close(true); });
            $ov.on('click', function (e) { if (e.target === $ov[0]) close(false); });
            $(document).on('keydown.defmodal', function (e) { if (e.key === 'Escape') { $(document).off('keydown.defmodal'); close(false); } });
            $('body').append($ov);
            $ov[0].offsetHeight;
            $ov.addClass('show');
        });
    }
    // Back-compat shims so the existing call sites read naturally.
    window.__defAlert = function (m) { defToast(m, true); };

    /* ---------- Tabbed admin (remembered across reloads) ----------
     * The active tab is driven by ?page=defenso&tab=… server-side. On a plain
     * reload with no ?tab, we restore the last tab the owner used from
     * localStorage so the page opens where they left off. Clicking a tab swaps
     * panels instantly (no reload) and updates the URL + storage. */
    var DEF_TAB_KEY = 'defenso_admin_tab';
    var $tabs = $('.defenso-tab');
    if ($tabs.length) {
        var validTabs = {};
        $tabs.each(function () { validTabs[$(this).data('tab')] = true; });

        function showTab(tab, push) {
            if (! validTabs[tab]) { tab = 'overview'; }
            $('.defenso-tab').removeClass('nav-tab-active').filter('[data-tab="' + tab + '"]').addClass('nav-tab-active');
            $('.defenso-panel').hide().filter('[data-panel="' + tab + '"]').show();
            try { localStorage.setItem(DEF_TAB_KEY, tab); } catch (e) { /* private mode */ }
            if (push && window.history && window.history.replaceState) {
                var u = new URL(window.location.href);
                u.searchParams.set('tab', tab);
                window.history.replaceState({}, '', u.toString());
            }
        }

        $tabs.on('click', function (e) {
            e.preventDefault();
            showTab($(this).data('tab'), true);
        });

        // No ?tab in the URL → restore the last-used tab from storage.
        var params = new URLSearchParams(window.location.search);
        if (! params.get('tab')) {
            var stored;
            try { stored = localStorage.getItem(DEF_TAB_KEY); } catch (e) { stored = null; }
            if (stored && validTabs[stored] && stored !== 'overview') {
                showTab(stored, true);
            }
        }
    }

    var popup = null;

    $('#defenso-connect, .defenso-connect-alt').on('click', function (e) {
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
            defToast('Popup blocked. Allow popups for this site and try again.', true);
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
            manage_url: event.data.site_url || '',
            _wpnonce: DefensoAdmin.oauth_nonce
        }).done(function (r) {
            if (r && r.success) {
                window.location = r.data.redirect;
            } else {
                defToast((r && r.data && r.data.message) || 'Could not save the key. Try again.', true);
            }
        }).fail(function () {
            defToast('Network error saving the key. Try again.', true);
        });
    }, false);

    $('#defenso-disconnect').on('click', function (e) {
        e.preventDefault();
        defConfirm({
            title: 'Disconnect Defen.so?',
            body: 'This unlinks Defen.so from this site. Your dashboard data is kept — you can reconnect any time.',
            ok: 'Disconnect', cancel: 'Keep connected', danger: true
        }).then(function (ok) {
            if (! ok) return;
            $.post(DefensoAdmin.ajax_url, {
                action: 'defenso_disconnect',
                _wpnonce: DefensoAdmin.admin_nonce
            }).done(function () { window.location.reload(); });
        });
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
                '<td style="padding:8px 10px;font-family:Consolas, Monaco, monospace;font-size:11.5px;color:#0a0a0a;">' + escapeHtml(f.file) + '</td>' +
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
                    defToast(msg, true);
                    $mwBtn.text('Scan now');
                }
            })
            .fail(function () { defToast('Network error running the scan.', true); $mwBtn.text('Scan now'); })
            .always(function () { $mwBtn.prop('disabled', false); });
    });

    /* ---------- File integrity ---------- */
    var $ibBtn = $('#defenso-integrity-baseline');
    var $idBtn = $('#defenso-integrity-diff');
    var $ibOut = $('#defenso-integrity-result');
    $ibBtn.on('click', function () {
        defConfirm({
            title: 'Take a fresh integrity baseline?',
            body: 'This hashes every PHP / JS / .htaccess file and overwrites the current baseline. Do this right after a clean install or update.',
            ok: 'Take baseline', cancel: 'Cancel'
        }).then(function (ok) {
            if (! ok) return;
            $ibBtn.prop('disabled', true).text('Hashing…');
            $.post(DefensoAdmin.ajax_url, { action: 'defenso_integrity_baseline', _wpnonce: DefensoAdmin.admin_nonce })
                .done(function (r) {
                    if (r && r.success) {
                        $ibOut.html('<p style="margin-top:14px;color:#166534;">Baseline stored · ' + r.data.files + ' files hashed.</p>');
                        $idBtn.prop('disabled', false);
                    } else {
                        defToast((r && r.data && r.data.message) || 'Failed.', true);
                    }
                })
                .fail(function () { defToast('Network error taking baseline.', true); })
                .always(function () { $ibBtn.prop('disabled', false).text('Take baseline'); });
        });
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
                        html += '<ul style="margin-top:12px;font-family:Consolas, Monaco, monospace;font-size:11.5px;">' +
                            top.map(function (row) {
                                var col = row.kind === 'added' ? '#166534' : (row.kind === 'changed' ? '#92400E' : '#991B1B');
                                return '<li style="padding:2px 0;color:' + col + ';">[' + row.kind + '] ' + escapeHtml(row.p) + '</li>';
                            }).join('') + '</ul>';
                    }
                    $ibOut.html(html);
                } else {
                    defToast((r && r.data && r.data.message) || 'Compare failed.', true);
                }
            })
            .fail(function () { defToast('Network error running the diff.', true); })
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
                                '<td style="padding:8px 10px;font-family:Consolas, Monaco, monospace;font-size:11.5px;">' + escapeHtml(f.name) + ' <em style="color:#a3a3a3;">(' + escapeHtml(f.kind) + ')</em></td>' +
                                '<td style="padding:8px 10px;font-family:Consolas, Monaco, monospace;font-size:11.5px;">' + escapeHtml(f.version) + '</td>' +
                                '<td style="padding:8px 10px;font-size:12px;">' + f.vulnerabilities.map(function (v) { return escapeHtml(v.id); }).join(', ') + '</td>' +
                            '</tr>';
                        });
                        html += '</tbody></table>';
                    }
                    $vsOut.html(html);
                } else {
                    var msg = (r && r.data && r.data.message) || 'Scan failed.';
                    if (r && r.data && r.data.upgrade_url) { msg += ' Upgrade: ' + r.data.upgrade_url; }
                    defToast(msg, true);
                }
            })
            .fail(function () { defToast('Network error running the vuln scan.', true); })
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

    /* ---------- Login hardening ---------- */
    $('#defenso-login-save').on('click', function () {
        $('#defenso-login-status').text('Saving…').css('color', '#525252');
        $.post(DefensoAdmin.ajax_url, {
            action: 'defenso_login_settings',
            max: $('#defenso-login-max').val(),
            window: $('#defenso-login-window').val(),
            recaptcha_site_key: $('#defenso-recaptcha-site').val(),
            recaptcha_secret_key: $('#defenso-recaptcha-secret').val(),
            _wpnonce: DefensoAdmin.admin_nonce
        }).done(function (r) {
            if (r && r.success) {
                $('#defenso-login-status').text('Saved · ' + r.data.max + ' attempts / ' + r.data.window + 's' + (r.data.recaptcha_enabled ? ' · reCAPTCHA on' : '')).css('color', '#166534');
            } else {
                $('#defenso-login-status').text((r && r.data && r.data.message) || 'Save failed.').css('color', '#991B1B');
            }
        }).fail(function () {
            $('#defenso-login-status').text('Network error.').css('color', '#991B1B');
        });
    });

    /* ---------- Firewall & hardening ---------- */
    $('#defenso-hardening-save').on('click', function () {
        var $status = $('#defenso-hardening-status');
        $status.text('Saving…').css('color', '#525252');
        var payload = { action: 'defenso_hardening_save', _wpnonce: DefensoAdmin.admin_nonce };
        $('.defenso-harden-cb').each(function () {
            payload[$(this).data('key')] = this.checked ? '1' : '0';
        });
        $.post(DefensoAdmin.ajax_url, payload)
            .done(function (r) {
                if (r && r.success) {
                    $status.text('Saved.').css('color', '#166534');
                } else {
                    $status.text((r && r.data && r.data.message) || 'Save failed.').css('color', '#991B1B');
                }
            })
            .fail(function () { $status.text('Network error.').css('color', '#991B1B'); });
    });

    /* ---------- Core checksum ---------- */
    var $ccBtn = $('#defenso-core-checksum');
    var $ccOut = $('#defenso-core-result');
    $ccBtn.on('click', function () {
        $ccBtn.prop('disabled', true).text('Verifying…');
        $ccOut.html('<p style="margin-top:14px;color:#525252;">Fetching official WordPress.org checksums and hashing core files…</p>');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_core_checksum', _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    var d = r.data;
                    if (d.counts.modified === 0 && d.counts.missing === 0) {
                        $ccOut.html('<p style="margin-top:14px;color:#166534;">All ' + d.checked + ' core files match the official ' + escapeHtml(d.version) + ' checksums.</p>');
                        return;
                    }
                    var html = '<p style="margin-top:14px;color:#991B1B;"><strong>' + d.counts.modified + '</strong> modified, <strong>' + d.counts.missing + '</strong> missing core files (WP ' + escapeHtml(d.version) + ').</p>';
                    var rows = [].concat(
                        d.modified.slice(0, 20).map(function (p) { return { k: 'modified', p: p }; }),
                        d.missing.slice(0, 20).map(function (p) { return { k: 'missing', p: p }; })
                    );
                    html += '<ul style="margin-top:8px;font-family:Consolas, Monaco, monospace;font-size:11.5px;">' +
                        rows.map(function (row) {
                            var col = row.k === 'modified' ? '#92400E' : '#991B1B';
                            return '<li style="padding:2px 0;color:' + col + ';">[' + row.k + '] ' + escapeHtml(row.p) + '</li>';
                        }).join('') + '</ul>';
                    $ccOut.html(html);
                } else {
                    $ccOut.html('<p style="margin-top:14px;color:#991B1B;">' + escapeHtml((r && r.data && r.data.message) || 'Check failed.') + '</p>');
                }
            })
            .fail(function () { $ccOut.html('<p style="margin-top:14px;color:#991B1B;">Network error running the core check.</p>'); })
            .always(function () { $ccBtn.prop('disabled', false).text('Verify core files'); });
    });

    /* ---------- Exposed files ---------- */
    var $efBtn = $('#defenso-exposed-files');
    $efBtn.on('click', function () {
        $efBtn.prop('disabled', true).text('Probing…');
        $ccOut.html('<p style="margin-top:14px;color:#525252;">Probing for publicly-reachable sensitive files…</p>');
        $.post(DefensoAdmin.ajax_url, { action: 'defenso_exposed_files', _wpnonce: DefensoAdmin.admin_nonce })
            .done(function (r) {
                if (r && r.success) {
                    var d = r.data;
                    if (! d.exposed || ! d.exposed.length) {
                        $ccOut.html('<p style="margin-top:14px;color:#166534;">No exposed sensitive files found (' + d.checked + ' paths checked).</p>');
                        return;
                    }
                    var html = '<p style="margin-top:14px;color:#991B1B;"><strong>' + d.exposed.length + '</strong> exposed file(s) — remove or block these now:</p>';
                    html += '<ul style="margin-top:8px;font-family:Consolas, Monaco, monospace;font-size:11.5px;">' +
                        d.exposed.map(function (row) {
                            return '<li style="padding:2px 0;color:#991B1B;">' + escapeHtml(row.file) + ' → ' + escapeHtml(row.url) + '</li>';
                        }).join('') + '</ul>';
                    $ccOut.html(html);
                } else {
                    $ccOut.html('<p style="margin-top:14px;color:#991B1B;">' + escapeHtml((r && r.data && r.data.message) || 'Check failed.') + '</p>');
                }
            })
            .fail(function () { $ccOut.html('<p style="margin-top:14px;color:#991B1B;">Network error running the exposure check.</p>'); })
            .always(function () { $efBtn.prop('disabled', false).text('Check exposed files'); });
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
