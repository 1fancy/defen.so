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
