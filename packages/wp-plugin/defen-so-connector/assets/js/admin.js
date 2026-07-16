/* global jQuery, DefensoAdmin */
jQuery(function ($) {
    'use strict';

    var popup = null;

    $('#defenso-connect').on('click', function (e) {
        e.preventDefault();
        var url = DefensoAdmin.oauth_url
            + '?wp_url=' + encodeURIComponent(DefensoAdmin.site_url)
            + '&nonce=' + encodeURIComponent(DefensoAdmin.oauth_nonce);
        var w = 560, h = 720;
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
});
