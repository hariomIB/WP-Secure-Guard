/**
 * WP Secure Guard - Admin JavaScript
 *
 * @package WP_Secure_Guard
 */

(function($) {
	'use strict';

	$(document).ready(function() {

		// 1. Add Current IP to Whitelist Textarea
		$('.wpsg-add-ip-btn').on('click', function(e) {
			e.preventDefault();
			var ip = $(this).data('ip');
			var $textarea = $('#wpsg_login_whitelist_ips');
			var currentVal = $textarea.val().trim();

			if (!ip) {
				return;
			}

			if (currentVal.indexOf(ip) !== -1) {
				alert('IP ' + ip + ' is already in the whitelist.');
				return;
			}

			if (currentVal.length > 0) {
				$textarea.val(currentVal + '\n' + ip);
			} else {
				$textarea.val(ip);
			}

			$(this).text('✓ IP Added').addClass('button-disabled').prop('disabled', true);
		});

		// 2. Universal Copy Button
		$(document).on('click', '.wpsg-copy-btn', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var targetSelector = $btn.data('target');
			var text = '';

			if (targetSelector && $(targetSelector).length) {
				text = $(targetSelector).first().text();
			} else if ($btn.closest('.wpsg-snippet-box').find('code').length) {
				text = $btn.closest('.wpsg-snippet-box').find('code').text();
			} else if ($btn.closest('.wpsg-php-ini-banner').find('code').length) {
				text = $btn.closest('.wpsg-php-ini-banner').find('code').text();
			} else if ($btn.parent().find('code').length) {
				text = $btn.parent().find('code').text();
			} else {
				text = $btn.siblings('.wpsg-code-box').text();
			}

			var copiedMsg = (typeof wpsgAdmin !== 'undefined' && wpsgAdmin.copiedMsg) ? wpsgAdmin.copiedMsg : 'Copied to clipboard!';
			copyTextToClipboard(text.trim(), $btn, copiedMsg);
		});

		// 3. Copy System Report to Clipboard
		$('.wpsg-copy-sysinfo-btn').on('click', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var info = $btn.data('info');
			var copiedMsg = (typeof wpsgAdmin !== 'undefined' && wpsgAdmin.copiedMsg) ? wpsgAdmin.copiedMsg : 'Copied to clipboard!';
			copyTextToClipboard(info, $btn, copiedMsg);
		});

		// 4. Toggle PHP Hardening Solution Drawers
		$(document).on('click', '.wpsg-toggle-solution-btn', function(e) {
			e.preventDefault();
			var $btn = $(this);
			var targetId = $btn.data('target');
			var $row = $(targetId);

			if ($row.is(':visible')) {
				$row.hide();
				$btn.find('.wpsg-btn-text').text('How to Fix ▼');
			} else {
				$row.show();
				$btn.find('.wpsg-btn-text').text('Hide Solution ▲');
			}
		});

		/**
		 * Helper to copy text to clipboard with modern navigator.clipboard or fallback.
		 */
		function copyTextToClipboard(text, $button, successMsg) {
			if (navigator.clipboard && window.isSecureContext) {
				navigator.clipboard.writeText(text).then(function() {
					showCopiedState($button, successMsg);
				}).catch(function() {
					fallbackCopy(text, $button, successMsg);
				});
			} else {
				fallbackCopy(text, $button, successMsg);
			}
		}

		function fallbackCopy(text, $button, successMsg) {
			var $temp = $('<textarea>');
			$('body').append($temp);
			$temp.val(text).select();
			try {
				document.execCommand('copy');
				showCopiedState($button, successMsg);
			} catch (err) {
				alert('Failed to copy. Please manually copy the text.');
			}
			$temp.remove();
		}

		function showCopiedState($button, msg) {
			var originalText = $button.html();
			$button.text(msg);
			setTimeout(function() {
				$button.html(originalText);
			}, 2000);
		}

	});

})(jQuery);
