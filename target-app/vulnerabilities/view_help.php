<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ] = 'Help' . $page[ 'title_separator' ].$page[ 'title' ];

if (array_key_exists ("id", $_GET) &&
	array_key_exists ("security", $_GET) &&
	array_key_exists ("locale", $_GET)) {
	$id       = $_GET[ 'id' ];
	$security = $_GET[ 'security' ];
	$locale = $_GET[ 'locale' ];

	ob_start();
	if ($locale == 'en') {
		$help_file = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php";
		$allowed_dir = realpath(DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities");
		$filename = basename($help_file);
		$help_file = $allowed_dir . DIRECTORY_SEPARATOR . $filename;
		$real_path = realpath($help_file);
		if ($real_path && file_exists($real_path) && strpos($real_path, $allowed_dir) === 0) {
			include $help_file;
		}
	} else {
		$help_file = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php";
		$allowed_files = array('csrf', 'file-inclusion', 'file-upload', 'insecure-captcha', 'insecure-deserialization', 'os-command-injection', 'sql-injection', 'sql-injection-blind', 'weak-session-ids', 'weak-authentication', 'xss-dom', 'xss-reflected', 'xss-stored');
		$help_filename = basename($help_file);
		$help_filename_clean = str_replace('.php', '', $help_filename);
		
		$safe_filename = basename($help_filename_clean);
		if (in_array($safe_filename, $allowed_files, true)) {
			$help_file = DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/' . $safe_filename;
			if (file_exists($help_file) && strpos(realpath($help_file), realpath(DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/')) === 0) {
			include $help_file;
		}
	}
	$help = ob_get_contents();
	ob_end_clean();
} else {
	$help = "<p>Not Found</p>";
}

$page[ 'body' ] .= "
<script src='/vulnerabilities/help.js'></script>
<link rel='stylesheet' type='text/css' href='/vulnerabilities/help.css' />

<div class=\"body_padded\">
	{$help}
</div>\n";

dvwaHelpHtmlEcho( $page );

?>
