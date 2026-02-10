<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated') );

// phpinfo() removed - sensitive information disclosure vulnerability
// Use a secure admin panel with authentication for debugging if needed
echo 'Access denied';

?>
