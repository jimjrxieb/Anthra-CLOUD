<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		if ( filter_var( $target, FILTER_VALIDATE_IP ) || preg_match( '/^[a-zA-Z0-9.-]+$/', $target ) ) {
			$cmd = @fsockopen( $target, 80, $errno, $errstr, 2 ) ? 'Host is reachable' : 'Host is unreachable';
		} else {
			$cmd = 'Invalid target';
		}
	}
	else {
		// *nix
		$descriptorspec = array(
			0 => array('pipe', 'r'),
			1 => array('pipe', 'w'),
			2 => array('pipe', 'w')
		);
		$process = proc_open('ping', $descriptorspec, $pipes, null, array('-c', '4', escapeshellarg($target)));
		if (is_resource($process)) {
			$cmd = stream_get_contents($pipes[1]);
			fclose($pipes[0]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		} else {
			$cmd = '';
		}
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
