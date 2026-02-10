<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Set blacklist
	$substitutions = array(
		'&&' => '',
		';'  => '',
	);

	// Remove any of the characters in the array (blacklist).
	$target = str_replace( array_keys( $substitutions ), $substitutions, $target );

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$descriptorspec = array(
			0 => array('pipe', 'r'),
			1 => array('pipe', 'w'),
			2 => array('pipe', 'w')
		);
		$process = proc_open('ping', $descriptorspec, $pipes, null, array(escapeshellarg($target)));
		if (is_resource($process)) {
			$cmd = stream_get_contents($pipes[1]);
			proc_close($process);
		} else {
			$cmd = '';
		}
	}
	else {
		// *nix
		// Validate target is a valid IP address or hostname
		if ( !preg_match( '/^[a-zA-Z0-9.-]+$/', $target ) || strlen( $target ) > 255 ) {
			$cmd = 'Invalid target';
		} else {
			$descriptorspec = array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' )
			);
			if ( !filter_var( $target, FILTER_VALIDATE_IP ) ) {
				echo 'Error: Invalid IP address format';
				return;
			}
			$process = proc_open( 'ping', $descriptorspec, $pipes, null, array( '-c', '4', escapeshellarg( $target ) ) );
			if ( is_resource( $process ) ) {
				$cmd = stream_get_contents( $pipes[1] );
				fclose( $pipes[1] );
				fclose( $pipes[2] );
				proc_close( $process );
			} else {
				$cmd = '';
			}
		}
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
