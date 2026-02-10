<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = trim($_REQUEST[ 'ip' ]);

	// Set blacklist
	$substitutions = array(
		'||' => '',
		'&'  => '',
		';'  => '',
		'| ' => '',
		'-'  => '',
		'$'  => '',
		'('  => '',
		')'  => '',
		'`'  => '',
	);

	// Remove any of the characters in the array (blacklist).
	$target = str_replace( array_keys( $substitutions ), $substitutions, $target );

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		// Validate target is a valid IP or hostname format
		if ( ! preg_match( '/^[a-zA-Z0-9.-]+$/', $target ) ) {
			$cmd = 'Invalid target format';
		} else {
			// Use proc_open with argument array to prevent shell injection
			$descriptorspec = array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' )
			);
			if ( !filter_var( $target, FILTER_VALIDATE_IP ) ) {
				echo 'Invalid IP address';
				return;
			}
			$process = proc_open( 'ping', $descriptorspec, $pipes, null, array( '-c', '4', escapeshellarg( $target ) ) );
			if ( is_resource( $process ) ) {
				$cmd = stream_get_contents( $pipes[1] );
				proc_close( $process );
			} else {
				$cmd = 'Ping command failed';
			}
		}
	}
	else {
		// *nix
		$descriptorspec = array(
			0 => array( 'pipe', 'r' ),
			1 => array( 'pipe', 'w' ),
			2 => array( 'pipe', 'w' )
		);
		if ( !filter_var( $target, FILTER_VALIDATE_IP ) ) {
			echo 'Error: Invalid IP address';
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

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
