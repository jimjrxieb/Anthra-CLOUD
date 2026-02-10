<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
if( !in_array( basename( $file ), array( "file1.php", "file2.php", "include.php" ), true ) ) {
	// This isn't the page we want!
	echo "ERROR: File not found!";
	exit;
}

?>
