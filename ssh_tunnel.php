<?php

// register a ssh tunnel to export data and a shutdown handler to clean it up again
register_shutdown_function('cleanSshTunnelHandler');
$proc_sshtun = proc_open("ssh myuser@myserver -T -N -L 5432:localhost:5432", array(), $dummy);

function cleanSshTunnelHandler() {
	global $proc_sshtun;
	
	$status = proc_get_status($proc_sshtun);
	$pid = $status['pid'];

	// kill with child procs, otherwise we might either leave trash or end up hanging forever
	if (strtoupper(substr(php_uname('s'), 0, 3)) === 'WIN') {
		system("TASKKILL /F /T /PID $pid");
	} else {
		posix_kill($pid, SIGKILL);
	}

	proc_terminate($proc_sshtun);
}