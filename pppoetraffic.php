#!/usr/bin/php -q
<?php

/* do NOT run this script through a web browser */
if (!isset($_SERVER["argv"][0]) || isset($_SERVER['REQUEST_METHOD'])  || isset($_SERVER['REMOTE_ADDR'])) {
   die("<br><strong>This script is only meant to run at the command line.</strong>");
}

/* We are not talking to the browser */
$no_http_headers = true;

// external functions
include_once(dirname(__FILE__)."/../include/global.php");
include_once(dirname(__FILE__) . "/../lib/snmp.php");

//vars
$debug=0;
$loglevel=0; // to be implemented
//--------------
$statustimeout=10;
//$userlistoid    = '1.3.6.1.4.1.9.10.24.1.3.2.1.2.2';
//$ifindexoid     = '1.3.6.1.4.1.9.10.24.1.3.2.1.11';
//$ifcallduration = '1.3.6.1.4.1.9.10.24.1.3.2.1.4';
//$path_snmpbulkwalk = '/usr/bin/snmpbulkwalk';
//$path_snmpget  = '/usr/bin/snmpget';

function DBCON ($sql) {
    // Connect and execute query to DB
    $dbservername = "localhost";
    $dbusername = "grapher";
    $dbpassword = "de6lw36";
    $dbname = "graph_lns";
    $connection = new mysqli($dbservername, $dbusername, $dbpassword, $dbname);
    return $connection->query($sql);
}

function DBCREATETABLE ($table) {
    // Create table
    DBCON("CREATE TABLE `$table` ( username varchar(255), oid varchar(255), date varchar(255), uptime varchar(255) );");
    DBCON("INSERT INTO bulk_check (lns, status) VALUES ('$table', '1')");
}

function CHECKUSER ($lns, $user) {
    // check if user exists in db
    $result = mysqli_fetch_assoc(DBCON("SELECT DISTINCT(username) FROM `$lns` WHERE username = '$user' ORDER BY date;"));
    if ($result['username'] == $user) {
        return 1;
    } else {
         return 0;
    }
}

function CHECKTABLE ($lns) {
    global $debug;
    global $statustimeout;
    // Check if table is ready for update
    $tableready = mysqli_fetch_assoc(DBCON("SELECT DISTINCT(status), date FROM bulk_check WHERE lns = '$lns';"));
    $checkseconds = CALCULATEDATEDIFF($tableready['date'], date("Y-m-d H:i:s"));
    if ($debug == 1) {
        LOGGER('echo', "Status table ready? Table is ".$tableready['status']." for ".$checkseconds." seconds.\n");
    }
    if ($tableready['status'] == 0 && $checkseconds > $statustimeout) {
        if ($debug == 1) {
            LOGGER('echo', "Update status timeout expired, resetting status to 1 for $lns.\n");
        }
        LOGGER('file', "Update status timeout expired, resetting status to 1 for $lns.");
        DBCON("UPDATE bulk_check SET status = '1', date = NOW() WHERE lns = '$lns';");
    }
    if ($tableready['status'] == 1) {
        // Ready
        return 1;
    } else {
        return 0;
    }
}

function SNMPGETDATA ($command, $snmp, $lns, $ifoid) { //
    //snmpget -v $snmpversion -c $snmpcommunity  $lns $ifoid
    //snmpget -l authPriv -v $snmpversion -u $snmpusername -a $snmpauthproto -A $snmppassword -x $snmpprivacyproto -X $snmppassphrase $lns $ifoid
    global $debug;
    $userlistoid    = '1.3.6.1.4.1.9.10.24.1.3.2.1.2.2';
    $ifindexoid     = '1.3.6.1.4.1.9.10.24.1.3.2.1.11';
    $ifcallduration = '1.3.6.1.4.1.9.10.24.1.3.2.1.4';
    $path_snmpget  = '/usr/bin/snmpget';
    $path_snmpbulkwalk = '/usr/bin/snmpbulkwalk';

    switch ($command) {
        case "userlist":
            // Lock bulk requests
            LOGGER('file', "Update status set zero for $lns");
            DBCON("UPDATE bulk_check SET status = '0', date = NOW() WHERE lns = '$lns';");
            if ($debug == 1) {
                LOGGER('echo', "Starting version ".$snmp['version']." SNMP bulk query.\n");
            }
            // Get online userlist from lns and insert into db
            if ($snmp['version'] == '2c') {
                $userlist = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qn -c ".$snmp['community']." -v ".$snmp['version']." ".cacti_escapeshellarg($lns)." ".cacti_escapeshellarg($userlistoid));
            } elseif ($snmp['version'] == '3') {
                $userlist = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qn -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".cacti_escapeshellarg($lns)." ".cacti_escapeshellarg($userlistoid));
            }
            // Delete previous userlist.
            DBCON("TRUNCATE TABLE `$lns`;");
            // Fill the table with corporate users.
            foreach($userlist as $line) {
                @list($ifoid, $user) = @explode("=", $line);
                @list(, $ifoid) = @explode(".1.3.6.1.4.1.9.10.24.1.3.2.1.2.", $ifoid);
                @list(, $user) = @explode("\"", $user);
                @list($user, $realm) = @explode("@", $user);
                if ( $realm == "netoneadsl" || $realm == "netonesdsl" ) {
                    DBCON("INSERT INTO `$lns` (username, oid, date, uptime) VALUES ('$user', '$ifoid', NOW(), NULL);");
                }
            }
            DBCON("UPDATE bulk_check SET status = '1', date = NOW() WHERE lns = '$lns';");
            LOGGER('file', "Update status set one for $lns");
            return 1;
        case "sessionduration":
            if ($debug == 1) {
                LOGGER('echo', "Starting version ".$snmp['version']." SNMP duration query.\n");
            }
            // Get ppp session duration and convert to seconds
            if ($snmp['version'] == '2c') {
                $sessionduration = exec_into_array(cacti_escapeshellcmd($path_snmpget)." -O Qv -c ".$snmp['community']." -v ".$snmp['version']." ".cacti_escapeshellarg($lns)." ".$ifcallduration.".".$ifoid);
            } elseif ($snmp['version'] == '3') {
                $sessionduration = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qv -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".cacti_escapeshellarg($lns)." ".$ifcallduration.".".$ifoid);
            }
            if ($debug == 1) {
                LOGGER('echo', "Session duration: ".$sessionduration[0]."\n");
            }
            @list($days, $hours, $minutes, $seconds) = @explode(":", $sessionduration[0]);
            return CONVERTTOSECONDS(0, $days, $hours, $minutes, $seconds);
        case "counters":
            if ($debug == 1) {
                LOGGER('echo', "Starting version ".$snmp['version']." SNMP interface query.\n");
            }
            // Get interface counters.
            if ($snmp['version'] == '2c') {
                $ifindex = exec_into_array(cacti_escapeshellcmd($path_snmpget)." -O Qv -c ".$snmp['community']." -v ".$snmp['version']." ".$lns." ".$ifindexoid.".".$ifoid);
                $inoctets = exec_into_array(cacti_escapeshellcmd($path_snmpget)." -O Qv -c ".$snmp['community']." -v ".$snmp['version']." ".cacti_escapeshellarg($lns)." ifInOctets.".$ifindex[0]);
                $outoctets = exec_into_array(cacti_escapeshellcmd($path_snmpget)." -O Qv -c ".$snmp['community']." -v ".$snmp['version']." ".cacti_escapeshellarg($lns)." ifOutOctets.".$ifindex[0]);
            } elseif ($snmp['version'] == '3') {
                $ifindex = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qv -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".$lns." ".$ifindexoid.".".$ifoid);
                $inoctets = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qv -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".cacti_escapeshellarg($lns)." ifInOctets.".$ifindex[0]);
                $outoctets = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qv -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".cacti_escapeshellarg($lns)." ifOutOctets.".$ifindex[0]);
            }
            if ($debug == 1) {
                echo "ifIndex: ".$ifindex[0]."\n";
                echo "inOctets: ".$inoctets[0]." outOctets: ".$outoctets[0]."\n";
            }
            $octets['in'] = $inoctets[0];
            $octets['out'] = $outoctets[0];
            return $octets;
    }
}

function CONVERTTOSECONDS ($months, $days, $hours, $minutes, $seconds) {
    return ($months * 2592000) + ($days * 86400) + ($hours * 3600) + ($minutes * 60) + ($seconds);
}

function CALCULATEDATEDIFF ($olddate, $newdate) {
    $date1 = new DateTime($olddate);
    $date2 = new DateTime($newdate);
    $interval = $date1->diff($date2);
    return CONVERTTOSECONDS($interval->m, $interval->d, $interval->h, $interval->i, $interval->s);
}

function LOGGER ($type, $log) {
    if ($type == 'file') {
        $log = date("Y-m-d H:i:s")." ".$log;
        $myfile = file_put_contents('/var/www/html/log/ppoe_log.txt', $log.PHP_EOL, FILE_APPEND);
    } elseif ($type == 'echo') {
        echo $log;
    }
}

/* process calling arguments */
$parms = $_SERVER["argv"];
array_shift($parms);

if (sizeof($parms)) {
    /* setup defaults */
    $lns			= ''; //arg
	$snmpcommunity	= ''; //arg
	$snmpversion	= ''; //arg
	$username		= ''; //arg
    // todo
    $snmp['version']    = '';
    $snmp['community']  = '';
    $snmp['username']   = '';
    $snmp['password']   = '';
    $snmp['authproto']  = '';
    $snmp['privacyproto'] = '';
    $snmp['passphrase'] = '';

    foreach($parms as $parameter) {
        @list($arg, $value) = @explode("=", $parameter);
        switch ($arg) {
            case "--sv":
                $snmp['version'] = trim($value);
                if ($snmp['version'] == '2') {
                    $snmp['version'] = '2c';
                }
                break;
            case "--sc":
                $snmp['community'] = trim($value);
                break;
            case "--lns":
                $lns = trim($value);
                break;
            case "--username":
                $username = trim($value);
                break;
            case "--su":
                $snmp['username'] = trim($value);
                break;
            case "--sp":
                $snmp['password'] = trim($value);
                break;
            case "--sap":
                $snmp['authproto'] = trim($value);
                break;
            case "--spp":
                $snmp['privacyproto'] = trim($value);
                break;
            case "--spassphr":
                $snmp['passphrase'] = trim($value);
                break;
            case "--version":
            case "-V":
            case "-H":
            case "--help":
                display_help();
                exit(0);
			default:
				echo "ERROR: Invalid Argument: ($arg)\n\n";
				display_help();
				exit(1);
        }
    }
    if ($debug == 1) {
        if ($snmp['version'] == '2c') {
            LOGGER('echo', "Query variables: ".$lns." ".$snmp['version']." ".$username."\nParameters: ".$snmp['community']."\n");
        } elseif ($snmp['version'] == '3') {
            LOGGER('echo', "Query variables: ".$lns." ".$snmp['version']." ".$username."\nParameters: ".$snmp['username']." ".$snmp['password']." ".$snmp['authproto']." ".$snmp['privacyproto']." ".$snmp['passphrase']."\n");
        }
    }

    // check if lns table exists, create if not.
    if (DBCON("SELECT 1 FROM `$lns` LIMIT 1") == FALSE) { DBCREATETABLE($lns); }

    // Sleep if table is being updated.
    usleep(rand(100,1000));
    while (!CHECKTABLE($lns)) {
        sleep(1);
    }

    // Check if username exists
    if (!CHECKUSER($lns, $username)) {
        if ($debug == 1) {
            LOGGER('echo', "User is not in database, starting snmpbulk request.\n");
        }
        while (!CHECKTABLE($lns)) {
            sleep(1);
        }
        LOGGER('file', "Bulk Request on $lns for $username - user is missing.");
        SNMPGETDATA("userlist", $snmp, $lns, null);
    }

    // Get oid and table update date for username
    $ifoid = mysqli_fetch_assoc(DBCON("SELECT DISTINCT(oid), date FROM `$lns` WHERE username = '$username' ORDER BY date"));
    if (is_null($ifoid['oid'])) {
        // username is not connected
        if ($debug == 1) {
            LOGGER('echo', "User not found, exit.\n");
        }
        echo "in_traffic:0 out_traffic:0\n";
        exit(1);
    }

    // Get ppp session up time as seconds
    $sessiondurationseconds = SNMPGETDATA("sessionduration", $snmp, $lns, $ifoid['oid']);
    if (!is_numeric($sessiondurationseconds)) {
        $sessiondurationseconds = 0;
    }

    // Calculate difference between now and table update time as seconds
    $diffseconds = CALCULATEDATEDIFF($ifoid['date'], date("Y-m-d H:i:s"));
    if (!is_numeric($diffseconds)) {
        $diffseconds = 0;
    }

    // Update table again if difftime is bigger than uptime. it means interface has changed.
    if ($debug == 1) {
        LOGGER('echo', "Table age: ".$diffseconds.", Session age: ".$sessiondurationseconds."\n");
    }
    if ($diffseconds > $sessiondurationseconds) {
        if ($debug == 1) {
            LOGGER('echo', "Table age is older than Session age, starting snmpbulk request.\n");
        }
        while (!CHECKTABLE($lns)) {
            sleep(1);
        }
        LOGGER('file', "Bulk Request on $lns for $username - session is newer.");
        SNMPGETDATA("userlist", $snmp, $lns, null);
        $ifoid = mysqli_fetch_assoc(DBCON("SELECT DISTINCT(oid) FROM `$lns` WHERE username = '$username' ORDER BY date;"));
    }

    // Get interface counters.
    LOGGER('file', "Get Request on $lns for $username");
    $counters = SNMPGETDATA("counters", $snmp, $lns, $ifoid['oid']);
    echo "in_traffic:".$counters['out']." out_traffic:".$counters['in']."\n";

} else {
        display_help();
        exit(0);
}

function display_help() {
        echo "VAE interface counters v 0.52\n";
        echo "Usage for SNMP v2\n";
        echo "pppoetraffic.php --lns=<hostname> --sc=<snmp_community> --sv=<snmp_version> --username=<PPPoE_UserName>\n";
        echo "Usage for SNMP v3\n";
        echo "pppoetraffic.php --lns=<hostname> --sc=<snmp_community> --sv=<snmp_version> --username=<PPPoE_UserName> --su=<snmp_username> --sp=<snmp_password> --sap=<snmp_auth_protocol> --spp=<snmp_priv_protocol> --spassphr=<snmp_priv_passphrase>\n";
}

?>
