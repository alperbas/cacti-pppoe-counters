<?php

/* do NOT run this script through a web browser */
if (!isset($_SERVER["argv"][0]) || isset($_SERVER['REQUEST_METHOD'])  || isset($_SERVER['REMOTE_ADDR'])) {
   die("<br><strong>This script is only meant to run at the command line.</strong>");
}

/* We are not talking to the browser */
$no_http_headers = true;
/* display No errors */
//error_reporting(E_ERROR);

// external functions
include_once(dirname(__FILE__) . "/../../include/global.php");
include_once(dirname(__FILE__) . "/../../lib/snmp.php");

if (!isset($called_by_script_server)) {
   array_shift($_SERVER["argv"]);
   print call_user_func_array("ss_pppoetraffic", $_SERVER["argv"]);
}


//vars
$debug=0;
$loglevel=0; // to be implemented
//--------------
$statustimeout=10;

/* Cacti sql functions
db_execute - run an sql query and do not return any output
db_fetch_cell - run a 'select' sql query and return the first column of the first row found
db_fetch_row - run a 'select' sql query and return the first row found
db_fetch_assoc - run a 'select' sql query and return all rows found
*/

function ss_pppoetraffic_DBCON ($query) {
    global $debug;
    global $database_username;
    global $database_password;
    global $database_hostname;
    global $database_default;
    if(is_file(dirname(__FILE__) . "/pppoetraffic_vars.php"))
        include dirname(__FILE__) . "/pppoetraffic_vars.php";
    // Connect and execute query to DB
    $connection = new mysqli($database_hostname, $database_username, $database_password, $database_default);
    if (!$debug == 1) {
        $result = $connection->query($query);
        if (!$result) {
            echo "Error executing query: (".$mysqli->errno.") ".$mysqli->error."\n";
        } else {
            return $result;
        }
    } else {
        return $connection->query($query);
    }
}

function ss_pppoetraffic_DBCREATETABLE ($table) {
    global $config;
    // Create table
    db_execute("CREATE TABLE `plugin_pppoe_$table` ( username varchar(255), oid varchar(255), date varchar(255), UNIQUE (username) );");
    db_execute("CREATE TABLE IF NOT EXISTS `plugin_pppoe_bulk_check` (lns varchar(255), status int(32), date varchar(255), UNIQUE (lns) );");
    db_execute("INSERT INTO plugin_pppoe_bulk_check (lns, status) VALUES ('$table', '1') ON DUPLICATE KEY UPDATE status=VALUES(status)");
}

function ss_pppoetraffic_CHECKUSER ($lns, $user) {
    // check if user exists in db
    global $config;
    //$result['username'] = db_fetch_cell("SELECT DISTINCT(username) FROM `plugin_pppoe_$lns` WHERE username = '$user' ORDER BY date;");
    $result = db_fetch_row("SELECT DISTINCT(username) FROM `plugin_pppoe_$lns` WHERE username = '$user' ORDER BY date;");
    if ($result['username'] == $user) {
        return 1;
    } else {
        return 0;
    }
}

function ss_pppoetraffic_CHECKTABLE ($lns) {
    global $config;
    global $debug;
    global $statustimeout;
    // Check if table is ready for update
    $tableready = db_fetch_row("SELECT DISTINCT(status), date FROM plugin_pppoe_bulk_check WHERE lns = '$lns';");
    $checkseconds = ss_pppoetraffic_CALCULATEDATEDIFF($tableready['date'], date("Y-m-d H:i:s"));
    if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Status table ready? Table is ".$tableready['status']." for ".$checkseconds." seconds.\n"); }
    if ($tableready['status'] == 0 && $checkseconds > $statustimeout) {
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Update status timeout expired, resetting status to 1 for $lns.\n"); }
        ss_pppoetraffic_LOGGER('file', "Update status timeout expired, resetting status to 1 for $lns.");
        db_execute("UPDATE plugin_pppoe_bulk_check SET status = '1', date = NOW() WHERE lns = '$lns';");
    }
    if ($tableready['status'] == 1) {
        // Ready
        return 1;
    } else {
        return 0;
    }
}

function ss_pppoetraffic_SNMPGETDATA ($command, $snmp, $lns, $ifoid = NULL) {
    global $config;
    //snmpget -v $snmpversion -c $snmpcommunity  $lns $ifoid
    //snmpget -l authPriv -v $snmpversion -u $snmpusername -a $snmpauthproto -A $snmppassword -x $snmpprivacyproto -X $snmppassphrase $lns $ifoid
    global $debug;
    //Path
    $path_snmpget  = '/usr/bin/snmpget';
    $path_snmpbulkwalk = '/usr/bin/snmpbulkwalk';
    //YAPA
    $casnUserId = "1.3.6.1.4.1.9.9.150.1.1.3.1.2";
    $casnIpAddr = "1.3.6.1.4.1.9.9.150.1.1.3.1.3";
    $casnVAIIfIndex = "1.3.6.1.4.1.9.9.150.1.1.3.1.8";
    //VAE
    $cvpdnSessionAttrTable = "1.3.6.1.4.1.9.10.24.1.3.2";
    $cvpdnSessionAttrBytesOut = "1.3.6.1.4.1.9.10.24.1.3.2.1.6";
    $cvpdnSessionAttrBytesIn = "1.3.6.1.4.1.9.10.24.1.3.2.1.8";
    $cvpdnSessionAttrCallDuration = "1.3.6.1.4.1.9.10.24.1.3.2.1.4";
    $cvpdnSessionAttrUserName = "1.3.6.1.4.1.9.10.24.1.3.2.1.2";
    $cvpdnSessionAttrDeviceType = "1.3.6.1.4.1.9.10.24.1.3.2.1.9";
    $cvpdnSessionAttrState = "1.3.6.1.4.1.9.10.24.1.3.2.1.3";
    $cvpdnSessionAttrPacketsOut = "1.3.6.1.4.1.9.10.24.1.3.2.1.5";
    $cvpdnSessionAttrPacketsIn = "1.3.6.1.4.1.9.10.24.1.3.2.1.7";
    $cvpdnSessionAttrDevicePhyId = "1.3.6.1.4.1.9.10.24.1.3.2.1.11";

    //$userlistoid    = '1.3.6.1.4.1.9.10.24.1.3.2.1.2'; //$cvpdnSessionAttrUserName
    //$ifindexoid     = '1.3.6.1.4.1.9.10.24.1.3.2.1.11'; //$cvpdnSessionAttrDevicePhyId
    //$ifcallduration = '1.3.6.1.4.1.9.10.24.1.3.2.1.4'; //$cvpdnSessionAttrCallDuration

    //$userlistoid = $cvpdnSessionAttrUserName;
    //$ifindexoid = $cvpdnSessionAttrDevicePhyId;
    $ifcallduration = $cvpdnSessionAttrCallDuration;

    $userlistoid = $casnUserId;
    $ifindexoid = $casnVAIIfIndex;

    $userlistexplode = ".$userlistoid.";


    switch ($command) {
        case "userlist":
            // Lock bulk requests
            ss_pppoetraffic_LOGGER('file', "Update status set zero for $lns");
            db_execute("UPDATE plugin_pppoe_bulk_check SET status = '0', date = NOW() WHERE lns = '$lns';");
            if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Starting version ".$snmp['version']." SNMP bulk query.\n"); }
            // Get online userlist from lns and insert into db
            if ($snmp['version'] == '2c') {
                $userlist = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qn -c ".$snmp['community']." -v ".$snmp['version']." ".cacti_escapeshellarg($lns)." ".cacti_escapeshellarg($userlistoid));
            } elseif ($snmp['version'] == '3') {
                $userlist = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qn -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".cacti_escapeshellarg($lns)." ".cacti_escapeshellarg($userlistoid));
            }
            // Delete previous userlist.
            db_execute("TRUNCATE TABLE `plugin_pppoe_$lns`;");
            // Fill the table with corporate users.
            foreach($userlist as $line) {
                @list($ifoid, $user) = @explode("=", $line);
                @list(, $ifoid) = @explode($userlistexplode, $ifoid);
                @list(, $user) = @explode("\"", $user);
                @list($user, $realm) = @explode("@", $user);
                if ( $realm == "netoneadsl" || $realm == "netonesdsl" ) {
                    db_execute("INSERT INTO `plugin_pppoe_$lns` (username, oid, date) VALUES ('$user', '$ifoid', NOW() ) ON DUPLICATE KEY UPDATE oid=VALUES(oid), date=VALUES(date);");
                }
            }
            db_execute("UPDATE plugin_pppoe_bulk_check SET status = '1', date = NOW() WHERE lns = '$lns';");
            ss_pppoetraffic_LOGGER('file', "Update status set one for $lns");
            return 1;
        case "sessionduration":
            if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Starting version ".$snmp['version']." SNMP duration query for ".$lns."\n"); }
            // Get ppp session duration and convert to seconds
            if ($snmp['version'] == '2c') {
                $sessionduration = exec_into_array(cacti_escapeshellcmd($path_snmpget)." -O Qv -c ".$snmp['community']." -v ".$snmp['version']." ".cacti_escapeshellarg($lns)." ".$ifcallduration.".".$ifoid);
            } elseif ($snmp['version'] == '3') {
                $sessionduration = exec_into_array(cacti_escapeshellcmd($path_snmpbulkwalk)." -O Qv -l authPriv -v ".$snmp['version']." -u ".$snmp['username']." -a ".$snmp['authproto']." -A ".$snmp['password']." -x ".$snmp['privacyproto']." -X ".$snmp['passphrase']." ".cacti_escapeshellarg($lns)." ".$ifcallduration.".".$ifoid);
            }
            if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Session duration: ".$sessionduration[0]."\n"); }
            if  ($sessionduration[0] == "No Such Instance currently exists at this OID") {
                return 0;
            } else {
                @list($days, $hours, $minutes, $seconds) = @explode(":", $sessionduration[0]);
                return ss_pppoetraffic_CONVERTTOSECONDS(0, $days, $hours, $minutes, $seconds);
            }
        case "counters":
            if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Starting version ".$snmp['version']." SNMP interface query for ".$lns."\n"); }
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

function ss_pppoetraffic_CONVERTTOSECONDS ($months, $days, $hours, $minutes, $seconds) {
    return ($months * 2592000) + ($days * 86400) + ($hours * 3600) + ($minutes * 60) + ($seconds);
}

function ss_pppoetraffic_CALCULATEDATEDIFF ($olddate, $newdate) {
    $date1 = new DateTime($olddate);
    $date2 = new DateTime($newdate);
    $interval = $date1->diff($date2);
    return ss_pppoetraffic_CONVERTTOSECONDS($interval->m, $interval->d, $interval->h, $interval->i, $interval->s);
}

function ss_pppoetraffic_LOGGER ($type, $log) {
    if ($type == 'file') {
        $log = date("Y-m-d H:i:s")." ".$log;
        $myfile = file_put_contents('/var/www/html/log/pppoe.log', $log.PHP_EOL, FILE_APPEND);
    } elseif ($type == 'echo') {
        echo $log;
    }
}

function ss_pppoetraffic_GETOLDCOUNTERS($username) {
    global $config;
    global $debug;

    $path_rrdtool = "/usr/bin/rrdtool";

    $rrdcell = db_fetch_cell("SELECT data_source_path FROM data_template_data WHERE name like '%- $username';");
    if (!is_null($rrdcell)) {
        @list( , $rrd) = @explode("/", $rrdcell);
        $rrd = $config["rra_path"]."/".$rrd;
        $oldcounters = exec_into_array(cacti_escapeshellcmd($path_rrdtool)." lastupdate ".cacti_escapeshellarg($rrd));
        @list($time, $counters['in'], $counters['out']) = @explode(" ", $oldcounters[2]);
    }

    ss_pppoetraffic_LOGGER('file', "Get old counters for $username, in ".$counters['in']." out ".$counters['out']." rrd is $rrd");
    return $counters;
}

function ss_pppoetraffic_CHECKTABLEAGE($lns, $interval) {
    global $debug;
    $updatediff = db_fetch_cell("SELECT IFNULL((SELECT date FROM `plugin_pppoe_bulk_check` WHERE (date > NOW() - INTERVAL $interval MINUTE) AND lns='$lns' limit 1) , 0) AS datediff");
    if ($updatediff == 0) {
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Table is older than $interval minute for $lns.\n"); }
        return 1;
    } else {
        return 0;
    }
}

function ss_pppoetraffic ($hostname, $snmpversion, $username) {
    global $config;
    global $debug;

    // check if device exists
    if (is_null(db_fetch_cell("SELECT hostname FROM host WHERE hostname = '$hostname'")) {
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Host $lns does not exists."); }
        ss_pppoetraffic_LOGGER('file', "Host $lns does not exists.");
        exit(1);
    }

    // get variables
    if ($snmpversion == '2') {
        $snmp['version'] = '2c';
        $snmp['community'] = db_fetch_cell("SELECT snmp_community FROM host WHERE hostname = '$hostname'", FALSE);
    } elseif ($snmpversion == '3') {
        $snmp['version'] = '3';
        $snmp['username'] = db_fetch_cell("SELECT snmp_username FROM host WHERE hostname = '$hostname';");
        $snmp['password'] = db_fetch_cell("SELECT snmp_password FROM host WHERE hostname = '$hostname';");
        $snmp['authproto'] = db_fetch_cell("SELECT snmp_auth_protocol FROM host WHERE hostname = '$hostname';");
        $snmp['privacyproto'] = db_fetch_cell("SELECT snmp_priv_protocol FROM host WHERE hostname = '$hostname';");
        $snmp['passphrase'] = db_fetch_cell("SELECT snmp_priv_passphrase FROM host WHERE hostname = '$hostname';");
    }
    $lns = $hostname;

    if ($debug == 1) {
        if ($snmp['version'] == '2c') {
            ss_pppoetraffic_LOGGER('echo', "Query variables: ".$lns." ".$snmp['version']." ".$username."\nParameters: ".$snmp['community']."\n");
        } elseif ($snmp['version'] == '3') {
            ss_pppoetraffic_LOGGER('echo', "Query variables: ".$lns." ".$snmp['version']." ".$username."\nParameters: ".$snmp['username']." ".$snmp['password']." ".$snmp['authproto']." ".$snmp['privacyproto']." ".$snmp['passphrase']."\n");
        }
    }

    // check if lns table exists, create if not.
    if (ss_pppoetraffic_DBCON("SELECT 1 FROM `plugin_pppoe_$lns` LIMIT 1") == FALSE) { ss_pppoetraffic_DBCREATETABLE($lns); }

    // Sleep if table is being updated.
    usleep(rand(200,1000));
    while (!ss_pppoetraffic_CHECKTABLE($lns)) {
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Table is updating, wait 1 second.\n"); }
        sleep(1);
    }

    // Update table if its older than 4 minutes
    if (ss_pppoetraffic_CHECKTABLEAGE($lns, 4)) {
        ss_pppoetraffic_LOGGER('file', "Bulk Request on $lns, table is older than 4 minutes - for $username");
        ss_pppoetraffic_SNMPGETDATA("userlist", $snmp, $lns);
    }

    // Check if username exists
    if (!ss_pppoetraffic_CHECKUSER($lns, $username)) {
        // username is not connected
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "User not found, exit.\n"); }
        ss_pppoetraffic_LOGGER('file', "User is missing on table $lns for $username - exit.");
        return "in_traffic:0 out_traffic:0";
        exit(1);
    } else {
        // Get oid for username
        $ifoid = db_fetch_row("SELECT oid FROM `plugin_pppoe_$lns` WHERE username = '$username' ORDER BY date");
    }

    // if oid select fails
    if (is_null($ifoid['oid'])) {
        // username is not connected
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "User not found, exit.\n"); }
        ss_pppoetraffic_LOGGER('file', "ifoid is missing on table $lns for $username - exit.");
        return "in_traffic:0 out_traffic:0";
        exit(1);
    }

    /* no more age check
    // Get ppp session up time as seconds YAPA returns 0
    $sessiondurationseconds = ss_pppoetraffic_SNMPGETDATA("sessionduration", $snmp, $lns, $ifoid['oid']);
    if (!is_numeric($sessiondurationseconds)) {
        $sessiondurationseconds = 0;
    }

    // Get table age as seconds
    $tableage = db_fetch_cell("SELECT date FROM `plugin_pppoe_bulk_check` WHERE lns='$lns'");
    // Calculate difference between now and table update time as seconds
    $tableageseconds = ss_pppoetraffic_CALCULATEDATEDIFF($tableage, date("Y-m-d H:i:s"));
    if (!is_numeric($tableageseconds)) {
        $tableageseconds = 0;
    }

    // Check table age, exit if sesion is newer. only works for VAE
    if ($tableageseconds > $sessiondurationseconds && $sessiondurationseconds != 0) {
        if ($debug == 1) { ss_pppoetraffic_LOGGER('echo', "Table age is older than Session age.\n"); }
        ss_pppoetraffic_LOGGER('file', "Session is newer than $lns for $username - table: $tableageseconds, session: $sessiondurationseconds - exit");
        return "in_traffic:0 out_traffic:0";
        exit(1);
    }
    */

    // Get interface counters.
    $counters = ss_pppoetraffic_SNMPGETDATA("counters", $snmp, $lns, $ifoid['oid']);
    ss_pppoetraffic_LOGGER('file', "Get Request on $lns for $username, if ".$ifoid['oid'].", age $sessiondurationseconds, in ".$counters['in']." out ".$counters['out']);
    $oldcounters = ss_pppoetraffic_GETOLDCOUNTERS($username);
    if ( $counters['in'] == '0' && $counters['out'] == '0' ) {
        ss_pppoetraffic_LOGGER('file', "Zero counters for $username");
        $counters = $oldcounters;
    }
    /* gecici kapadim. session age 5dk'dan fazla ise true olsun ?
    if ( $counters['in'] != '0' && $oldcounters['in'] > '1' && ($counters['in'] / $oldcounters['in']) > 100 && $sessiondurationseconds > 300 ) {
        ss_pppoetraffic_LOGGER('file', "Inbound peak for $username, old counter ".$oldcounters['in']." new counter ".$counters['in']);
        $counters['in'] = $oldcounters['in'];
    }
    if ( $counters['out'] != '0' && $oldcounters['out'] > '1' && ($counters['out'] / $oldcounters['out']) > 100 && $sessiondurationseconds > 300 ) {
        ss_pppoetraffic_LOGGER('file', "Outbound peak for $username, old counter ".$oldcounters['out']." new counter ".$counters['out']);
        $counters['out'] = $oldcounters['out'];
    }
    */

    return "in_traffic:".$counters['out']." out_traffic:".$counters['in'];
    exit(0);

}

?>
