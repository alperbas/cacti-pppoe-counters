<?php

/*
It creates graphs for pppoe users.
Device must have "pppoe" in its notes section in device settings on cacti.
Graph script collects online users every 5 minutes, so we have a user database.

This script gets the username list from database for each device with "pppoe" note set;
then checks if that username have graph, if not creates one and creates threshold for that graph.

*/

include_once(dirname(__FILE__) . "/../../include/global.php");
include_once(dirname(__FILE__) . "/../../lib/snmp.php");

global $config;
global $debug;

// Device note field must be 'pppoe'
$devices = db_fetch_assoc("SELECT id, hostname FROM `host` WHERE notes = 'pppoe'");
if (is_null($devices) || sizeof($devices) == 0) {
    echo "No available device, check if devices have notes, exit.\n";
    exit(1);
}
$graphtemplateid = db_fetch_cell("SELECT graph_template_id FROM `graph_templates_graph` WHERE title = '<PPPoE Username>' AND local_graph_id = '0'");
if (is_null($graphtemplateid)) {
    echo "Could not locate graph_template_id, exit.\n";
    exit(1);
}

$devicecount = 0;
$graphcount = 0;
foreach($devices as $device) {
    $lns = $device['hostname'];
    $hostid = $device['id'];
    $checktable = db_fetch_cell("SHOW TABLES LIKE 'plugin_pppoe_$lns'");
    echo "Checking $lns...\n";
    if (is_null($checktable)) {
        echo "Table for $lns does not exists, manually create at least one PPPoE Graph, exit.\n";
        continue;
    }
    $usernames = db_fetch_assoc("SELECT username FROM `plugin_pppoe_$lns` ORDER by username");
    $usernamecount = 0;
    foreach($usernames as $username) {
        $username = $username['username'];
        $graphid = db_fetch_cell("SELECT DISTINCT(GTG.local_graph_id) AS Gid, GTG.title, GTG.title_cache, DTD.local_data_id AS Did, DTD.name, DTD.name_cache, DTD.data_source_path, DID.value AS username
                                FROM (data_template_data DTD, data_template_rrd DTR, graph_templates_item GTI, graph_templates_graph GTG, data_input_data DID)
                                WHERE GTI.task_item_id=DTR.id
                                AND DTR.local_data_id=DTD.local_data_id
                                AND GTG.local_graph_id=GTI.local_graph_id
                                AND DTD.id=DID.data_template_data_id
                                AND DID.data_input_field_id=(SELECT DISTINCT(id) FROM cacti.data_input_fields WHERE data_name = 'PPPoE_UserName' order by id desc limit 1)
                                AND DTD.data_template_id=(SELECT DISTINCT(id) FROM cacti.data_template WHERE name = 'PPPoE Interface - Traffic')
                                AND GTI.local_graph_id>0
                                AND DID.value = '$username'");
        if (is_null($graphid)) {
            $output = exec_into_array("php /var/www/html/cli/add_graphs.php --graph-type=cg --graph-template-id=$graphtemplateid --host-id=$hostid --graph-title=\"$username\" --input-fields=\"40:PPPoE_UserName=$username\" --force");
            $output = $output[0];
            @list(,,,,,,,$dataid) = @explode(" ", $output);
            $dataid = preg_replace('/[^A-Za-z0-9\-]/', '', $dataid);
            $name = "|host-description| - $username";
            $name_cache = db_fetch_cell("SELECT name_cache FROM data_template_data WHERE local_data_id = $dataid");
            @list($name_cache,,) = @explode(" ", $name_cache);
            $name_cache = "$name_cache - $username";

            db_execute("UPDATE data_template_data SET name = '$name', name_cache = '$name_cache' WHERE local_data_id = '$dataid';");
            echo "$username graph yok -> $hostid $graphtemplateid $output\n";
            $usernamecount++;
        }
    }
    if ($usernamecount > 0) {
        echo "$usernamecount graphs added for $lns\n";
        $graphcount += $usernamecount;
    }
    $addthold = "php /var/www/html/plugins/thold/cli_thresholds.php -auto=$hostid";
    $tholds = exec_into_array($addthold);
    var_dump($tholds);
}
if ($graphcount > 0) {
    echo "$graphcount graphs added.\n";
} else {
    echo "All usernames have graphs!\n";
}

?>
