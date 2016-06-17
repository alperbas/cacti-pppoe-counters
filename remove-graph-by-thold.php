<?php

/*
It delets graphs for pppoe users which did not generate traffic for a period of time

*/

include(dirname(__FILE__)."/../../include/global.php");
include_once($config["base_path"]."/lib/api_automation_tools.php");
include_once($config["base_path"]."/lib/api_data_source.php");
include_once($config["base_path"]."/lib/api_graph.php");

// 1 month = 8640
$tholdcount='8640';


//graphs with 0 value for more tholdcount
$abovethold = db_fetch_assoc("SELECT * FROM thold_data
                            WHERE template = (SELECT DISTINCT(id) FROM thold_template WHERE data_template_name='PPPoE Interface - Traffic')
                            AND thold_enabled = 'on'
                            AND thold_fail_count > $tholdcount;");

foreach ($abovethold as $thold) {
    $gid = $thold['graph_id'];
    $ids = db_fetch_row("SELECT  DISTINCT(GTG.local_graph_id), DTD.local_data_id, DID.value, DTD.data_source_path
                        FROM (data_template_data DTD, data_template_rrd DTR, graph_templates_item GTI, graph_templates_graph GTG, data_input_data DID)
                        WHERE GTI.task_item_id=DTR.id
                        AND DTR.local_data_id=DTD.local_data_id
                        AND GTG.local_graph_id=GTI.local_graph_id
                        AND DTD.id=DID.data_template_data_id
                        AND DID.data_input_field_id=(SELECT DISTINCT(id) FROM cacti.data_input_fields WHERE data_name = 'PPPoE_UserName' order by id desc limit 1)
                        AND DTD.data_template_id=(SELECT DISTINCT(id) FROM cacti.data_template WHERE name = 'PPPoE Interface - Traffic')
                        AND GTI.local_graph_id>0
                        AND GTG.local_graph_id = $gid
                        ORDER by GTG.local_graph_id asc;");

    $username = $ids['value'];
    @list(,$rrd) = @explode("/", $ids['data_source_path']);
    $did = $ids['local_data_id'];

    echo "Removing $did $gid for $username, archiving $rrd\n";
    /* Do the actual removes */
    api_data_source_remove($did);
    api_graph_remove($gid);
    //move rrd to archive
    db_execute("INSERT INTO plugin_rrdclean_action(name, action) VALUES('$rrd', '3')");

    // break after first removal, for test env.
    break;
}

?>
