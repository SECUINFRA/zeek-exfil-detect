##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! the following part contains some telemtery function to monitor the size of the 'aggregation' and 'connections_baseline' datastructure

module EXFIL_DETECTION;

export {
    ## determines the number of days in the baseline. to do this, all days are determined and duplicates removed. 
    ## the result is the number of days of the longest baseline.
    global get_days_within_baseline: function() : count;

    ## determines the number of connections within the entire baseline. 
    ## for this purpose, all connections of all host/port combinations and days are counted.
    global get_connections_within_baseline: function() : count;

}

event zeek_init()
    {
    do_profiling();
    }

global connections_baseline_table_hosts = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="connections_baseline_table_hosts",
    $unit="count",
    $help_text="Number of host/ports combinations in EXFIL_DETECTION::connections_baseline"
]);
global connections_baseline_table_hosts_gauge = Telemetry::gauge_with(connections_baseline_table_hosts);

global connections_baseline_table_days = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="connections_baseline_table_days",
    $unit="count",
    $help_text="Number of unique days in EXFIL_DETECTION::connections_baseline"
]);
global connections_baseline_table_days_gauge = Telemetry::gauge_with(connections_baseline_table_days);

global connections_baseline_table_connections = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="connections_baseline_table_connections",
    $unit="count",
    $help_text="Number of connections in EXFIL_DETECTION::connections_baseline"
]);
global connections_baseline_table_connections_gauge = Telemetry::gauge_with(connections_baseline_table_connections);

global aggregation_table_size = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="aggregation_table",
    $unit="count",
    $help_text="Number of connections in EXFIL_DETECTION::aggregation"
]);
global aggregation_table_size_gauge = Telemetry::gauge_with(aggregation_table_size);

hook Telemetry::sync()
    {
    Telemetry::gauge_set(connections_baseline_table_hosts_gauge, |EXFIL_DETECTION::connections_baseline|);
    Telemetry::gauge_set(connections_baseline_table_days_gauge, get_days_within_baseline());
    Telemetry::gauge_set(connections_baseline_table_connections_gauge, get_connections_within_baseline());
    Telemetry::gauge_set(aggregation_table_size_gauge, |EXFIL_DETECTION::aggregation|);
    }

function get_days_within_baseline() : count
    {
    # get all unique dates from connections_baseline
    local dates: set[time] = set();
    for ( [i, p], days_table in connections_baseline ) 
        {
        local days: set[time] = table_keys(days_table);
        for ( d in days )
            add dates[d];
        }
    return |dates|;
    }

function get_connections_within_baseline() : count
    {
    # get all unique dates from connections_baseline
    local connections: count = 0;
    for ( [i, p], days_table in connections_baseline ) 
        {
        # count connections from all day-vector values
        for ( [j], vectors in days_table )
            connections += |vectors|;
        }
    return connections;
    }

