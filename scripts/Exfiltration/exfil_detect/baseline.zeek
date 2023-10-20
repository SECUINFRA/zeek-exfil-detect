##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part contains the creation of the baseline as well as the deletion of obsolete elements

module EXFIL_DETECTION;

export {
    ## the baseline is formed from the aggregated connections over the specified time.
    ## the baseline is used to calculate the "normal" values in order to derive the scores of the connections.
    ## .. :zee:see: `aggregation`
    global connections_baseline: table[addr, port] of table[time] of vector of element &write_expire=max_baseline_hold_time;

    ## function that deletes the obsolte elements from the baseline at regular intervals
    ## the function is triggerd by the scheduler with the time interval from `new_calculation_window`
    ## .. :zee:see: `new_calculation_window`, `connections_baseline`
    global cleanup_elements: function(days_table: table[time] of vector of element) : table[time] of vector of element;

}

event calculate_parametes() &priority=5 
    {
    # cleanup outdated elements
    for ( [i, p], days_table in connections_baseline )
        connections_baseline[i, p] = cleanup_elements(days_table);

    # callback
    schedule new_calculation_window { EXFIL_DETECTION::calculate_parametes() };

    }

function cleanup_elements(days_table: table[time] of vector of element) : table[time] of vector of element 
    {
    local old_element: time = 0;
    if ( baseline_days < |days_table| ) 
        {
        local days_set: set[time] = table_keys(days_table);

        local days_vec: vector of time;
        for ( d in days_set )
            days_vec += d;
        # sort vector, access first (oldest) element
        local foobar: vector of time = sort(days_vec);
        old_element = foobar[0];
        delete days_table[old_element];
        } 

    # call cleanup_elemnts recursive for further cleanup
    if ( old_element != 0 )
        days_table = cleanup_elements(days_table);

    return days_table;
    }

hook calculate_score(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element) &priority=5
    {
    local conn_date: time = Exfiltration::strip_time_from_date(network_time());
    local item: element = t[a, p, s];

    if ( [a, p] in connections_baseline ) 
        {
        if ( [conn_date] in connections_baseline[a, p] )
            connections_baseline[a, p][conn_date] += item;                  # add element to exsisting vector entry
        else
            connections_baseline[a, p][conn_date] = vector(item);           # create new 'date' table entry + new vector
        } 
    else
        connections_baseline[a, p] = table([conn_date] = vector(item));     # create new 'ip/port' table entry + new 'date' table entry + new vector
    }

