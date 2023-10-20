##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part detects new logs for individual hosts based on the baseline. 
##! The findings are logged as notice.

@load base/frameworks/notice

module EXFIL_DETECTION;

export {
    redef enum Notice::Type += {
        ## generated when a new protocol has been detected based on the baseline for a host. 
        ## as long as the baseline has not reached the required length, no messages are generated
        ## .. :zeek:see: `baseline_min_days_for_score`
        New_Protocol
    };
}

hook calculate_score(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element) &priority=6 
    {
    # exit, if port already exists
    if ( [a, p] in connections_baseline )
        return;

    # get ports for current address
    local ports: set[port] = set();
    local connection_keys: set[addr, port] = table_keys(connections_baseline);
    for ( [orig_h, resp_p] in connection_keys )
        {
        if ( a == orig_h )
            add ports[resp_p];
        }
    if ( |ports| == 0 )
        return;
    
    # get all days in baseline for current address and all existing ports
    # **known issue**: It is not mandatory that the days of the connections come from ONE port.
    # However, due to the large number of days, the host is present in the baseline for a 
    # sufficiently long time and new ports should be logged.
    local dates: set[time] = set();
    for ( prt in ports )
        {
        local days: set[time] = table_keys(connections_baseline[a, prt]);
        for ( d in days )
            add dates[d];
        }

    # check if baseline is long enough
    if ( |dates| >= baseline_min_days_for_score )
        {
        NOTICE([
            $note=New_Protocol,
            $msg=fmt("new protocol detected: protocol %s from host %s", cat(p), cat(a)),
            $sub=fmt("protocol was found in following uids: %s", cat(t[a, p, s]$uid)), 
            $ts=le$ts,
            $src=le$orig_h,
            $p=le$resp_p,
            $suppress_for=aggregation_interval
        ]);
        }
    }

