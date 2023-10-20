##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part calculates the 'producer-consumer ratio' score
##! The Producer-Consumer-Ratio implemantation is based on http://resources.sei.cmu.edu/asset_files/Presentation/2014_017_001_90063.pdf

module EXFIL_DETECTION;

export {
    ## add producer-consumer-ratio score of the element
    ## .. :zeek:see: `score`, `logging_element`
    redef record score += {
        pcr: double &log &optional;
    };

}

hook calculate_score(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element) &priority=0 
    {
    local item: element = t[a, p, s];
    # check if baseline is long enough
    if ( |connections_baseline[a, p]| >= baseline_min_days_for_score ) 
        {
        # claculate pcr
        local numerator: double = (item$orig_ip_bytes + 0.0) - (item$resp_ip_bytes + 0.0);
        local denominator: double = (item$orig_ip_bytes + 0.0) + (item$resp_ip_bytes + 0.0);

        if (numerator != 0.0 )
            {
            local x = ( numerator / denominator );
            # normalize value 
            # replace values < 0 with 0 to allow aggregation and keep value granularity untouched
            if ( x < 0.0 )
                le$score$pcr = 0.0;
            else
                le$score$pcr = x;
            }
        }
    }

