##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part calculates the 'z-score' score

module EXFIL_DETECTION;

export {
    ## define dataset to store individual parameters of the baseline for the zscore
    ## .. :zeek:see: `zscore_parameters`
    type zscore_parameter: record {
        median: double;
        mad: double;
    };

    ## define dataset to store all parameters of the baseline for the calculation of the zscore over individual 
    ## connections
    ## .. :zeek:see: `zscore_parameter`
    global zscore_parameters: table[addr, port] of zscore_parameter &write_expire=max_baseline_hold_time;

    ## define dataset to store all parameters for normalizing the zscore
    global zscore_normalization: record {
        n: count &default=0;
        mean: double &default=0;
        std: double &default=0;
    };

    ## add zsocre score of the element
    ## .. :zeek:see: `score`, `logging_element`
    redef record score += {
        zscore: double &log &optional;
    };

}

event calculate_parametes() &priority=0
    {
    for ( [i, p], days_table in connections_baseline ) 
        {
        # create single vector with all day-vector values
        local vec: vector of element = vector();
        for ( [j], vectors in days_table )
            vec += vectors;

        local median: double = Exfiltration::median(vec, "orig_ip_bytes");
        local mad: double = Exfiltration::mad(vec, median, "orig_ip_bytes");
        # add parameters to dataset 
        zscore_parameters[i, p] = zscore_parameter($median=median, $mad=mad);
        }
    }

hook calculate_score(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element) &priority=0
    {
    # check if baseline is long enough
    if ( |connections_baseline[a, p]| >= baseline_min_days_for_score )
        {
        # calculate zscore
        local item: element = t[a, p, s];
        if ( [a, p] in zscore_parameters )
            {
            local zscore: double;
            if ( zscore_parameters[a, p]$mad != 0 )
                {
                zscore = (item$orig_ip_bytes - zscore_parameters[a, p]$median) / zscore_parameters[a, p]$mad;
                # normalise zscore
                ++zscore_normalization$n;
                local old_mean: double = zscore_normalization$mean;
                zscore_normalization$mean = Exfiltration::add_to_mean(zscore_normalization$mean, zscore_normalization$n, zscore);
                zscore_normalization$std = Exfiltration::add_to_std(zscore_normalization$std, zscore_normalization$mean, old_mean, 
                                                                 zscore_normalization$n, zscore);
                local result: double = Exfiltration::tanh_normalization(zscore, zscore_normalization$mean, zscore_normalization$std);
                # replace values < 0 with 0 to allow aggregation and keep value granularity untouched
                if ( result < 0.0 )
                    le$score$zscore = 0.0;
                else
                    le$score$zscore = result;
                } 
            }
        }
    }

