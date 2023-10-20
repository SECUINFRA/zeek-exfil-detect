##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part calculates the 'euclidean' score

module EXFIL_DETECTION;

export {
    ## define dataset to store individual parameters of the baseline for the euclidean score
    ## .. :zeek:see: `euclidean_parameters`
    type euclidean_parameter: record {
        median_bytes: double;
        mad_bytes: double;
        median_duration: double;
        mad_duration: double;
        reference_point_median_bytes: double;
        reference_point_median_duration: double;
    };

    ## define dataset to store all parameters of the baseline for the calculation of the euclidean score over individual 
    ## connections
    ## .. :zeek:see: `euclidean_parameter`
    global euclidean_parameters: table[addr, port] of euclidean_parameter &write_expire=max_baseline_hold_time;

    ## define dataset to store all parameters for normalizing the euclidean score
    global euclidean_normalization: record {
        n: count &default=0;
        mean: double &default=0;
        std: double &default=0;
    };

    ## add euclidean score of the element
    ## .. :zeek:see: `score`, `logging_element`
    redef record score += {
        euclidean: double &log &optional;
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

        # normalize parameters with modified z-score
        local median_bytes: double = Exfiltration::median(vec, "orig_ip_bytes");
        local mad_bytes: double = Exfiltration::mad(vec, median_bytes, "orig_ip_bytes");
        local median_duration: double = Exfiltration::median(vec, "duration");
        local mad_duration: double = Exfiltration::mad(vec, median_duration, "duration");

        if ( mad_bytes != 0 && mad_duration != 0)
            {
            local norm_vec: vector of element = vector();
            for ( _, e in vec )
                {
                norm_vec += element(
                    $orig_ip_bytes=double_to_count(|(e$orig_ip_bytes - median_bytes) / mad_bytes|),
                    $resp_ip_bytes=0,    # not needed
                    $duration=double_to_interval(|(|e$duration| - median_duration) / mad_duration|)
                );
                }

            # get median from normalized values as reference point for euclidean distance
            local reference_point_median_bytes: double = Exfiltration::median(norm_vec, "orig_ip_bytes");
            local reference_point_median_duration: double = Exfiltration::median(norm_vec, "duration");
            # add parameters to dataset 
            euclidean_parameters[i, p] = euclidean_parameter(
                $median_bytes=median_bytes,
                $mad_bytes=mad_bytes,
                $median_duration=median_duration,
                $mad_duration=mad_duration,
                $reference_point_median_bytes=reference_point_median_bytes, 
                $reference_point_median_duration=reference_point_median_duration
            );
            }
        }
    }

hook calculate_score(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element) &priority=0
    {
    # check if baseline is long enough
    if ( |connections_baseline[a, p]| >= baseline_min_days_for_score )
        {
        # calculate euclidean score
        local item: element = t[a, p, s];
        if ( [a, p] in euclidean_parameters )
            {
            local euclidean: double;
            if ( euclidean_parameters[a, p]$mad_bytes != 0 && euclidean_parameters[a, p]$mad_duration != 0 )
                {
                # normalize values (of current connection) with modified z-score
                local norm_orig_ip_byes = |(item$orig_ip_bytes - euclidean_parameters[a, p]$median_bytes) / euclidean_parameters[a, p]$mad_bytes|;
                local norm_duration = |(|item$duration| - euclidean_parameters[a, p]$median_duration) / euclidean_parameters[a, p]$mad_duration|;
                # calculate euclidean distance
                euclidean = sqrt(
                    pow(norm_orig_ip_byes - euclidean_parameters[a, p]$reference_point_median_bytes, 2) +
                    pow(norm_duration - euclidean_parameters[a, p]$reference_point_median_duration, 2)
                );
                # normalise euclidean score
                ++euclidean_normalization$n;
                local old_mean: double = euclidean_normalization$mean;
                euclidean_normalization$mean = Exfiltration::add_to_mean(euclidean_normalization$mean, euclidean_normalization$n, euclidean);
                euclidean_normalization$std = Exfiltration::add_to_std(euclidean_normalization$std, euclidean_normalization$mean, old_mean, 
                                                                 euclidean_normalization$n, euclidean);
                local result: double = Exfiltration::tanh_normalization(euclidean, euclidean_normalization$mean, euclidean_normalization$std);
                # replace values < 0 with 0 to allow aggregation and keep value granularity untouched
                if ( result < 0.0 )
                    le$score$euclidean = 0.0;
                else
                    le$score$euclidean = result;
                } 
            }
        }
    }
