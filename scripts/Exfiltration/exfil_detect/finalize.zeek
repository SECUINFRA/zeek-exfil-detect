##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part calculates a final exfiltration score for the probability of exfiltration from all available sub-scores. 
##! Furthermore, the results are logged in the 'exfil_detection' log and a notice is raised when a certain 
##! threshold is exceeded.

@load base/frameworks/notice

module EXFIL_DETECTION;

export {
    ## properties of a logging element for the final logging
    redef record logging_element += {
        ## name of the identifier for the aggregation of the baseline element
        identifier: string &log &optional;
        ## total number of `resp_ip_bytes` over the specified aggregation interval
        orig_ip_bytes: count &log &optional;
        ## total number of `resp_ip_bytes` over the specified aggregation interval
        resp_ip_bytes: count &log &optional;
        ## total interval of `duration` over the specified aggregation interval
        duration: interval &log &optional;
        ## vector of all `uid` over the specified aggregation interval
        uid: vector of string &log &optional;
        ## calculated final exfiltration score of the element
        exfiltration_score: double &log &optional;
    };

    ## define new logging type for EXFIL_DETECTION
    redef enum Log::ID += { LOG };

    ## called EXFIL_DETECTION::logging_element.
    global log_exfil: event(rec: logging_element);

    redef enum Notice::Type += {
        ## generated when a exfiltration score above the given threshold is deteced.
        ## .. :zeek:see: `threshold_raise_notice_at_high_score`
        High_Score
    };
}

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=logging_element, $ev=log_exfil, $path="exfil_detection"]);
    }

hook calculate_score(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element) &priority=-5
    {
    if ( |connections_baseline[a, p]| < baseline_min_days_for_score ) 
        return;

    local item: element = t[a, p, s];
    le$exfiltration_score = 0;
    le$orig_ip_bytes = item$orig_ip_bytes;
    le$resp_ip_bytes = item$resp_ip_bytes;
    le$duration = item$duration;
    le$uid = item$uid;
    le$identifier = s;

    # calculate final exfiltration score form all sub-scores
    local cnt: count = 0;
    for ( [recored_key], field in record_fields(le$score) )
        {
        if ( field?$value )
            {
            le$exfiltration_score += field$value as double;
            }
        #
        # count, even if value does not exists
        # Info: the workaround can definitely be questioned, however, this prevents high results from being 
        #       generated on the basis of a single score
        #
        ++cnt;
        }
    if ( cnt > 0 )
        le$exfiltration_score = le$exfiltration_score / cnt;

    # create new log entry
    Log::write(EXFIL_DETECTION::LOG, le);

    # raise notice at high score
    if ( le$exfiltration_score >= threshold_raise_notice_at_high_score )
        {
        NOTICE([
            $note=High_Score,
            $msg=fmt("possible exfiltration detected: score %s from host %s with protocol %s", cat(le$exfiltration_score), cat(a), cat(p)),
            $sub=cat(le$exfiltration_score),
            $ts=le$ts,
            $src=le$orig_h,
            $p=le$resp_p,
            $suppress_for=aggregation_interval
        ]);
        }
    }

