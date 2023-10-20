##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information.
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part defines different adjustable parameters. Also the initial aggregation of the connection data and 
##! the hook for further processing is defined here.

@load base/protocols/conn
@load base/frameworks/broker

module EXFIL_DETECTION;

export {
    ## define the maximal hold time for a baseline or parameter element
    const max_baseline_hold_time: interval = 30day &redef;

    ## define the time inveral in which new parameters are calculated for the individual score
    ## e.g. the median/MAD for the modified zscore
    const new_calculation_window: interval = 1hr &redef;

    ## define the time interval in which multiple connections are aggregated (based on various indicators)
    ## before being appended to the baseline
    ## .. note:: for possible aggregation indicators see `enabled_indicators`
    ## .. :zeek:see: `enabled_indicators`
    const aggregation_interval: interval = 3hr &redef;

    ## define the number of days to be recoreded in the baseline
    const baseline_days: count = 14 &redef;

    ## keep baseline persistent across zeek restarts
    ## .. :zeek:see: `connections_baseline`
    const connections_baseline_persistent: bool = T &redef;

    ## define path for sqlite database to store connections_baseline across zeek restarts
    ## .. note:: '.sqlite' is added automaticly to the filename
    ## .. :zeek:see: `connections_baseline`, `connections_baseline_persistent`
    const connections_baseline_persistent_sqlite_path: string = "/tmp/zeek_persistent_baseline" &redef;

    ## define the minimum number of days with connections before the score are to be calculated using the baseline
    const baseline_min_days_for_score: count = 10 &redef;

    ## define which indicators should be used for the aggregation of the connections.
    ## if multiple indicators are used, aggregations is performed for all of them individually.
    ## possible indicators are `resp_h`, `domain` and `ja3s`
    ## .. :zeek:see: `aggregation_interval`, `get_identifier`
    const enabled_identifier: set[string] = set("resp_h", "domain", "ja3s") &redef;

    ## pulls all enabled identifiers from the :zeek:type:`connection` record for aggregation of the connections. 
    ## .. note:: For additional identifiers the hook body can be implemented again.
    ## .. :zeek:see: `aggregation_interval`, `enabled_identifier`
    global get_identifier: hook(c: connection, ident: vector of string);

    ## define the multicast address range which are excluded from the calcualtion of the scores
    const multicast_address_range: set[subnet] = set(224.0.0.0/4, [ff00::]/8, 255.255.255.255/32) &redef;
    
    ## define the threshold above which score a notice should be triggered
    const threshold_raise_notice_at_high_score: double = 0.8 &redef;
    
    ## properties of a baseline element
    type element: record {
        ## total number of `orig_ip_bytes` over the specified aggregation interval
        orig_ip_bytes: count;
        ## total number of `resp_ip_bytes` over the specified aggregation interval
        resp_ip_bytes: count;
        ## total interval of `duration` over the specified aggregation interval
        duration: interval;
        ## vector of all `uid` over the specified aggregation interval
        uid: vector of string &optional;
    } &log;

    ## contains entries for each score. the record is appended to each score as it is implemented.
    ## .. :zeek:see: `logging_element`
    type score: record {} &log;

    ## parameter for all information that will be logged. the record will be supplemented with further information during 
    ## the process of the script.
    ## .. :zeek:see: `score`
    type logging_element: record {
        ## timestamp at which the aggregated element is added to the baseline an the score is calculated
        ts: time &log;
        ## ip address of originator
        orig_h: addr &log;
        ## port number of responder
        resp_p: port &log;
        ## contains individual scores fo the element
        score: score &log;
    } &log;

    ## function that is triggered after completion of the aggregation interval
    ## This initiates the further procession of the relevant element
    ## .. :zee:see: `aggregation_interval`
    global agg_expire_func: function(t: table[addr, port, string] of element, a: addr, p: port, s: string) : interval;

    ## data strcuture for the storage/aggregation of the individul connections before they are added to the baseline
    ## .. :zee:see: `aggregation_interval`, `connections_baseline`, `agg_expire_func`
    global aggregation: table[addr, port, string] of element 
        &create_expire=aggregation_interval
        &expire_func=agg_expire_func;

    ## the event is used to calculate parameters for individual scores over the baseline. 
    ## using the zscore as an example, the median and mad are calculated here.
    ## the event is also used to determine and adjust the size of the baseline.
    ## The event is executed in periodic intervals based on the `new_calculation_window` time.
    ## .. :zeek:see: `new_calculation_window`
    global calculate_parametes: event();

    ## the hook is triggered as soon as an element has finished the time for aggregating of the connections. 
    ## the hook adds the corresponding element to the baseline and calculates the scores. 
    ## finally, the calculated scores are aggregated and the log entry is created
    ## .. :zeek:see: `agg_expire_func`
    global calculate_score: hook(t: table[addr, port, string] of element, a: addr, p: port, s: string, le: logging_element);

}

event network_time_init() 
    {
    schedule new_calculation_window { EXFIL_DETECTION::calculate_parametes() };
    }

event connection_state_remove(c: connection) &priority=1 
    {
    # only proceed with outgoing connections
    if ( c$conn$id$orig_h !in Site::local_nets || (c$conn$id$resp_h in Site::local_nets || c$conn$id$resp_h in multicast_address_range) )
        return;

    # workaround: add connection duration if not exists
    # otherwise it may cause wrong score results
    if ( ! c$conn?$duration )
        c$conn$duration = 0sec;

    # build new item
    local item = element(
        $orig_ip_bytes=c$conn$orig_ip_bytes, 
        $resp_ip_bytes=c$conn$resp_ip_bytes, 
        $duration=c$conn$duration,
        $uid=vector(c$conn$uid)
    );

    # get identifier for aggregation
    local ident: vector of string = vector();
    hook get_identifier(c, ident);

    for ( i in ident ) 
        {
        if ( [c$conn$id$orig_h, c$conn$id$resp_p, ident[i]] in aggregation ) 
            {
            # aggregate element to exsisting table entry
            aggregation[c$conn$id$orig_h, c$conn$id$resp_p, ident[i]]$orig_ip_bytes += c$conn$orig_ip_bytes;
            aggregation[c$conn$id$orig_h, c$conn$id$resp_p, ident[i]]$resp_ip_bytes += c$conn$resp_ip_bytes;
            aggregation[c$conn$id$orig_h, c$conn$id$resp_p, ident[i]]$duration += c$conn$duration;
            aggregation[c$conn$id$orig_h, c$conn$id$resp_p, ident[i]]$uid += c$conn$uid;
            } 
        else 
            {
            # create new 'ip/port/identifier' table entry
            aggregation[c$conn$id$orig_h, c$conn$id$resp_p, ident[i]] = item;
            }
        }

}

function agg_expire_func(t: table[addr, port, string] of element, a: addr, p: port, s: string) : interval 
    {
    local le: logging_element = logging_element($ts = network_time(), $orig_h=a, $resp_p=p, $score=score());
    hook calculate_score(t, a, p, s, le);
    return 0sec;
    }

hook get_identifier(c: connection, ident: vector of string) &priority=0 
    {
    if ( "resp_h" in enabled_identifier )
        ident += cat(c$conn$id$resp_h);

    if ( "domain" in enabled_identifier )
        local foo: vector of string;
        {
        if ( c?$http && c$http?$host )
            { 
            if ( is_valid_ip(c$http$host) )
                ident += c$http$host;
            else 
                {
                # extract parent domain
                foo = split_string(cat(c$http$host), /\./);
                ident += cat(foo[|foo|-2], ".", foo[|foo|-1]);
                }
            }
        else if ( c?$ssl && c$ssl?$server_name )
            { 
            # extract parent domain
            foo = split_string(cat(c$ssl$server_name), /\./);
            ident += cat(foo[|foo|-2], ".", foo[|foo|-1]);
            }
        }

    @ifdef ( JA3_Server )
    if ("ja3s" in enabled_identifier)
        {
        if ( c?$ssl && c$ssl?$ja3s ) 
            ident += cat(c$ssl$ja3s);
        }
    @endif
    }

