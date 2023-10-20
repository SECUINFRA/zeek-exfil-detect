##! The script belongs to the module 'EXFIL_DETECTION' which detects exfiltration attempts based on a baseline 
##! with historical information. 
##! For this purpose, different scores are calculated and differences from the baseline are considered as anomaly 
##! and thus exfiltration.
##! The following part enables the persistent storage of the created baseline across zeek restarts. 
##! For this purpose, all beasline information are written to a sqlite database when zeek is terminated. 
##! On restart, this information is inserted back into the baseline data structure.

@load base/frameworks/reporter

module EXFIL_DETECTION;

export {
    ## define new logging type for EXFIL_DETECTION
    ## this logging type is used as sqlite-logger only
    redef enum Log::ID += { BASELINE_LOG };

    ## define new logging record for sqlite database entries
    type Baseline_Info: record {
        orig_h: addr &log;
        resp_p: port &log;
        day: time &log;
        entry: element &log;
    };

    ## called EXFIL_DETECTION::Baseline_Info
    global log_sqlite: event(rec: Baseline_Info);

    ## define event handler to read sqlite data into `connections_baseline` at zeek init
    global baseline_ingest: event(description: Input::EventDescription, tpe: Input::Event, data: Baseline_Info);

    ## define error event handler for sqlite input stream
    global error_ev: event(desc: Input::EventDescription, message: string, level: Reporter::Level);
}

event zeek_init() &priority=0
    {
    if ( ! connections_baseline_persistent )
        return;
    
    Input::add_event([
        $source=connections_baseline_persistent_sqlite_path, 
        $name="baseline_ingest", 
        $fields=Baseline_Info, 
        $ev=baseline_ingest,
        $error_ev=error_ev,
        $reader=Input::READER_SQLITE,
        $config=table(["query"] = "select * from baseline;")
    ]);
    }

event baseline_ingest(description: Input::EventDescription, tpe: Input::Event, data: Baseline_Info)
    {
    if ( [data$orig_h, data$resp_p] in connections_baseline ) 
        {
        if ( [data$day] in connections_baseline[data$orig_h, data$resp_p] )
            connections_baseline[data$orig_h, data$resp_p][data$day] += data$entry;                  # add element to exsisting vector entry
        else
            connections_baseline[data$orig_h, data$resp_p][data$day] = vector(data$entry);           # create new 'date' table entry + new vector
        } 
    else
        connections_baseline[data$orig_h, data$resp_p] = table([data$day] = vector(data$entry));     # create new 'ip/port' table entry + new 'date' table entry + new vector
    }

event error_ev(desc: Input::EventDescription, message: string, level: Reporter::Level)
    {
    if ( message == "SQLite call failed: unable to open database file" )    # log warning message only once
        Reporter::warning(fmt("Exfil_Detection: failed to load sqlite database for persistent baseline. file not found in path '%s'", connections_baseline_persistent_sqlite_path));
    }

event Input::end_of_data(name: string, source:string)
    {
    if ( source == connections_baseline_persistent_sqlite_path )
        {
        Reporter::info(fmt("Exfil_Detection: successful loaded %s [host/port] entries from sqlite database for persistent baseline from file: '%s'", 
            cat(|connections_baseline|), 
            connections_baseline_persistent_sqlite_path));
        Input::remove(name);
        }
    }

event zeek_done() &priority=-10
    {
    if ( ! connections_baseline_persistent )
        return;
    
    # if exists, remove old sqlite file
    # modifiy `connections_baseline_persistent_sqlite_path` b/c '.sqlite' is automaticly added to filename
    local filename: string = fmt("%s.sqlite", connections_baseline_persistent_sqlite_path);
    if ( ! unlink(filename) )
        Reporter::warning(fmt("Exfil_Detection: unable to remove old sqlite database for persistent baseline in path '%s'", filename));

    Log::create_stream(EXFIL_DETECTION::BASELINE_LOG, [$columns=Baseline_Info, $ev=log_sqlite, $path="sqlite_baseline"]);

    local filter: Log::Filter =
        [
        $name="sqlite",
        $path=connections_baseline_persistent_sqlite_path,
        $config=table(["tablename"] = "baseline"),
        $writer=Log::WRITER_SQLITE
        ];

    # define sqlite logging, remove default (logfile) log
    Log::add_filter(EXFIL_DETECTION::BASELINE_LOG, filter);
    Log::remove_filter(EXFIL_DETECTION::BASELINE_LOG, "default");

    for ( [i, p], days_table in connections_baseline ) 
        {
        for ( [j], vectors in days_table )
            {
            for ( v in vectors )
                {
                # log each vector element
                local e: Baseline_Info = Baseline_Info($orig_h=i, $resp_p=p, $day=j, $entry=vectors[v]);
                Log::write(EXFIL_DETECTION::BASELINE_LOG, e);
                }
            }
        }
    Reporter::info(fmt("Exfil_Detection: successful stored %s [host/port] entries to sqlite database for persistent baseline to file: '%s'", 
        cat(|connections_baseline|), 
        connections_baseline_persistent_sqlite_path));
    }

