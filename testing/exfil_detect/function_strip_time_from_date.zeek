# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

export {
    const foo: double = 1669816341.0;
}

event zeek_init()
    {
    local bar: time = double_to_time(foo);
    print Exfiltration::strip_time_from_date(bar);
    }


