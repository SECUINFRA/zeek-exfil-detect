# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

export {
    const old_mean: double = 2.416;
    const cnt: count = 4;
    const new_value: double = 3.1;
}

event zeek_init()
    {
    print Exfiltration::add_to_mean(old_mean, cnt, new_value);
    }

