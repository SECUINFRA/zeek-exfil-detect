# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

export {
    const old_std: double = 0.6615;
    const old_mean: double = 2.416;
    const new_mean: double = 2.587;
    const cnt: count = 4;
    const new_value: double = 3.1;
}

event zeek_init()
    {
    print Exfiltration::add_to_std(old_std, old_mean, new_mean, cnt, new_value);
    }

