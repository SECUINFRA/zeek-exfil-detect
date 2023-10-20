# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

export {
    const mean: double = 2.416;
    const std: double = 0.6615;
    const value: double = 3.1;
}

event zeek_init()
    {
    print Exfiltration::tanh_normalization(value, mean, std);
    }

