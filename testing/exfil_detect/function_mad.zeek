# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

export {
    type values: record {
        value: count;
        name: string;
    };
    const m: double = 2.0;
}

event zeek_init()
    {
    # mad with even numbers in vector
    local foo: vector of count = vector(1, 3, 5, 7, 1, 5);
    print Exfiltration::mad(foo, m);

    # mad with un-even numbers in vector
    local bar: vector of count = vector(1, 3, 5);
    print Exfiltration::mad(bar, m);

    # mad with record values within vector
    local baz: vector of values = vector(
        values($value=1, $name="1"),
        values($value=3, $name="3"),
        values($value=5, $name="5"),
        values($value=7, $name="7"),
        values($value=1, $name="1"),
        values($value=5, $name="5")
    );
    print Exfiltration::mad(baz, m, "value");
    }


