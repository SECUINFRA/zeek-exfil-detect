# @TEST-EXEC: zeek -NN Exfiltration::exfil_detect |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
