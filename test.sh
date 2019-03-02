 # Build tests and run specific function as sudo
 go test -c -o tests && sudo ./tests -v -test.run TestRateConnectionslmpr
 