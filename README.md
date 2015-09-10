```
$ ./rolod -server-addr=127.0.0.1:10005 -policy-file=./policy.json  &
$ ./rolome -user=polvi -readonly=true
authorized
$ ./rolome -user=polvi -readonly=false
rpc error: code = 2 desc = "No policy matched."
not authorized
exit status 1
```
