# gazk
A Gnark proof-of-stake service for the Gnarc ecosystem.



## Running
### Service (tested)
START
```bash
# Terminal 1
go run main.go server
```
STOP
```bash
# Terminal 2
go run main.go stop
```
### Signal (tested)
```bash
# Terminal 2
go run main.go generate 3 35
```
### Verification (wait)
```bash
# Terminal 3
go test -v ./test/...
```