## Compiling
To compile the project, you can simply do:
```
cargo build --release
```
---
## Service
The service needs to be ran with `root` permissions, so instead of using
`cargo run`, use:
```sh
sudo ./target/release/service
```
or, to make your life easier,
```sh
./tester.sh
```
---
## Central
The program for visualizing the results is simpler, you can use:
```sh
cargo run --release --bin central
```
or, if you want to some consistency with how you run the other program,
```sh
./target/release/central
```
