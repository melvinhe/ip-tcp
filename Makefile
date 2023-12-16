all:
	go build -o vhost ./cmd/vhost/main.go
	go build -o vrouter ./cmd/vrouter/main.go

topologies: prepare-directories doc-example linear-r1h2 linear-r1h4 linear-r2h2 linear-r3h2 loop

prepare-directories:
	mkdir -p topologies/doc-example
	mkdir -p topologies/linear-r1h2
	mkdir -p topologies/linear-r1h4
	mkdir -p topologies/linear-r2h2
	mkdir -p topologies/linear-r3h2
	mkdir -p topologies/loop

doc-example:
	util/vnet_generate nets/doc-example.json topologies/doc-example

linear-r1h2:
	util/vnet_generate nets/linear-r1h2.json topologies/linear-r1h2

linear-r1h4:
	util/vnet_generate nets/linear-r1h4.json topologies/linear-r1h4

linear-r2h2:
	util/vnet_generate nets/linear-r2h2.json topologies/linear-r2h2

linear-r3h2:
	util/vnet_generate nets/linear-r3h2.json topologies/linear-r3h2

loop:
	util/vnet_generate nets/loop.json topologies/loop

run-doc-example:
	util/vnet_run --clean topologies/doc-example

run-linear-r1h2:
	util/vnet_run --clean topologies/linear-r1h2

run-linear-r1h4:
	util/vnet_run --clean topologies/linear-r1h4

run-linear-r2h2:
	util/vnet_run --clean topologies/linear-r2h2

run-linear-r3h2:
	util/vnet_run --clean topologies/linear-r3h2

run-loop:
	util/vnet_run --clean topologies/loop

clean:
	rm -f ./vhost
	rm -f ./vrouter

clean-topologies:
	rm -rf topologies