# Prototype implementation of MPSS protocol

This project is a prototype implementation of the VSSR protocol proposed by [Schultz et al.](https://dl.acm.org/doi/10.1145/1880022.1880028).

We implemented MPSS on top of the modified [BFT-SMaRt](https://github.com/bft-smart/library) library. 
You can find the modified version of the library [here](https://github.com/rvassantlal/library).

## Recommendation
The prototype is implemented in Java and was tested using Java 11.0.13.

## Compiling and packaging
First, clone this repository. Now inside the main directory `MPSS` (assuming you did not 
change the name), execute the following command to compile and package this implementation:
```
./gradlew installDist
```
The required jar files and default configurations files will be available inside 
the `MPSS/build/install/MPSS` directory.

## Usage
Since this MPSS prototype extends the BFT-SMaRt library, first configure BFT-SMaRt following 
instructions presented in its [repository](https://github.com/bft-smart/library). 
Next, configure MPSS by changing the `MPSS/config/mpss.config` file.

**TIP:** Reconfigure the system before compiling and packaging. This way, 
you don't have to configure multiple replicas.

**NOTE:** The following commands assume the Linux operating system. For the Windows operating system, 
use script `run.cmd` instead of `smartrun.sh`.

***Running throughput and latency experiment:***

After compiling and packaging, copy the content of the `MPSS/build/install/MPSS` directory into 
different locations/servers. Next, we present an example of running a system with four replicas 
tolerating one fault.

Execute the following commands across four different server consoles:
```
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 0
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 1
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 2
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 3
```

Once all replicas are ready, you can launch clients by executing the following command:
```
./smartrun.sh confidential.benchmark.PreComputedKVStoreClient <initial client id> <num clients> <number of ops> <request size> <write?> <precomputed?>
```
where:
* `<initial client id>` - the initial client id, e.g, 100;
* `<num clients>` - the number clients each execution of command will create, e.g., 20;
* `<number of ops>` - the number of requests each client will send, e.g., 10000;
* `<request size>` - the size in byte of each request, e.g., 1024;
* `<write?>` - requests are of write or read type? E.g., true;
* `<precompute?>` - are the requests precompute before sending to servers or are created on fly? E.g., true;

***Interpreting the throughput and latency results***

When clients continuously send the requests, servers will print the throughput information 
every two seconds.
When a client finishes sending the requests, it will print a string containing space-separated 
latencies of each request in nanoseconds. For example, you can use this result to compute average latency.
