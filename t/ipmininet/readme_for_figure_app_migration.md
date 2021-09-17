# Generating results for the application-level connection migration.

Assuming ipmininet has been successfully [installed](https://ipmininet.readthedocs.io/en/latest/install.html) and picotcpls successfuly compiled (follow the main readme), the first step is to launch the network:

```
$ sudo python3 test_network_2path.py  
```

This script configures a mininet experiment with a client, a server, some routers and 2 IP-level paths. 

Open a terminal for the client and server from mininet's command line interpreter:

```
xterm c s
```

Then, on the server, do:

```
./run_test_server_multipath.sh
```

On client, do the following to launch the experiment:

```
./run_test_client_multipath.sh
```

This experiment will download a 60MiB file and perform two application-level migrations during the download. The file "tcpls_migration_goodput" should be generated and be available in the current directory.

To capture TCP's throughput, open a client or server terminal and capture a .pcap with tcpdump on _one_ interface. Redirect its output to a file.

After the experiment, convert the .pcap using the python script convert_tcpdump.py: 

```
usage: convert_tcpdump.py [-h] -t T [-o O] -oname ONAME

Process a tcpdump -n trace and convert it to the following format: %H:%M:%S.%µS IP_SRC > IP_DEST LENGTH

optional arguments:
  -h, --help    show this help message and exit
  -t T          Path to the _ascii_ trace file
  -o O          Output directorty, default .
  -oname ONAME  Output filename
jaym@office:~/Documents/picotcpl
```

The converted tcpdump file, and the file tcpls_migration_goodput then needs to be feeded to the plot script.
