# pcap_truncate: A tool to truncate pcap files by resizing snaplen

`pcap_truncate` is a tool to truncate pcap files. It resizes speplen (i.e., maximum packet length to store).

## How to use

### Build
```
$ cmake .
$ make
```

### Execution
The following is the example to truncate `original.pcap` to `truncated.pcap` with snaplen of 96.
```
$ ./build/truncate_pcap original.pcap truncated.pcap 96
```

