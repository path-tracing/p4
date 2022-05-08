# Path Tracing 

Path Tracing provides a record of the packet path as a sequence of interface ids. In addition, it provides a record of end-to-end delay, per-hop delay, and load on each egress interface along the packet delivery path.

Path Tracing supports fine grained timestamp. It has been designed for linerate hardware implementation in the base pipeline. 

## Benefits 
**Low overhead:**

- Lowest MTU overhead compared to alternative solutions such as [INT](https://github.com/p4lang/p4-applications/blob/master/docs/INT_v2_1.pdf), [IOAM](https://www.ietf.org/archive/id/draft-ietf-ippm-ioam-data-17.txt), [IFIT](https://www.ietf.org/archive/id/draft-song-opsawg-ifit-framework-17.txt), and [IFA](https://www.ietf.org/archive/id/draft-kumar-ippm-ifa-04.txt).

**Linerate and HW friendliness:**

- Implemented at linerate in current hardware, using the regular forwarding pipeline. No offloading to co-processors or slow-path whose databases might defer from forwarding pipeline.

- Leverages mature hardware capabilities (basic shift operation); no packet resizing at every node along the path.

- High number of diverse linerate interoperable hardware Implementations.

**Scalable Fine-grained Timestamp**

- Full 64bit timestamp at PT Source and PT Sink nodes.

- Truncated 8bit timestamp at PT Midpoint leveraging flexible per-outgoing-link template allowing diverse link types in the same measurement (e.g., DC, metro, WAN).

**Scalable Load measurement**

## Ecosystem 

Path Tracing enjoys a rich ecosystem that includes several implementations in merchant silicon (Broadcom, Cisco, Marvell, others) and open source (Linux, VPP, P4, others). 

Several operators have shown strong interest in Path Tracing. Some operators are already testing Path Tracing in their lab. 

## Standardization 

The Path Tracing solution is currently being standardized in the SPRING WG at IETF. Please refer to the [Path Tracing IETF draft] (https://datatracker.ietf.org/doc/draft-filsfils-spring-path-tracing/) for more details. 

## Tutorials  

Tutorials, Demos, and more details on Path Tracing can be found on the [segment routing website] (https://www.segment-routing.net/path-tracing). 


## P4 Implementation
In this repository we provide a P4 implementation for the Path Tracing solution. 

The P4 implementation uses the behavioral-model-v2 (bmv2) for the software implementation of the P4 Datapath.

The repository is structured as follows:

 * `p4src/` P4 implementation


## Authors 
 * Angelo Tulumello
 * Ahmed Abdelsalam 


## References
* [Path Tracing IETF Draft](https://datatracker.ietf.org/doc/draft-filsfils-spring-path-tracing/)
* [Path Tracing tutorials + demos](https://www.segment-routing.net/path-tracing)