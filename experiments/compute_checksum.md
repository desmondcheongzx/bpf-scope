# Checksum computation overheads

Each run is set up as follows.

1. Flush the cache
    ```
    redis-cli flushall
    ```

2. Either run the set or get benchmark:
    ```
    redis-benchmark -t set -n 100000 -q
    ```
    or
    ```
    redis-benchmark -t get -n 100000 -q
    ```
## Results


| Program           | Test | Requests/s* |
| ----------------- | ---- | ----------- |
| No XDP            | SET  | 33394       |
| No XDP            | GET  | 31881       |
| Plain XDP**       | SET  | 32023       |
| Plain XDP**       | GET  | 29946       |
| XDP + checksum    | SET  | 32520       |
| XDP + checksum    | GET  | 30709       |
| XDP + 2x checksum | SET  | 31414       |
| XDP + 2x checksum | GET  | 30129       |

*Requests/s is the computed average over 50 runs

**The plain XDP program simply grabs the IP header, and does nothing else

Looking at the XDP + 2x checksum results, we see that SET has -5.93% throughput vs no XDP, and GET has -5.50% throughput vs no XDP.

But compared to XDP without checksum computation, there seems to be almost no difference.
