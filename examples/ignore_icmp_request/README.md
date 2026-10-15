# Ignore ICMP Request

This will demo the iptables accepting an icmp message, and then the kernel not generating a response based on a sysctl value that is set.

![Ignore ICMP Request](../../media/examples/ignore_icmp_request/ignore_icmp_request.gif)

In the `router` container, we have, net.ipv4.icmp_echo_ignore_all: "1", which disables icmp response at the kernel level. To validate this we can do the following:

### 1. Launch the demo containers:

```
docker-compose up -d --build
```

The `router` container should start `packetman` on its entrypoint, navigate to `localhost:8080` in your browser.

### 2. Send a ping:

Verify there is no ping response

```
username@os# docker exec host-a bash -c "ping -c 1 172.10.1.10 -c 1 -w 1"
PING 172.10.1.10 (172.10.1.10) 56(84) bytes of data.

--- 172.10.1.10 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

username@os#
```

### 3. Validate iptables traversal

![Validate Incoming Packet](../../media/examples/ignore_icmp_request/incoming_packet_capture.png)

### 4. Validate no response generated

![No Response](../../media/examples/ignore_icmp_request/validate_no_response.png)


This demonstrates that the incoming packet is accepted through all iptables, however a reponse message is not generated because of the sysctl disabling icmp echo response at the kernel level in the `router` container.

### 5. Stop the demo containers:


```
docker compose down -t 0
```