
## Pcap Demo

Require JDK-17 or later.

- pcap_dispatch
```bash
./mvnw clean package
java -jar pcap-dispatch/target/pcap-dispatch-*-jar-with-dependencies.jar
```

- pcap_loop
```bash
./mvnw clean package
java -jar pcap-loop/target/pcap-loop-*-jar-with-dependencies.jar
```

- pcap_next
```bash
./mvnw clean package
java -jar pcap-next/target/pcap-next-*-jar-with-dependencies.jar
```

- pcap_next_ex
```bash
./mvnw clean package
java -jar pcap-next-ex/target/pcap-next-ex-*-jar-with-dependencies.jar
```