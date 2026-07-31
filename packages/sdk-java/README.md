# defenso (Java / Spring)

Fail-open Defenso servlet filter.

## Install

```gradle
implementation "io.defenso:defenso:0.2.0"
```

or Maven:

```xml
<dependency>
    <groupId>io.defenso</groupId>
    <artifactId>sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Use — Spring Boot

```java
@Bean
public DefensoFilter defenso() {
    return new DefensoFilter(System.getenv("DEFENSO_TOKEN"));
}
```

## Status

Scaffold — this SDK currently passes every request through and does not yet inspect, block, cache policy, or forward attack logs. For working protection today use the CNAME edge (point your domain at guard.defen.so — full WAF, no code) or the Node/PHP SDKs.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-java)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
