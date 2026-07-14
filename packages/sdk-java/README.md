# defenso (Java / Spring)

Fail-open Defenso servlet filter.

## Install

```gradle
implementation "io.defenso:sdk:0.1.0"
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

## Fail-open contract

Same guarantees as the Node SDK.

## Status

Alpha scaffold.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-java)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
