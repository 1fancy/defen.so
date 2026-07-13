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
