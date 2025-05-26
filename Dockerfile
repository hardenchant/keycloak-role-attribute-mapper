FROM eclipse-temurin:21 AS base

WORKDIR /app

ADD . /app

RUN ./scripts/package

FROM alpine

COPY --from=base /app/target/keycloak-role-attribute-mapper-1.0.6-SNAPSHOT.jar /keycloak-role-attribute-mapper.jar
