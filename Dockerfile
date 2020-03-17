FROM openjdk:8-jdk-alpine
MAINTAINER Atos
VOLUME /tmp
ADD ./target/idp-edugain-0.1.1.DEVELOPMENT.jar idp-edugain-0.1.1.DEVELOPMENT.jar
RUN sh -c 'touch /idp-edugain-0.1.1.DEVELOPMENT.jar'
ENV JAVA_OPTS=""
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /idp-edugain-0.1.1.DEVELOPMENT.jar" ]
EXPOSE 8090