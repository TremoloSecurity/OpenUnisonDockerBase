FROM tomcat:8-jre8

MAINTAINER Tremolo Security, Inc. - Docker <docker@tremolosecurity.com>


ENV OPEN_UNISON_VERSION 1.0.6
ENV OPEN_UNISON_WAR_URL https://www.tremolosecurity.com/nexus/service/local/repositories/releases/content/com/tremolosecurity/unison/open-unison-webapp/$OPEN_UNISON_VERSION/open-unison-webapp-$OPEN_UNISON_VERSION.war


ADD ./conf/context.xml /tmp/context.xml

RUN rm -rf /usr/local/tomcat/webapps/* ; \
    mkdir /etc/openunison ; \
    wget $OPEN_UNISON_WAR_URL -O /tmp/openunison.zip ; \
    mkdir /usr/local/tomcat/webapps/ROOT ; \
    unzip /tmp/openunison.zip -d /usr/local/tomcat/webapps/ROOT/ ; \
    rm /usr/local/tomcat/webapps/ROOT/WEB-INF/log4j.xml ; \
    mv /tmp/context.xml /usr/local/tomcat/webapps/ROOT/META-INF/context.xml ; \
    rm -rf /tmp/openunison.zip ; \
    mkdir -p /var/lib/unison-activemq



ENV CATALINA_OPTS -XX:+UseParallelGC  -Djava.security.egd=file:/dev/./urandom
