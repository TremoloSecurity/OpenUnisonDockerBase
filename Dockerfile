FROM tomcat:8-jre8

MAINTAINER Tremolo Security, Inc. - Docker <docker@tremolosecurity.com>

USER root
ENV OPEN_UNISON_VERSION 1.0.6
ENV OPEN_UNISON_WAR_URL https://www.tremolosecurity.com/nexus/service/local/repositories/releases/content/com/tremolosecurity/unison/open-unison-webapp/$OPEN_UNISON_VERSION/open-unison-webapp-$OPEN_UNISON_VERSION.war

ADD ./scripts/*.py /usr/local/tomcat/bin/
ADD ./conf/context.xml /tmp/context.xml

RUN useradd openunison ; \
    rm -rf /usr/local/tomcat/webapps/* ; \
    mkdir /etc/openunison ; \
    chown -R openunison:openunison /etc/openunison ; \
    curl $OPEN_UNISON_WAR_URL -o /tmp/openunison.zip ; \
    mkdir /usr/local/tomcat/webapps/ROOT ; \
    unzip /tmp/openunison.zip -d /usr/local/tomcat/webapps/ROOT/ ; \
    rm /usr/local/tomcat/webapps/ROOT/WEB-INF/log4j.xml ; \
    mv /tmp/context.xml /usr/local/tomcat/webapps/ROOT/META-INF/context.xml ; \
    chown -R openunison:openunison /usr/local/tomcat ; \
    rm -rf /tmp/openunison.zip ; \
    apt-get -y update ; \
    apt-get -y install python ; \
    mkdir -p /var/lib/unison-activemq ; \
    chown -R openunison:openunison /var/lib/unison-activemq



ENV CATALINA_OPTS -XX:+UseParallelGC  -Djava.security.egd=file:/dev/./urandom
