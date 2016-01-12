# OpenUnisonDocker

This file builds the base image for OpenUnison.  There are two options for deploying OpenUnison into your Docker server:

1. Deploy the OpenUnisonDockerDeploy deploy image
2. Use shared volumes to start OpenUnison using an underlying environment

The first choice is the easiest for getting up and running, but offers several challenges for deployments and security (how do you secure artifacts? how do you store passwords?).  The second option makes for a more manageable deployment, but requires more steps.  See the OpenUnisonDockerDeploy project for details on how to deploy OpenUnison using the deploy Dockerfile.

## Create OpenUnison Files on the Host System

Prior to setting up OpenUnison create a directory on your Docker host for the OpenUnison configuration files and for the Tomcat configuration file.  For the sake of simplicity, we'll asssume that all configuration files will go into /etc/openunison:

```bash
$ mkdir -p /etc/openunison
```

Next, create the /etc/openunison/unisonService.props file based on the below template:

```
com.tremolosecurity.openunison.forceToSSL=true
com.tremolosecurity.openunison.openPort=8080
com.tremolosecurity.openunison.securePort=8443
com.tremolosecurity.openunison.externalOpenPort=8080
com.tremolosecurity.openunison.externalSecurePort=8443
#Uncomment and set for production deployments
com.tremolosecurity.openunison.activemqdir=/var/lib/unison-activemq
```

Now create the OpenUnison key store:
```bash
$ keytool -genkeypair -storetype JCEKS -alias unison-tls -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -keystore /etc/openunison/unisonKeyStore.jks
$ keytool -genseckey -storetype JCEKS -alias session-unison -keyalg AES -keysize 256  -keystore /etc/openunison/unisonKeyStore.jks
```
We're assuming the same key aliases as the deploy image.  Once these two files are created, next create the /etc/openunison/unison.xml file.  The below file is a very basic starting point.  Make sure to update the hosts (below its dockerhost.domain.com) and the keystore password.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<tremoloConfig xmlns="http://www.tremolosecurity.com/tremoloConfig" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.tremolosecurity.com/tremoloConfig tremoloConfig.xsd">
  <applications openSessionCookieName="openSession" openSessionTimeout="9000">
    <application name="LoginTest" azTimeoutMillis="30000" >
      <urls>
        <!-- The regex attribute defines if the proxyTo tag should be interpreted with a regex or not -->
        <!-- The authChain attribute should be the name of an authChain -->
        <url regex="false" authChain="formloginFilter" overrideHost="true" overrideReferer="true">
          <!-- Any number of host tags may be specified to allow for an application to work on multiple hosts.  Additionally an asterick (*) can be specified to make this URL available for ALL hosts -->
          <host>dockerhost.domain.com</host>
          <!-- The filterChain allows for transformations of the request such as manipulating attributes and injecting headers -->
          <filterChain>
            <filter class="com.tremolosecurity.prelude.filters.LoginTest">
              <!-- The path of the logout URI		-->
              <param name="logoutURI" value="/logout"/>
            </filter>
          </filterChain>
          <!-- The URI (aka path) of this URL -->
          <uri>/</uri>
          <!-- Tells OpenUnison how to reach the downstream application.  The ${} lets you set any request variable into the URI, but most of the time ${fullURI} is sufficient -->
          <proxyTo>http://dnm${fullURI}</proxyTo>
          <!-- List the various results that should happen -->
          <results>
            <azSuccess>
            </azSuccess>
            <azFail>Invalid Login</azFail>
            <auFail>Invalid Login</auFail>
          </results>
          <!-- Determine if the currently logged in user may access the resource.  If ANY rule succeeds, the authorization succeeds.
          The scope may be one of group, dn, filter, dynamicGroup or custom
          The constraint identifies what needs to be satisfied for the authorization to pass and is dependent on the scope:
            * group - The DN of the group in OpenUnison's virtual directory (must be an instance of groupOfUniqueNames)
            * dn - The base DN of the user or users in OpenUnison's virtual directory
            * dynamicGroup - The DN of the dynamic group in OpenUnison's virtual directory (must be an instance of groupOfUrls)
            * custom - An implementation of com.tremolosecurity.proxy.az.CustomAuthorization -->
          <azRules>
            <rule scope="dn" constraint="o=Tremolo" />
          </azRules>
        </url>
        <url regex="false" authChain="formloginFilter" overrideHost="true" overrideReferer="true">
          <!-- Any number of host tags may be specified to allow for an application to work on multiple hosts.  Additionally an asterick (*) can be specified to make this URL available for ALL hosts -->
          <host>dockerhost.domain.com</host>
          <!-- The filterChain allows for transformations of the request such as manipulating attributes and injecting headers -->
          <filterChain>
            <filter class="com.tremolosecurity.prelude.filters.StopProcessing" />
          </filterChain>
          <!-- The URI (aka path) of this URL -->
          <uri>/logout</uri>
          <!-- Tells OpenUnison how to reach the downstream application.  The ${} lets you set any request variable into the URI, but most of the time ${fullURI} is sufficient -->
          <proxyTo>http://dnm${fullURI}</proxyTo>
          <!-- List the various results that should happen -->
          <results>
            <azSuccess>Logout</azSuccess>
          </results>
          <!-- Determine if the currently logged in user may access the resource.  If ANY rule succeeds, the authorization succeeds.
                    The scope may be one of group, dn, filter, dynamicGroup or custom
                    The constraint identifies what needs to be satisfied for the authorization to pass and is dependent on the scope:
                      * group - The DN of the group in OpenUnison's virtual directory (must be an instance of groupOfUniqueNames)
                      * dn - The base DN of the user or users in OpenUnison's virtual directory
                      * dynamicGroup - The DN of the dynamic group in OpenUnison's virtual directory (must be an instance of groupOfUrls)
                      * custom - An implementation of com.tremolosecurity.proxy.az.CustomAuthorization -->
          <azRules>
            <rule scope="dn" constraint="o=Tremolo" />
          </azRules>
        </url>
      </urls>
      <!-- The cookie configuration determines how sessions are managed for this application -->
      <cookieConfig>
        <!-- The name of the session cookie for this application.  Applications that want SSO between them should have the same cookie name -->
        <sessionCookieName>tremolosession</sessionCookieName>
        <!-- The domain of component of the cookie -->
        <domain>dockerhost.domain.com</domain>
        <!-- The URL that OpenUnison will interpret as the URL to end the session -->
        <logoutURI>/logout</logoutURI>
        <!-- The name of the AES-256 key in the keystore to use to encrypt this session -->
        <keyAlias>session-unison</keyAlias>
        <!-- If set to true, the cookie's secure flag is set to true and the browser will only send this cookie over https connections -->
        <secure>false</secure>
        <!-- The number of secconds that the session should be allowed to be idle before no longer being valid -->
        <timeout>900</timeout>
        <!-- required but ignored -->
        <scope>-1</scope>
      </cookieConfig>
    </application>
    <!-- Uncomment this block for web services -->
    <!--
    <application name="WebServices">
    <urls>
      <url regex="false" authChain="sslCert">
        <host>dockerhost.domain.com</host>
        <filterChain />
        <uri>/services</uri>
        <results />
        <azRules>
          <rule scope="dn" constraint="ou=CertAuth,o=Tremolo" />
        </azRules>
      </url>
    </urls>
    <cookieConfig>
      <sessionCookieName>tremoloWSSession</sessionCookieName>
      <domain>dockerhost.domain.com</domain>
      <scope>-1</scope>
      <logoutURI>/logout</logoutURI>
      <keyAlias>session-wssession</keyAlias>
      <keyPassword>
      </keyPassword>
      <secure>true</secure>
      <timeout>900</timeout>
    </cookieConfig>
    </application>
  -->
  </applications>
  <myvdConfig>/etc/openunison/myvd.conf</myvdConfig>
  <authMechs>
    <mechanism name="loginForm">
      <uri>/auth/formLogin</uri>
      <className>com.tremolosecurity.proxy.auth.FormLoginAuthMech</className>
      <init>
      </init>
      <params>
        <param>FORMLOGIN_JSP</param>
      </params>
    </mechanism>
    <mechanism name="anonymous">
      <uri>/auth/anon</uri>
      <className>com.tremolosecurity.proxy.auth.AnonAuth</className>
      <init>
        <!-- The RDN of unauthenticated users -->
        <param name="userName" value="uid=Anonymous"/>
        <!-- Any number of attributes can be added to the anonymous user -->
        <param name="role" value="Users" />
      </init>
      <params>
      </params>
    </mechanism>
    <mechanism name="certAuth">
      <uri>/auth/ssl</uri>
      <className>com.tremolosecurity.proxy.auth.CertAuth</className>
      <init>
        <!-- Comma seperated list of CRLs to check -->
        <param name="crl.names" value=""/>
      </init>
      <params>
      </params>
    </mechanism>
  </authMechs>
  <authChains>
    <!-- An anonymous authentication chain MUST be level 0 -->
    <chain name="anon" level="0">
      <authMech>
        <name>anonymous</name>
        <required>required</required>
        <params>
        </params>
      </authMech>
    </chain>
    <chain name="formloginFilter" level="20">
      <authMech>
        <name>loginForm</name>
        <required>required</required>
        <params>
          <!-- Path to the login form -->
          <param name="FORMLOGIN_JSP" value="/auth/forms/defaultForm.jsp"/>
          <!-- Either an attribute name OR an ldap filter mapping the form parameters. If this is an ldap filter, form parameters are identified by ${parameter} -->
          <param name="uidAttr" value="uid"/>
          <!-- If true, the user is determined based on an LDAP filter rather than a simple user lookup -->
          <param name="uidIsFilter" value="false"/>
        </params>
      </authMech>
    </chain>
    <!-- Uncomment to support web services -->
    <!--
    <chain name="certClientAuth" level="40">
      <authMech>
        <name>certAuth</name>
        <required>required</required>
        <params>
          <param name="uidAttr" value="(uid=${CN})" />
          <param name="uidIsFilter" value="true"/>
          <param name="rdnAttribute" value="CN" />
          <param name="defaultOC" value="inetOrgPerson" />
          <param name="dnLabel" value="ou=CertAuth"/>
          <param name="issuer" value="OU=Dev, O=Tremolo Security Inc., C=US, ST=Virginia, CN=Root CA"/>
        </params>
      </authMech>
    </chain>
  -->
  </authChains>
  <resultGroups>
    <!-- The name attribute is how the resultGroup is referenced in the URL -->
    <resultGroup name="Logout">
      <!-- Each result should be listed -->
      <result>
        <!-- The type of result, one of cookie, header or redirect -->
        <type>redirect</type>
        <!-- The source of the result value, one of user, static, custom -->
        <source>static</source>
        <!-- Name of the resuler (in this case a cookie) and the value -->
        <value>/auth/forms/logout.jsp</value>
      </result>
    </resultGroup>
    <!-- The name attribute is how the resultGroup is referenced in the URL -->
    <resultGroup name="Invalid Login">
      <!-- Each result should be listed -->
      <result>
        <!-- The type of result, one of cookie, header or redirect -->
        <type>redirect</type>
        <!-- The source of the result value, one of user, static, custom -->
        <source>static</source>
        <!-- Name of the resuler (in this case a cookie) and the value -->
        <value>/auth/forms/defaultFailedLogin.jsp</value>
      </result>
    </resultGroup>
  </resultGroups>
  <keyStorePath>/etc/openunison/unisonKeyStore.jks</keyStorePath>
  <keyStorePassword>start123</keyStorePassword>
  </tremoloConfig>
```

Next create /etc/openunison/log4j.xml
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE log4j:configuration SYSTEM "log4j.dtd">
<log4j:configuration xmlns:log4j="http://jakarta.apache.org/log4j/">
  <appender name="console" class="org.apache.log4j.ConsoleAppender">
    <param name="Target" value="System.out"/>
    <layout class="org.apache.log4j.PatternLayout">
      <param name="ConversionPattern" value="%-5p %c{1} - %m%n"/>
    </layout>
  </appender>

  <root>
    <priority value ="info" />
    <appender-ref ref="console" />
  </root>

</log4j:configuration>
```

Finally, create an /etc/openunison/myvd.conf
```properties
#Global AuthMechConfig
server.globalChain=

server.nameSpaces=rootdse,myvdroot,testuser
server.rootdse.chain=dse
server.rootdse.nameSpace=
server.rootdse.weight=0
server.rootdse.dse.className=net.sourceforge.myvd.inserts.RootDSE
server.rootdse.dse.config.namingContexts=o=Tremolo
server.myvdroot.chain=root
server.myvdroot.nameSpace=o=Tremolo
server.myvdroot.weight=0
server.myvdroot.root.className=net.sourceforge.myvd.inserts.RootObject

server.testuser.chain=admin
server.testuser.nameSpace=ou=testuser,o=Tremolo
server.testuser.weight=0
server.testuser.admin.className=com.tremolosecurity.proxy.myvd.inserts.admin.AdminInsert
server.testuser.admin.config.uid=test
server.testuser.admin.config.password=test
```

## Create the Tomcat /etc/openunison/server.xml File

The below server.xml file is tested with the OpenUnison image.  It points to the /etc/openunison/unisonKeystore.jks file and the unison-tls key generated earlier.  Make sure to replace the password with what you used to protect the unisonKeystore.jks file.

```xml
<?xml version='1.0' encoding='utf-8'?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<!-- Note:  A "Server" is not itself a "Container", so you may not
     define subcomponents such as "Valves" at this level.
     Documentation at /docs/config/server.html
 -->
<Server port="8005" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <!-- Security listener. Documentation at /docs/config/listeners.html
  <Listener className="org.apache.catalina.security.SecurityListener" />
  -->
  <!--APR library loader. Documentation at /docs/apr.html -->
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" />
  <!-- Prevent memory leaks due to use of particular java/javax APIs-->
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />

  <!-- Global JNDI resources
       Documentation at /docs/jndi-resources-howto.html
  -->
  <GlobalNamingResources>
    <!-- Editable user database that can also be used by
         UserDatabaseRealm to authenticate users
    -->
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              description="User database that can be updated and saved"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>

  <!-- A "Service" is a collection of one or more "Connectors" that share
       a single "Container" Note:  A "Service" is not itself a "Container",
       so you may not define subcomponents such as "Valves" at this level.
       Documentation at /docs/config/service.html
   -->
  <Service name="Catalina">

    <!--The connectors can use a shared executor, you can define one or more named thread pools-->
    <!--
    <Executor name="tomcatThreadPool" namePrefix="catalina-exec-"
        maxThreads="150" minSpareThreads="4"/>
    -->


    <!-- A "Connector" represents an endpoint by which requests are received
         and responses are returned. Documentation at :
         Java HTTP Connector: /docs/config/http.html (blocking & non-blocking)
         Java AJP  Connector: /docs/config/ajp.html
         APR (HTTP/AJP) Connector: /docs/apr.html
         Define a non-SSL/TLS HTTP/1.1 Connector on port 8080
    -->
    <Connector port="#[OPENUNISON_PT_PORT]" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />
    <!-- A "Connector" using the shared thread pool-->
    <!--
    <Connector executor="tomcatThreadPool"
               port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />
    -->
    <!-- Define a SSL/TLS HTTP/1.1 Connector on port 8443
         This connector uses the NIO implementation that requires the JSSE
         style configuration. When using the APR/native implementation, the
         OpenSSL style configuration is required as described in the APR/native
         documentation -->

    <Connector port="#[OPENUNISON_ENC_PORT]" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="want" sslProtocol="TLS" keystoreFile="/etc/openunison/unisonKeyStore.jks" keystoreType="JCEKS" keystorePass="start123" keyAlias="unison-tls"/>


    <!-- Define an AJP 1.3 Connector on port 8009 -->
    <!-- <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" /> -->


    <!-- An Engine represents the entry point (within Catalina) that processes
         every request.  The Engine implementation for Tomcat stand alone
         analyzes the HTTP headers included with the request, and passes them
         on to the appropriate Host (virtual host).
         Documentation at /docs/config/engine.html -->

    <!-- You should set jvmRoute to support load-balancing via AJP ie :
    <Engine name="Catalina" defaultHost="localhost" jvmRoute="jvm1">
    -->
    <Engine name="Catalina" defaultHost="localhost">

      <!--For clustering, please take a look at documentation at:
          /docs/cluster-howto.html  (simple how to)
          /docs/config/cluster.html (reference documentation) -->
      <!--
      <Cluster className="org.apache.catalina.ha.tcp.SimpleTcpCluster"/>
      -->

      <!-- Use the LockOutRealm to prevent attempts to guess user passwords
           via a brute-force attack -->
      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <!-- This Realm uses the UserDatabase configured in the global JNDI
             resources under the key "UserDatabase".  Any edits
             that are performed against this UserDatabase are immediately
             available for use by the Realm.  -->
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>

      <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">

        <!-- SingleSignOn valve, share authentication between web applications
             Documentation at: /docs/config/valve.html -->
        <!--
        <Valve className="org.apache.catalina.authenticator.SingleSignOn" />
        -->

        <!-- Access log processes all example.
             Documentation at: /docs/config/valve.html
             Note: The pattern used is equivalent to using pattern="common" -->
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />

      </Host>
    </Engine>
  </Service>
</Server>
```
