# OpenUnisonDocker

This file builds the base image for OpenUnison.  There are two options for deploying OpenUnison into your Docker server:

1. Deploy the OpenUnisonDockerDeploy deploy image
2. Use shared volumes to start OpenUnison using an underlying environment

The first choice is the easiest for getting up and running, but offers several challenges for deployments and security (how do you secure artifacts? how do you store passwords?).  The second option makes for a more manageable deployment, but requires more steps.  See the OpenUnisonDockerDeploy project for details on how to deploy OpenUnison using the deploy Dockerfile.

## Create Files on the Host System

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
