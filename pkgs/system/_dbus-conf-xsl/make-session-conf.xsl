<?xml version="1.0"?>
<!--
  AOS dbus-1 session.conf aggregator. Verbatim port of nixpkgs
  pkgs/by-name/ma/makeDBusConf/make-session-conf.xsl. AOS does not run
  a session bus today; emitted for symmetry only.
-->
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="str">

  <xsl:output method="xml" encoding="UTF-8" doctype-system="busconfig.dtd" />

  <xsl:param name="serviceDirectories" />
  <xsl:param name="apparmor" />

  <xsl:template match="/busconfig">
    <busconfig>
      <!-- Leave <standard_session_servicedirs/> in place: it includes XDG
           dirs which is what session-bus consumers expect. -->
      <xsl:copy-of select="child::node()[name() != 'include' and name() != 'servicedir' and name() != 'includedir']" />

      <apparmor mode="{$apparmor}"/>

      <xsl:for-each select="str:tokenize($serviceDirectories)">
        <servicedir><xsl:value-of select="." />/share/dbus-1/services</servicedir>
        <includedir><xsl:value-of select="." />/etc/dbus-1/session.d</includedir>
        <includedir><xsl:value-of select="." />/share/dbus-1/session.d</includedir>
      </xsl:for-each>
    </busconfig>
  </xsl:template>

</xsl:stylesheet>
