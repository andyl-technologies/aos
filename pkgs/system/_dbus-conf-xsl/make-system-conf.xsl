<?xml version="1.0"?>
<!--
  AOS dbus-1 system.conf aggregator. Ported from nixpkgs
  pkgs/by-name/ma/makeDBusConf/make-system-conf.xsl with two deviations:
    1. SELinux-conditional <include> survives (predicate below).
    2. Operator override hooks (system.d/, system-local.conf) emitted
       at end. NixOS does not emit these.
-->
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="str">

  <xsl:output method="xml" encoding="UTF-8" doctype-system="busconfig.dtd" />

  <xsl:param name="serviceDirectories" />
  <xsl:param name="suidHelper" />
  <xsl:param name="apparmor" />

  <xsl:template match="/busconfig">
    <busconfig>
      <!--
        Pass everything through except elements we re-emit. The 'include'
        predicate keeps <include if_selinux_enabled="yes">...</include>
        while dropping the upstream sysconfdir re-include and
        system-local.conf include (both replaced below with the correct
        AOS paths).
      -->
      <xsl:copy-of select="child::node()[
        not(
          (name() = 'include' and not(@if_selinux_enabled))
          or name() = 'standard_system_servicedirs'
          or name() = 'servicehelper'
          or name() = 'servicedir'
          or name() = 'includedir'
        )
      ]" />

      <apparmor mode="{$apparmor}"/>

      <servicehelper><xsl:value-of select="$suidHelper" /></servicehelper>

      <xsl:for-each select="str:tokenize($serviceDirectories)">
        <servicedir><xsl:value-of select="." />/share/dbus-1/system-services</servicedir>
        <includedir><xsl:value-of select="." />/etc/dbus-1/system.d</includedir>
        <includedir><xsl:value-of select="." />/share/dbus-1/system.d</includedir>
      </xsl:for-each>

      <!-- AOS operator override hooks (deviation from nixpkgs).
           Placed last so per-contributor entries take precedence. -->
      <includedir>/etc/dbus-1/system.d</includedir>
      <include ignore_missing="yes">/etc/dbus-1/system-local.conf</include>
    </busconfig>
  </xsl:template>

</xsl:stylesheet>
