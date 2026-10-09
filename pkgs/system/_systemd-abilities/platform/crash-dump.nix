##! Projects native crash-dump files into the image bootstrap filesystem.
{config, ...}: {environment.etc = config.aos.security.hardening.crashFiles;}
